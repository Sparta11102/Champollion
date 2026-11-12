#include <champollion/macho_loader.h>
#include <champollion/arm64_decoder.h>
#include <champollion/ir.h>
#include <champollion/x64_backend.h>

#include <cstring>
#include <iostream>
#include <string>

using namespace champollion;

int main(int argc, char** argv) {
    bool run = false;
    std::string path;
    for (int k = 1; k < argc; ++k) {
        if (std::strcmp(argv[k], "--run") == 0) run = true;
        else if (path.empty()) path = argv[k];
    }
    if (path.empty()) {
        std::cerr << "Usage: champollion-jit [--run] <path-to-arm64-macho>\n"
                     "  Loads the image, decodes the entry point and tries to JIT-compile the\n"
                     "  entry function. --run executes it with zeroed registers (x86-64 hosts only).\n"
                     "  Supported: integer code, general-register loads/stores, branches and\n"
                     "  calls within the image. SIMD/FP, atomics and external calls are refused,\n"
                     "  not approximated. Guest memory is accessed at guest addresses, so --run\n"
                     "  is only meaningful once the image is mapped at its own addresses.\n";
        return 1;
    }

    std::cout << "champollion-jit v0.2.0 (arm64 -> x64)\n";
    std::cout << "Loading guest image: " << path << "\n";

    std::unique_ptr<MachoImage> image;
    if (std::error_code ec = load_macho(path, image)) {
        std::cerr << "Failed to load Mach-O: " << ec.message() << "\n";
        return 1;
    }
    std::cout << "  cputype=0x" << std::hex << image->cputype << " cpusubtype=0x" << image->cpusubtype
              << " filetype=" << std::dec << image->filetype << "\n"
              << "  segments=" << image->segments.size() << " sections=" << image->sections.size()
              << " symbols=" << image->symbols.size() << " dylibs=" << image->dylibs.size() << "\n";

    if (image->entry_vaddr == 0) {
        std::cout << "No entry point (LC_MAIN) found.\n";
        return 0;
    }

    const MachoSegment* code_seg = nullptr;
    for (const auto& s : image->segments) {
        if ((s.initprot & 4u) && s.vmaddr <= image->entry_vaddr &&
            image->entry_vaddr < s.vmaddr + s.filesize) {
            code_seg = &s;
            break;
        }
    }
    if (!code_seg) {
        std::cerr << "Entry point is not inside a file-backed executable segment.\n";
        return 1;
    }

    Arm64Decoder decoder;
    const uint8_t* seg_bytes = image->file_data.data() + code_seg->fileoff;
    std::cout << "\nDecoding from entry point 0x" << std::hex << image->entry_vaddr << ":\n";
    uint64_t cur = image->entry_vaddr;
    for (int n = 0; n < 16 && cur + 4 <= code_seg->vmaddr + code_seg->filesize; ++n, cur += 4) {
        DecodeResult r = decoder.decode(cur, seg_bytes + (cur - code_seg->vmaddr));
        std::cout << "  0x" << cur << ": " << std::hex << r.inst.opcode << "  "
                  << (r.inst.alias.empty() ? r.inst.mnemonic : r.inst.mnemonic + " (" + r.inst.alias + ")")
                  << (r.inst.supported ? "" : "  [not decoded]") << "\n";
        if (r.error || r.inst.is_branch) break;
    }
    std::cout << std::dec;

    X64Backend& backend = global_backend();
    X64CodeBlock block;
    std::error_code ec = backend.compile_guest(seg_bytes, code_seg->vmaddr, code_seg->filesize,
                                               image->entry_vaddr, block);
    if (ec) {
        std::cout << "\nJIT: entry function not compiled (" << ec.message()
                  << "). It uses instructions or control flow outside the supported subset.\n";
        return 0;
    }
    std::cout << "\nJIT: compiled entry function to " << block.code.size() << " bytes of x86-64.\n";
    if (run) {
        std::cout << "Warning: --run does not map the image; code that touches memory will crash.\n";
        uint64_t ctx[32] = {};
        backend.entry_point(block)(ctx);
        std::cout << "Executed. x0 = 0x" << std::hex << ctx[0] << std::dec << "\n";
    }
    return 0;
}
