// Test driver for the JIT. stdin:
//   N, then N lines "addr word" (hex), then the entry address, then M and M extra function
//   entries, then 32 hex register values (x0..x30, SP).
// Maps the same 128 KiB memory window as the AOT test harness at 0x40000000, JIT-compiles the
// code, runs it, and prints the 32 registers and a CRC32 of the window (or COMPILE_ERROR).
#include <champollion/x64_backend.h>
#include <sys/mman.h>
#include <cstdio>
#include <map>
#include <vector>
using namespace champollion;

static uint32_t crc32_of(const uint8_t* p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (-(int32_t)(c & 1)));
    }
    return ~c;
}

int main() {
    unsigned n;
    if (std::scanf("%u", &n) != 1) return 2;
    std::map<uint64_t, uint32_t> words;
    for (unsigned k = 0; k < n; ++k) {
        unsigned long long a; unsigned w;
        if (std::scanf("%llx %x", &a, &w) != 2) return 2;
        words[a] = w;
    }
    unsigned long long entry; unsigned m;
    if (std::scanf("%llx %u", &entry, &m) != 2) return 2;
    std::vector<uint64_t> extras;
    for (unsigned k = 0; k < m; ++k) {
        unsigned long long e;
        if (std::scanf("%llx", &e) != 1) return 2;
        extras.push_back(e);
    }
    uint64_t ctx[32];
    for (int k = 0; k < 32; ++k) {
        unsigned long long v;
        if (std::scanf("%llx", &v) != 1) return 2;
        ctx[k] = v;
    }

    const uint64_t lo = words.begin()->first, hi = words.rbegin()->first + 4;
    std::vector<uint8_t> bytes(hi - lo, 0);
    for (auto& kv : words)
        for (int j = 0; j < 4; ++j) bytes[kv.first - lo + j] = uint8_t(kv.second >> (8 * j));

    const uint64_t base = 0x40000000ull, size = 0x20000ull;
    uint8_t* mem = static_cast<uint8_t*>(mmap(reinterpret_cast<void*>(base), size, PROT_READ | PROT_WRITE,
                                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0));
    if (mem != reinterpret_cast<uint8_t*>(base)) { std::fprintf(stderr, "mmap failed\n"); return 3; }
    for (size_t i = 0; i < size; i++) mem[i] = uint8_t(i * 37 + 11);

    X64Backend be;
    X64CodeBlock blk;
    std::error_code ec = be.compile_guest(bytes.data(), lo, bytes.size(), entry, blk, extras);
    if (ec) { std::printf("COMPILE_ERROR %s\n", ec.message().c_str()); return 0; }
    be.entry_point(blk)(ctx);
    for (int k = 0; k < 32; ++k) std::printf("%llx ", (unsigned long long)ctx[k]);
    std::printf("%x\n", crc32_of(mem, size));
    return 0;
}
