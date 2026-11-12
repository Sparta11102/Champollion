#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <system_error>

namespace champollion {

// ============================================================================
// Mach-O loader (ToDo.txt Phase 1: Mach-O loader and mini-dyld)
// Parses fat/thin Mach-O binaries for arm64 guest applications.
// ============================================================================
using cpu_type_t = int32_t;
using cpu_subtype_t = int32_t;

// Mach-O magic numbers
constexpr uint32_t MH_MAGIC     = 0xFEEDFACE;   // 32-bit little-endian
constexpr uint32_t MH_CIGAM     = 0xCEFAEDFE;   // 32-bit big-endian
constexpr uint32_t MH_MAGIC_64  = 0xFEEDFACF;   // 64-bit little-endian
constexpr uint32_t MH_CIGAM_64  = 0xCFFAEDFE;   // 64-bit big-endian
constexpr uint32_t FAT_MAGIC    = 0xCAFEBABE;   // fat binary big-endian
constexpr uint32_t FAT_CIGAM    = 0xBEBAFECA;   // fat binary little-endian
constexpr uint32_t FAT_MAGIC_64 = 0xCAFEBABF;
constexpr uint32_t FAT_CIGAM_64 = 0xBFBAFECA;

// CPU types
constexpr cpu_type_t CPU_TYPE_ARM64  = 0x0100000C;  // ARM64 (with CPU_SUBTYPE_ARM64_ALL)
constexpr cpu_type_t CPU_TYPE_X86_64 = 0x01000007;

// Load command types
constexpr uint32_t LC_SEGMENT          = 0x1;
constexpr uint32_t LC_SEGMENT_64       = 0x19;
constexpr uint32_t LC_SYMTAB           = 0x2;
constexpr uint32_t LC_DYSYMTAB         = 0xB;
constexpr uint32_t LC_LOAD_DYLIB       = 0xC;
constexpr uint32_t LC_ID_DYLIB         = 0xD;
constexpr uint32_t LC_LOAD_DYLINKER    = 0xE;
constexpr uint32_t LC_UUID             = 0x1B;
constexpr uint32_t LC_SOURCE_VERSION   = 0x2A;
constexpr uint32_t LC_BUILD_VERSION    = 0x32;
constexpr uint32_t LC_DYLD_CHAINED_FIXUPS = 0x30;  // chained fixups
constexpr uint32_t LC_MAIN = 0x80000028;

// Segment protection
constexpr uint32_t VM_PROT_READ  = 0x1;
constexpr uint32_t VM_PROT_WRITE = 0x2;
constexpr uint32_t VM_PROT_EXEC  = 0x4;

// Symbol types (partial)
constexpr uint8_t N_SECT = 0xE;

// Forward declarations
struct MachoImage;
struct MachoSection;
struct MachoSegment;
struct MachoSymbol;
struct MachoDylib;

// A loaded Mach-O image (thin or one architecture from a fat binary)
struct MachoImage {
    bool is_64bit = false;
    bool is_little_endian = true;
    cpu_type_t cputype = 0;
    cpu_subtype_t cpusubtype = 0;
    uint32_t filetype = 0;
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;
    uint32_t flags = 0;

    // Raw file backing (memory-mapped or heap copy)
    std::vector<uint8_t> file_data;

    // Parsed structures
    std::vector<MachoSegment> segments;
    std::vector<MachoSection> sections;
    std::vector<MachoSymbol> symbols;
    std::vector<MachoDylib> dylibs;

    // Entry point (main) for executables
    uint64_t entry_offset = 0;   // file offset
    uint64_t entry_vaddr = 0;    // virtual address

    // Chained fixups (dyld v3)
    bool has_chained_fixups = false;
    uint64_t chained_fixups_offset = 0;
    uint64_t chained_fixups_size = 0;
};

// A section within a segment
struct MachoSection {
    std::string sectname;
    std::string segname;
    uint64_t addr = 0;
    uint64_t size = 0;
    uint64_t offset = 0;      // file offset
    uint32_t align = 0;
    uint32_t type = 0;
    uint32_t attributes = 0;
};

// A segment (loadable region)
struct MachoSegment {
    std::string segname;
    uint64_t vmaddr = 0;
    uint64_t vmsize = 0;
    uint64_t fileoff = 0;
    uint64_t filesize = 0;
    uint32_t maxprot = 0;
    uint32_t initprot = 0;
    uint32_t nsects = 0;
    uint32_t flag = 0;
};

// A symbol table entry
struct MachoSymbol {
    std::string name;
    uint64_t value = 0;
    uint32_t sect = 0;       // section index (N_SECT = absolute)
    uint32_t type = 0;
    uint16_t desc = 0;
    bool is_undefined = false;
    bool is_external = false;
};

// A dylib dependency
struct MachoDylib {
    std::string name;
    uint32_t timestamp = 0;
    uint32_t current_version = 0;
    uint32_t compatibility_version = 0;
};

// Load a Mach-O image from a file path.
// Returns std::error_code on failure.
std::error_code load_macho(const std::string& path, std::unique_ptr<MachoImage>& out);

// Resolve the virtual address of a symbol by name.
uint64_t macho_symbol_address(const MachoImage& image, const std::string& name);

// Check whether a file offset lies within a readable segment.
bool macho_offset_in_segment(const MachoImage& image, uint64_t file_offset, uint64_t size);

// Read bytes from the image at a file offset.
std::vector<uint8_t> macho_read_bytes(const MachoImage& image, uint64_t file_offset, uint64_t size);

// Translate a file offset to a virtual address (and vice versa) using segment mappings.
uint64_t macho_file_offset_to_vaddr(const MachoImage& image, uint64_t file_offset);
uint64_t macho_vaddr_to_file_offset(const MachoImage& image, uint64_t vaddr);

} // namespace champollion
