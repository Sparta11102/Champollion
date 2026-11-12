#include <champollion/macho_loader.h>

#include <cstring>
#include <fstream>
#include <limits>
#include <system_error>

namespace champollion {

namespace {

constexpr uint32_t kFatMagic64 = 0xCAFEBABF;
constexpr uint32_t kFatCigam64 = 0xBFBAFECA;
constexpr uint32_t kLcMain = 0x80000028;

uint16_t read_u16(const uint8_t* bytes, bool little_endian) {
    uint16_t value;
    std::memcpy(&value, bytes, sizeof(value));
    return little_endian ? value : __builtin_bswap16(value);
}

uint32_t read_u32(const uint8_t* bytes, bool little_endian) {
    uint32_t value;
    std::memcpy(&value, bytes, sizeof(value));
    return little_endian ? value : __builtin_bswap32(value);
}

uint64_t read_u64(const uint8_t* bytes, bool little_endian) {
    uint64_t value;
    std::memcpy(&value, bytes, sizeof(value));
    return little_endian ? value : __builtin_bswap64(value);
}

std::error_code invalid_macho() {
    return std::make_error_code(std::errc::invalid_argument);
}

} // namespace

std::error_code load_macho(const std::string& path, std::unique_ptr<MachoImage>& out) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return std::make_error_code(std::errc::no_such_file_or_directory);

    const std::streamoff end = file.tellg();
    if (end < 4 || static_cast<uint64_t>(end) > std::numeric_limits<size_t>::max()) {
        return invalid_macho();
    }
    const size_t file_size = static_cast<size_t>(end);
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(file_size);
    if (!file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(file_size))) {
        return std::make_error_code(std::errc::io_error);
    }

    auto image = std::make_unique<MachoImage>();
    const uint32_t outer_magic = read_u32(data.data(), true);
    const bool is_fat_64 = outer_magic == kFatMagic64 || outer_magic == kFatCigam64;
    const bool is_fat = is_fat_64 || outer_magic == FAT_MAGIC || outer_magic == FAT_CIGAM;
    std::vector<uint8_t> slice;

    if (is_fat) {
        if (file_size < 8) return invalid_macho();
        const bool fat_little_endian = outer_magic == FAT_MAGIC || outer_magic == kFatMagic64;
        const uint32_t architecture_count = read_u32(data.data() + 4, fat_little_endian);
        const size_t record_size = is_fat_64 ? 32 : 20;
        if (architecture_count > 4096 || architecture_count > (file_size - 8) / record_size) {
            return invalid_macho();
        }

        bool found_arm64 = false;
        for (uint32_t index = 0; index < architecture_count; ++index) {
            const size_t record = 8 + static_cast<size_t>(index) * record_size;
            const int32_t cputype = static_cast<int32_t>(read_u32(data.data() + record, fat_little_endian));
            if (cputype != static_cast<int32_t>(CPU_TYPE_ARM64)) continue;

            const uint64_t offset = is_fat_64
                ? read_u64(data.data() + record + 8, fat_little_endian)
                : read_u32(data.data() + record + 8, fat_little_endian);
            const uint64_t size = is_fat_64
                ? read_u64(data.data() + record + 16, fat_little_endian)
                : read_u32(data.data() + record + 12, fat_little_endian);
            if (offset > file_size || size > file_size - offset || size < 4) return invalid_macho();
            slice.assign(data.begin() + static_cast<size_t>(offset),
                         data.begin() + static_cast<size_t>(offset + size));
            found_arm64 = true;
            break;
        }
        if (!found_arm64) return invalid_macho();
    } else {
        slice = std::move(data);
    }

    const uint32_t slice_magic = read_u32(slice.data(), true);
    if (slice_magic == MH_MAGIC_64) {
        image->is_64bit = true;
        image->is_little_endian = true;
    } else if (slice_magic == MH_CIGAM_64) {
        image->is_64bit = true;
        image->is_little_endian = false;
    } else {
        return invalid_macho();
    }
    if (slice.size() < 32) return invalid_macho();

    image->file_data = std::move(slice);
    const uint8_t* base = image->file_data.data();
    const size_t slice_size = image->file_data.size();
    image->cputype = static_cast<int32_t>(read_u32(base + 4, image->is_little_endian));
    image->cpusubtype = static_cast<int32_t>(read_u32(base + 8, image->is_little_endian));
    image->filetype = read_u32(base + 12, image->is_little_endian);
    image->ncmds = read_u32(base + 16, image->is_little_endian);
    image->sizeofcmds = read_u32(base + 20, image->is_little_endian);
    image->flags = read_u32(base + 24, image->is_little_endian);
    if (image->cputype != static_cast<int32_t>(CPU_TYPE_ARM64) || image->sizeofcmds > slice_size - 32) {
        return invalid_macho();
    }

    const size_t commands_end = 32 + image->sizeofcmds;
    size_t cursor = 32;
    bool has_main = false;
    uint64_t main_file_offset = 0;
    for (uint32_t index = 0; index < image->ncmds; ++index) {
        if (cursor > commands_end || commands_end - cursor < 8) return invalid_macho();
        const uint32_t command = read_u32(base + cursor, image->is_little_endian);
        const uint32_t command_size = read_u32(base + cursor + 4, image->is_little_endian);
        if (command_size < 8 || command_size > commands_end - cursor) return invalid_macho();

        if (command == LC_SEGMENT_64) {
            if (command_size < 72) return invalid_macho();
            MachoSegment segment;
            char segment_name[17] = {};
            std::memcpy(segment_name, base + cursor + 8, 16);
            segment.segname = segment_name;
            segment.vmaddr = read_u64(base + cursor + 24, image->is_little_endian);
            segment.vmsize = read_u64(base + cursor + 32, image->is_little_endian);
            segment.fileoff = read_u64(base + cursor + 40, image->is_little_endian);
            segment.filesize = read_u64(base + cursor + 48, image->is_little_endian);
            segment.maxprot = read_u32(base + cursor + 56, image->is_little_endian);
            segment.initprot = read_u32(base + cursor + 60, image->is_little_endian);
            segment.nsects = read_u32(base + cursor + 64, image->is_little_endian);
            segment.flag = read_u32(base + cursor + 68, image->is_little_endian);
            const uint64_t required_size = 72ULL + static_cast<uint64_t>(segment.nsects) * 80ULL;
            if (required_size > command_size || segment.fileoff > slice_size ||
                segment.filesize > slice_size - segment.fileoff) {
                return invalid_macho();
            }

            for (uint32_t section_index = 0; section_index < segment.nsects; ++section_index) {
                const size_t section_offset = cursor + 72 + static_cast<size_t>(section_index) * 80;
                MachoSection section;
                char section_name[17] = {};
                char section_segment_name[17] = {};
                std::memcpy(section_name, base + section_offset, 16);
                std::memcpy(section_segment_name, base + section_offset + 16, 16);
                section.sectname = section_name;
                section.segname = section_segment_name;
                section.addr = read_u64(base + section_offset + 32, image->is_little_endian);
                section.size = read_u64(base + section_offset + 40, image->is_little_endian);
                section.offset = read_u32(base + section_offset + 48, image->is_little_endian);
                section.align = read_u32(base + section_offset + 52, image->is_little_endian);
                section.attributes = read_u32(base + section_offset + 64, image->is_little_endian);
                section.type = section.attributes & 0xFF;
                image->sections.push_back(std::move(section));
            }
            image->segments.push_back(std::move(segment));
        } else if (command == LC_SYMTAB) {
            if (command_size < 24) return invalid_macho();
            const uint32_t symbol_offset = read_u32(base + cursor + 8, image->is_little_endian);
            const uint32_t symbol_count = read_u32(base + cursor + 12, image->is_little_endian);
            const uint32_t string_offset = read_u32(base + cursor + 16, image->is_little_endian);
            const uint32_t string_size = read_u32(base + cursor + 20, image->is_little_endian);
            if (symbol_offset > slice_size || symbol_count > (slice_size - symbol_offset) / 16 ||
                string_offset > slice_size || string_size > slice_size - string_offset) {
                return invalid_macho();
            }
            for (uint32_t symbol_index = 0; symbol_index < symbol_count; ++symbol_index) {
                const size_t record = symbol_offset + static_cast<size_t>(symbol_index) * 16;
                const uint32_t string_index = read_u32(base + record, image->is_little_endian);
                const uint8_t type = base[record + 4];
                MachoSymbol symbol;
                symbol.sect = base[record + 5];
                symbol.desc = read_u16(base + record + 6, image->is_little_endian);
                symbol.value = read_u64(base + record + 8, image->is_little_endian);
                symbol.type = type;
                symbol.is_undefined = symbol.sect == 0;
                symbol.is_external = (type & 0x1) != 0;
                if (string_index < string_size) {
                    const char* name = reinterpret_cast<const char*>(base + string_offset + string_index);
                    const size_t available = string_size - string_index;
                    const void* terminator = std::memchr(name, '\0', available);
                    if (terminator) symbol.name.assign(name, static_cast<const char*>(terminator) - name);
                }
                image->symbols.push_back(std::move(symbol));
            }
        } else if (command == LC_LOAD_DYLIB || command == LC_ID_DYLIB) {
            if (command_size < 24) return invalid_macho();
            const uint32_t name_offset = read_u32(base + cursor + 8, image->is_little_endian);
            if (name_offset >= command_size) return invalid_macho();
            MachoDylib dylib;
            const char* name = reinterpret_cast<const char*>(base + cursor + name_offset);
            const size_t available = command_size - name_offset;
            const void* terminator = std::memchr(name, '\0', available);
            if (terminator) dylib.name.assign(name, static_cast<const char*>(terminator) - name);
            dylib.timestamp = read_u32(base + cursor + 12, image->is_little_endian);
            dylib.current_version = read_u32(base + cursor + 16, image->is_little_endian);
            dylib.compatibility_version = read_u32(base + cursor + 20, image->is_little_endian);
            image->dylibs.push_back(std::move(dylib));
        } else if (command == LC_DYLD_CHAINED_FIXUPS) {
            if (command_size < 16) return invalid_macho();
            image->has_chained_fixups = true;
            image->chained_fixups_offset = read_u32(base + cursor + 8, image->is_little_endian);
            image->chained_fixups_size = read_u32(base + cursor + 12, image->is_little_endian);
        } else if (command == kLcMain) {
            if (command_size < 24) return invalid_macho();
            main_file_offset = read_u64(base + cursor + 8, image->is_little_endian);
            has_main = true;
        }
        cursor += command_size;
    }

    if (has_main) {
        image->entry_offset = main_file_offset;
        for (const auto& segment : image->segments) {
            if (main_file_offset >= segment.fileoff && main_file_offset - segment.fileoff < segment.filesize) {
                image->entry_vaddr = segment.vmaddr + (main_file_offset - segment.fileoff);
                break;
            }
        }
    }
    if (image->entry_vaddr == 0) {
        for (const auto& segment : image->segments) {
            if (segment.initprot & VM_PROT_EXEC) {
                image->entry_offset = segment.fileoff;
                image->entry_vaddr = segment.vmaddr;
                break;
            }
        }
    }
    out = std::move(image);
    return {};
}

uint64_t macho_symbol_address(const MachoImage& image, const std::string& name) {
    for (const auto& symbol : image.symbols) {
        if (symbol.name == name) return symbol.value;
    }
    return 0;
}

bool macho_offset_in_segment(const MachoImage& image, uint64_t file_offset, uint64_t size) {
    for (const auto& segment : image.segments) {
        if (file_offset < segment.fileoff) continue;
        const uint64_t relative_offset = file_offset - segment.fileoff;
        if (relative_offset <= segment.filesize && size <= segment.filesize - relative_offset) return true;
    }
    return false;
}

std::vector<uint8_t> macho_read_bytes(const MachoImage& image, uint64_t file_offset, uint64_t size) {
    if (file_offset >= image.file_data.size() || size == 0) return {};
    for (const auto& segment : image.segments) {
        if (file_offset < segment.fileoff) continue;
        const uint64_t relative_offset = file_offset - segment.fileoff;
        if (relative_offset >= segment.filesize) continue;
        const uint64_t segment_available = segment.filesize - relative_offset;
        const uint64_t file_available = image.file_data.size() - file_offset;
        const uint64_t byte_count = std::min(size, std::min(segment_available, file_available));
        const auto begin = image.file_data.begin() + static_cast<size_t>(file_offset);
        return std::vector<uint8_t>(begin, begin + static_cast<size_t>(byte_count));
    }
    return {};
}

uint64_t macho_file_offset_to_vaddr(const MachoImage& image, uint64_t file_offset) {
    for (const auto& segment : image.segments) {
        if (file_offset >= segment.fileoff && file_offset - segment.fileoff < segment.filesize) {
            return segment.vmaddr + (file_offset - segment.fileoff);
        }
    }
    return 0;
}

uint64_t macho_vaddr_to_file_offset(const MachoImage& image, uint64_t vaddr) {
    for (const auto& segment : image.segments) {
        if (vaddr >= segment.vmaddr && vaddr - segment.vmaddr < segment.filesize) {
            return segment.fileoff + (vaddr - segment.vmaddr);
        }
    }
    return 0;
}

} // namespace champollion