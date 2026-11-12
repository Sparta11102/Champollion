"""
Mach-O loader prototype (ToDo.txt Phase 1: Mach-O loader and mini-dyld).

Pure-stdlib Python port of champollion::macho_loader. Parses fat/thin Mach-O
binaries and extracts the arm64 slice, segments, sections, symbols and dylib
dependencies. Mirrors the C++ structs for a 1:1 port later.
"""

from dataclasses import dataclass, field
from typing import List
import struct

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_DYLINKER = 0xE
LC_UUID = 0x1B
LC_DYLD_CHAINED_FIXUPS = 0x30
LC_MAIN = 0x80000028

VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXEC = 0x4


@dataclass
class MachoSection:
    sectname: str = ""
    segname: str = ""
    addr: int = 0
    size: int = 0
    offset: int = 0
    align: int = 0
    type: int = 0
    attributes: int = 0


@dataclass
class MachoSegment:
    segname: str = ""
    vmaddr: int = 0
    vmsize: int = 0
    fileoff: int = 0
    filesize: int = 0
    maxprot: int = 0
    initprot: int = 0
    nsects: int = 0
    flag: int = 0
    sections: List[MachoSection] = field(default_factory=list)


@dataclass
class MachoSymbol:
    name: str = ""
    value: int = 0
    sect: int = 0
    type: int = 0
    desc: int = 0
    is_undefined: bool = False
    is_external: bool = False


@dataclass
class MachoDylib:
    name: str = ""
    timestamp: int = 0
    current_version: int = 0
    compatibility_version: int = 0


@dataclass
class MachoImage:
    is_64bit: bool = False
    is_little_endian: bool = True
    cputype: int = 0
    cpusubtype: int = 0
    filetype: int = 0
    ncmds: int = 0
    sizeofcmds: int = 0
    flags: int = 0
    file_data: bytes = b""
    segments: List[MachoSegment] = field(default_factory=list)
    sections: List[MachoSection] = field(default_factory=list)
    symbols: List[MachoSymbol] = field(default_factory=list)
    dylibs: List[MachoDylib] = field(default_factory=list)
    entry_offset: int = 0
    entry_vaddr: int = 0
    has_chained_fixups: bool = False
    chained_fixups_offset: int = 0
    chained_fixups_size: int = 0


def _read_u16(b: bytes, off: int, le: bool) -> int:
    fmt = "<H" if le else ">H"
    return struct.unpack_from(fmt, b, off)[0]


def _read_u32(b: bytes, off: int, le: bool) -> int:
    fmt = "<I" if le else ">I"
    return struct.unpack_from(fmt, b, off)[0]


def _read_u64(b: bytes, off: int, le: bool) -> int:
    fmt = "<Q" if le else ">Q"
    return struct.unpack_from(fmt, b, off)[0]


def _cstr(b: bytes, off: int) -> str:
    end = b.find(b"\x00", off)
    if end == -1:
        end = len(b)
    return b[off:end].decode("utf-8", errors="replace")
def load_macho(path: str) -> MachoImage:
    """Load and parse a Mach-O (fat or thin) file."""
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 4:
        raise ValueError("file too small to be a Mach-O")

    magic = _read_u32(data, 0, True)
    is_fat = magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64)

    image = MachoImage()

    if is_fat:
        image.is_little_endian = (magic == FAT_MAGIC)
    elif magic in (MH_MAGIC_64, MH_CIGAM_64):
        image.is_64bit = True
        image.is_little_endian = (magic == MH_MAGIC_64)
    elif magic in (MH_MAGIC, MH_CIGAM):
        image.is_64bit = False
        image.is_little_endian = (magic == MH_MAGIC)
    else:
        raise ValueError(f"not a Mach-O file: magic=0x{magic:08X}")

    le = image.is_little_endian
    base = data
    slice_offset = 0

    if is_fat:
        if len(data) < 8:
            raise ValueError("fat binary truncated")
        nfat = _read_u32(base, 4, le)
        is_fat_64 = magic in (FAT_MAGIC_64, FAT_CIGAM_64)
        record_size = 32 if is_fat_64 else 20
        if nfat > 4096 or 8 + nfat * record_size > len(data):
            raise ValueError("fat architecture table is truncated or invalid")
        off = 8
        found = False
        for _ in range(nfat):
            ctype = _read_u32(base, off, le)
            if is_fat_64:
                offset = _read_u64(base, off + 8, le)
                slice_size = _read_u64(base, off + 16, le)
            else:
                offset = _read_u32(base, off + 8, le)
                slice_size = _read_u32(base, off + 12, le)
            if ctype == CPU_TYPE_ARM64:
                if offset > len(data) or slice_size > len(data) - offset:
                    raise ValueError("ARM64 slice extends beyond the fat binary")
                slice_offset = offset
                found = True
                break
            off += record_size
        if not found:
            raise ValueError("no arm64 slice in fat binary")

    base = data[slice_offset:slice_offset + slice_size] if is_fat else data
    magic = _read_u32(base, 0, True)

    if magic in (MH_MAGIC_64, MH_CIGAM_64):
        image.is_64bit = True
        image.is_little_endian = magic == MH_MAGIC_64
    elif magic in (MH_MAGIC, MH_CIGAM):
        image.is_64bit = False
        image.is_little_endian = magic == MH_MAGIC
    else:
        raise ValueError(f"invalid Mach-O slice magic: 0x{magic:08X}")
    le = image.is_little_endian

    if not image.is_64bit:
        raise ValueError("only 64-bit Mach-O is supported in this prototype")

    if len(base) < 32:
        raise ValueError("mach_header_64 truncated")
    image.cputype = _read_u32(base, 4, le)
    image.cpusubtype = _read_u32(base, 8, le)
    image.filetype = _read_u32(base, 12, le)
    image.ncmds = _read_u32(base, 16, le)
    image.sizeofcmds = _read_u32(base, 20, le)
    image.flags = _read_u32(base, 24, le)
    if 32 + image.sizeofcmds > len(base):
        raise ValueError("Mach-O load commands extend beyond the selected slice")
    load_commands_end = 32 + image.sizeofcmds

    cursor = slice_offset + 32
    entry_file_offset = None
    for _ in range(image.ncmds):
        rel = cursor - slice_offset
        if rel + 8 > load_commands_end:
            raise ValueError("load command header is truncated")
        cmd = _read_u32(base, rel, le)
        cmdsize = _read_u32(base, rel + 4, le)
        if cmdsize < 8 or rel + cmdsize > load_commands_end:
            raise ValueError("load command size is invalid")

        if cmd == LC_SEGMENT_64:
            if rel + 72 > len(base):
                raise ValueError("LC_SEGMENT_64 command is truncated")
            seg = MachoSegment()
            seg.segname = _cstr(base, rel + 8)[:16]
            seg.vmaddr = _read_u64(base, rel + 24, le)
            seg.vmsize = _read_u64(base, rel + 32, le)
            seg.fileoff = _read_u64(base, rel + 40, le)
            seg.filesize = _read_u64(base, rel + 48, le)
            seg.maxprot = _read_u32(base, rel + 56, le)
            seg.initprot = _read_u32(base, rel + 60, le)
            seg.nsects = _read_u32(base, rel + 64, le)
            seg.flag = _read_u32(base, rel + 68, le)

            sect_cursor = cursor + 72
            for _ in range(seg.nsects):
                srel = sect_cursor - slice_offset
                if srel + 80 > rel + cmdsize:
                    raise ValueError("Mach-O section table exceeds its segment command")
                sec = MachoSection()
                sec.sectname = _cstr(base, srel)[:16]
                sec.segname = _cstr(base, srel + 16)[:16]
                sec.addr = _read_u64(base, srel + 32, le)
                sec.size = _read_u64(base, srel + 40, le)
                sec.offset = _read_u32(base, srel + 48, le)
                sec.align = _read_u32(base, srel + 56, le)
                section_flags = _read_u32(base, srel + 64, le)
                sec.type = section_flags & 0xFF
                sec.attributes = section_flags
                seg.sections.append(sec)
                image.sections.append(sec)
                sect_cursor += 80
            image.segments.append(seg)

        elif cmd == LC_SYMTAB:
            if rel + 24 > len(base):
                raise ValueError("LC_SYMTAB command is truncated")
            rel = cursor - slice_offset
            symoff = _read_u32(base, rel + 8, le)
            nsyms = _read_u32(base, rel + 12, le)
            stroff = _read_u32(base, rel + 16, le)
            strtab = base[stroff:]
            for s in range(nsyms):
                n64 = symoff + s * 16
                if n64 + 16 > len(base):
                    break
                strx = _read_u32(base, n64, le)
                sym_type = base[n64 + 4]
                sect = base[n64 + 5]
                desc = _read_u16(base, n64 + 6, le)
                value = _read_u64(base, n64 + 8, le)
                sym = MachoSymbol()
                sym.value = value
                sym.sect = sect
                sym.type = sym_type
                sym.desc = desc
                sym.is_undefined = (sect == 0)
                sym.is_external = bool(sym_type & 0x1)
                if strx != 0 and stroff + strx < len(base):
                    sym.name = _cstr(base, stroff + strx)
                image.symbols.append(sym)

        elif cmd in (LC_LOAD_DYLIB, LC_ID_DYLIB):
            if rel + 24 > len(base):
                raise ValueError("dylib load command is truncated")
            rel = cursor - slice_offset
            nameoff = _read_u32(base, rel + 8, le)
            dylib = MachoDylib()
            name_offset = rel + nameoff
            if nameoff != 0 and name_offset < len(base):
                dylib.name = _cstr(base, name_offset)
            dylib.timestamp = _read_u32(base, rel + 12, le)
            dylib.current_version = _read_u32(base, rel + 16, le)
            dylib.compatibility_version = _read_u32(base, rel + 20, le)
            image.dylibs.append(dylib)

        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            image.has_chained_fixups = True
            rel = cursor - slice_offset
            image.chained_fixups_offset = _read_u32(base, rel + 8, le)
            image.chained_fixups_size = _read_u32(base, rel + 12, le)

        elif cmd == LC_MAIN:
            rel = cursor - slice_offset
            if cmdsize >= 24:
                entry_file_offset = _read_u64(base, rel + 8, le)

        cursor += cmdsize

    image.entry_vaddr = 0
    if entry_file_offset is not None:
        image.entry_offset = entry_file_offset
        for seg in image.segments:
            if seg.fileoff <= entry_file_offset < seg.fileoff + seg.filesize:
                image.entry_vaddr = seg.vmaddr + entry_file_offset - seg.fileoff
                break
    for seg in image.segments:
        if image.entry_vaddr == 0 and seg.initprot & VM_PROT_EXEC:
            image.entry_vaddr = seg.vmaddr
            image.entry_offset = seg.fileoff
            break

    image.file_data = base
    return image


def symbol_address(image: MachoImage, name: str) -> int:
    for sym in image.symbols:
        if sym.name == name:
            return sym.value
    return 0


def offset_in_segment(image: MachoImage, file_offset: int, size: int) -> bool:
    for seg in image.segments:
        if seg.fileoff <= file_offset < seg.fileoff + seg.filesize:
            if file_offset + size <= seg.fileoff + seg.filesize:
                return True
    return False


def read_bytes(image: MachoImage, file_offset: int, size: int) -> bytes:
    if not offset_in_segment(image, file_offset, size):
        return b""
    return image.file_data[file_offset:file_offset + size]


def file_offset_to_vaddr(image: MachoImage, file_offset: int) -> int:
    for seg in image.segments:
        if seg.fileoff <= file_offset < seg.fileoff + seg.filesize:
            return seg.vmaddr + (file_offset - seg.fileoff)
    return 0


def vaddr_to_file_offset(image: MachoImage, vaddr: int) -> int:
    for seg in image.segments:
        if seg.vmaddr <= vaddr < seg.vmaddr + seg.vmsize:
            return seg.fileoff + (vaddr - seg.vmaddr)
    return 0

