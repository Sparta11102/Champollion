"""End-to-end test: build a synthetic arm64 Mach-O, load it, decode entry point."""
import os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from macho import (
    MachoImage, MachoSegment, MachoSection,
    MH_MAGIC_64, CPU_TYPE_ARM64, LC_SEGMENT_64,
    VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXEC,
    load_macho, vaddr_to_file_offset, read_bytes
)
from arm64_decode import Arm64Decoder

MH_MAGIC_64_val = MH_MAGIC_64

# Code: ret x30; br x0; b +8; bl +12; cbz x0, +4 (padded to 64 bytes)
code = (
    bytes([0xC0, 0x03, 0x5F, 0xD6]) +  # ret x30 (0x1000)
    bytes([0x00, 0x00, 0x3F, 0xD6]) +  # br x0 (0x1004)
    bytes([0x05, 0x00, 0x00, 0x14]) +  # b +8  (0x1008)
    bytes([0x06, 0x00, 0x00, 0x94]) +  # bl +12 (0x100C)
    bytes([0x00, 0x00, 0x00, 0xB4])    # cbz x0, +4 (0x1010)
).ljust(64, b"\x00")

# File layout: header(32) + segment command and section + LC_MAIN + code
code_offset = 32 + 152 + 24

# mach_header_64 (32 bytes)
header = struct.pack("<IIIIIIII",
    MH_MAGIC_64_val,      # magic
    CPU_TYPE_ARM64,       # cputype
    0,                    # cpusubtype
    2,                    # filetype (MH_OBJECT)
    2,                    # ncmds
    176,                  # sizeofcmds (segment+section 152, LC_MAIN 24)
    0,                    # flags
    0                     # reserved
)

# Segment command (LC_SEGMENT_64 = 72 bytes) for __TEXT
seg_cmd = struct.pack("<II16sqqqqIIII",
    LC_SEGMENT_64,        # cmd
    152,                  # cmdsize (segment + one section)
    b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00",  # segname (16 bytes)
    0x1000,               # vmaddr
    0x1000,               # vmsize
    code_offset,          # fileoff
    len(code),            # filesize
    VM_PROT_READ | VM_PROT_EXEC,  # maxprot
    VM_PROT_READ | VM_PROT_EXEC,  # initprot
    1,                    # nsects
    0                     # flag
)

# Section (80 bytes)
section = struct.pack("<16s16sqqIIIIIIII",
    b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # sectname
    b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00",        # segname
    0x1000,                      # addr
    64,                          # size
    code_offset,                 # offset
    2,                           # align (4 bytes)
    0x80000000,                  # type (S_REGULAR)
    0x0,                         # attributes
    0, 0, 0, 0                   # reserved1-4
)

# LC_MAIN (24 bytes): entry offset is relative to the Mach-O slice.
main_cmd = struct.pack("<IIQQ", 0x80000028, 24, code_offset, 0)

data = header + seg_cmd + section + main_cmd + code

# Write to temp file
test_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_macho.bin")
with open(test_path, "wb") as f:
    f.write(data)

print(f"Wrote synthetic Mach-O ({len(data)} bytes) to {test_path}")

# Load and decode
image = load_macho(test_path)
print(f"  cputype=0x{image.cputype:08X} filetype={image.filetype}")
print(f"  segments={len(image.segments)} sections={len(image.sections)} symbols={len(image.symbols)}")
print(f"  entry_vaddr=0x{image.entry_vaddr:X}")

# Decode at entry point
dec = Arm64Decoder()
foff = vaddr_to_file_offset(image, image.entry_vaddr)
if foff:
    code_bytes = read_bytes(image, foff, 64)
    print(f"\nDisassembly at entry point (0x{image.entry_vaddr:X}):")
    cur = image.entry_vaddr
    off = 0
    while off + 4 <= len(code_bytes):
        res = dec.decode(cur, code_bytes[off:off + 4])
        if res.error:
            print(f"  0x{cur:X}: decode error: {res.error}")
            break
        print(f"  0x{cur:X}: {res.inst.mnemonic:10s} {res.inst.operands}")
        cur += res.size
        off += res.size
        if res.inst.is_return:
            break

os.remove(test_path)
print("\nE2E test complete")
