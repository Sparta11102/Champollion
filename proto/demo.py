"""
Demo: load an arm64 Mach-O and decode instructions at its entry point.

Usage:
    python demo.py <path-to-arm64-macho>
"""

import sys
from macho import load_macho, vaddr_to_file_offset, read_bytes
from arm64_decode import Arm64Decoder


def main(argv):
    if len(argv) < 2:
        print("Usage: python demo.py <path-to-arm64-macho>")
        return 1

    path = argv[1]
    image = load_macho(path)

    print("champollion-jit prototype (arm64 Mach-O loader + decoder)")
    print("  cputype=0x%08X cpusubtype=0x%08X filetype=%d" % (
        image.cputype, image.cpusubtype, image.filetype))
    print("  segments=%d sections=%d symbols=%d dylibs=%d" % (
        len(image.segments), len(image.sections),
        len(image.symbols), len(image.dylibs)))
    print("  entry_vaddr=0x%X has_chained_fixups=%s" % (
        image.entry_vaddr, image.has_chained_fixups))

    print("\nSegments:")
    for seg in image.segments:
        print("  %-16s vmaddr=0x%08X vmsize=0x%08X fileoff=0x%08X "
              "filesize=0x%08X initprot=0x%X nsects=%d" % (
                  seg.segname, seg.vmaddr, seg.vmsize, seg.fileoff,
                  seg.filesize, seg.initprot, seg.nsects))

    print("\nDylibs:")
    for d in image.dylibs:
        print("  %s (compat=%d current=%d)" % (
            d.name, d.compatibility_version, d.current_version))

    # Decode first instructions at entry point
    if image.entry_vaddr:
        foff = vaddr_to_file_offset(image, image.entry_vaddr)
        if foff:
            code = read_bytes(image, foff, 64)
            dec = Arm64Decoder()
            cur = image.entry_vaddr
            off = 0
            print("\nDisassembly at entry point (0x%X):" % image.entry_vaddr)
            while off + 4 <= len(code):
                res = dec.decode(cur, code[off:off + 4])
                if res.error:
                    print("  0x%X: decode error: %s" % (cur, res.error))
                    break
                print("  0x%X: %-10s %s" % (
                    cur, res.inst.mnemonic, res.inst.operands))
                cur += res.size
                off += res.size
                if res.inst.is_return:
                    break
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
