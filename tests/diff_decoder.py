"""Check the C++ decoder agrees with the Python decoder on every field except `operands`.

Usage: python3 tests/diff_decoder.py [path-to-decode_dump]   (builds it with g++ if absent)
"""
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "proto"))
from arm64_decode import Arm64Decoder  # noqa: E402
from test_decoder import KNOWN  # noqa: E402

FLAGS = ["set_flags", "is_load", "is_store", "is_signed", "is_pair", "rd_is_sp", "rn_is_sp",
         "is_branch", "is_call", "is_return", "is_cond_branch", "is_indirect", "is_system",
         "is_pac", "is_unallocated", "supported"]


def py_line(addr, word):
    i = Arm64Decoder().decode(addr, word.to_bytes(4, "little")).inst
    flags = sum(int(bool(getattr(i, f))) << n for n, f in enumerate(FLAGS))
    return "|".join(str(x) for x in (
        i.mnemonic, i.alias, i.shift_type, i.mem_mode, i.sf, i.rd, i.rn, i.rm, i.ra, i.rt2, i.size,
        i.shift, i.imm & 0xFFFFFFFFFFFFFFFF, int(i.cond), flags, int(i.reg_class)))


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else None
    tmp = None
    if exe is None:
        if not shutil.which("g++"):
            print("SKIP: no g++")
            return 0
        tmp = tempfile.mkdtemp()
        exe = os.path.join(tmp, "decode_dump")
        subprocess.run(["g++", "-std=c++20", "-O1", "-I" + os.path.join(ROOT, "include"),
                        os.path.join(ROOT, "src", "arm64_decoder.cpp"),
                        os.path.join(ROOT, "tests", "decode_dump.cpp"), "-o", exe], check=True)
    rng = random.Random(99)
    cases = [(0x1000, w) for w, *_ in KNOWN]
    cases += [(rng.getrandbits(40) & ~3, rng.getrandbits(32)) for _ in range(300000)]
    # bias toward the structured groups so they get real coverage
    for _ in range(100000):
        w = rng.getrandbits(32)
        w = (w & 0xE1FFFFFF) | (rng.choice([0x0A, 0x0B, 0x11, 0x12, 0x13, 0x14, 0x1A, 0x1B, 0x08, 0x09,
                                            0x18, 0x19, 0x28, 0x29, 0x38, 0x39, 0x34, 0x36, 0x54,
                                            0x2A, 0x2B]) << 24 & 0x1E000000 | (w & 0xE1000000 if False else 0))
        cases.append((rng.getrandbits(40) & ~3, w))
    stdin = "".join("%x %x\n" % c for c in cases)
    out = subprocess.run([exe], input=stdin, capture_output=True, text=True, check=True).stdout.splitlines()
    assert len(out) == len(cases)
    bad = 0
    for (addr, word), got in zip(cases, out):
        want = py_line(addr, word)
        if got != want:
            bad += 1
            if bad <= 5:
                print("MISMATCH 0x%08x\n  c++: %s\n  py : %s" % (word, got, want))
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        print("%d / %d words differ" % (bad, len(cases)))
        return 1
    print("[PASS] C++ and Python decoders agree on %d instruction words" % len(cases))
    return 0


if __name__ == "__main__":
    sys.exit(main())
