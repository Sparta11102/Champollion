"""Differential test for the C++ JIT: random ARM64 programs are run through the JIT
(tests/jit_run.cpp) and through the Python reference model; every register must match.
Also checks that unsupported code is refused rather than mistranslated."""
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "proto"))
from test_aot_diff import gen_program, rand_value, run_ref  # noqa: E402


def run_jit(exe, prog, regs, entry=0, extras=(), addrs=None):
    """prog: list of words laid out from address 0 (or `addrs` to place them explicitly)."""
    addrs = addrs if addrs is not None else [4 * i for i in range(len(prog))]
    lines = ["%d" % len(prog)] + ["%x %x" % (a, w) for a, w in zip(addrs, prog)]
    lines += ["%x" % entry, "%d" % len(extras)] + ["%x" % e for e in extras]
    lines.append(" ".join("%x" % r for r in regs))
    return subprocess.run([exe], input="\n".join(lines) + "\n", capture_output=True, text=True,
                          check=True).stdout.strip()


def main(count=600, seed=424242):
    if platform.machine() not in ("x86_64", "AMD64") or not shutil.which("g++"):
        print("SKIP: needs an x86-64 host with g++")
        return 0
    tmp = tempfile.mkdtemp()
    exe = os.path.join(tmp, "jit_run")
    subprocess.run(["g++", "-std=c++20", "-O1", "-I" + os.path.join(ROOT, "include"),
                    os.path.join(ROOT, "src", "arm64_decoder.cpp"),
                    os.path.join(ROOT, "src", "x64_backend.cpp"),
                    os.path.join(ROOT, "tests", "jit_run.cpp"), "-o", exe], check=True)
    rng = random.Random(seed)
    failures = 0
    for n in range(count):
        prog = gen_program(rng)
        regs = [rand_value(rng) for _ in range(31)] + [0x7FFF0000 + rng.getrandbits(12) * 16]
        out = run_jit(exe, prog, regs)
        want = run_ref(prog, regs)
        got = [int(x, 16) for x in out.split()][:32] if not out.startswith("COMPILE_ERROR") else None
        if got != want:
            failures += 1
            if failures <= 3:
                print("MISMATCH program %d: %s" % (n, out[:80]))
                print("  words:", " ".join("%08x" % w for w in prog))
                if got:
                    for i, (g, w) in enumerate(zip(got, want)):
                        if g != w:
                            print("  reg %d: jit=%x ref=%x" % (i, g, w))
    # unsupported code must be refused with an error, never mistranslated
    refused = 0
    for words in ([0xC85F7C20, 0xD65F03C0],            # ldxr x0,[x1]; ret       (exclusive access)
                  [0x94000100, 0xD65F03C0],            # bl far outside the code (call target not in region)
                  [0x1E622820, 0xD65F03C0],            # fadd; ret               (FP)
                  [0xD2800020]):                       # movz with no ret
        out = run_jit(exe, words, [0] * 32)
        refused += out.startswith("COMPILE_ERROR")
    shutil.rmtree(tmp, ignore_errors=True)
    if failures or refused != 4:
        print("%d mismatches, %d/4 unsupported programs refused" % (failures, refused))
        return 1
    print("[PASS] JIT matches the ARM64 reference model on %d random programs; "
          "4/4 unsupported programs refused" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
