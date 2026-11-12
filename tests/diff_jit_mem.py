"""JIT differential test for loads/stores, the stack and calls: the same random multi-function
programs as proto/test_aot_mem_diff.py, run through the C++ JIT and the Python reference model.
Registers and a CRC of the 128 KiB memory window must match."""
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "proto"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_aot_mem_diff import directed_programs, gen_program, initial_regs, run_ref  # noqa: E402
from diff_jit import run_jit  # noqa: E402


def main(count=500, seed=20261111):
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
    directed = directed_programs()
    for n in range(count + len(directed)):
        if n < len(directed):
            prog, entry, funcs, patch = directed[n]
            regs = initial_regs(rng, 0)
            for reg, value in patch.items():
                regs[reg] = value
        else:
            prog, entry, funcs, index = gen_program(rng)
            regs = initial_regs(rng, index)
        addrs = sorted(prog)
        out = run_jit(exe, [prog[a] for a in addrs], regs, entry=entry, extras=funcs, addrs=addrs)
        want_regs, want_crc = run_ref(prog, entry, regs)
        got = None if out.startswith("COMPILE_ERROR") else [int(x, 16) for x in out.split()]
        if got != want_regs + [want_crc]:
            failures += 1
            if failures <= 3:
                print("MISMATCH program %d: %s" % (n, out[:60]))
                if got:
                    for i, (g, w) in enumerate(zip(got[:32], want_regs)):
                        if g != w:
                            print("  reg %d: jit=%x ref=%x" % (i, g, w))
                    if got[32] != want_crc:
                        print("  memory crc: jit=%x ref=%x" % (got[32], want_crc))
    shutil.rmtree(tmp, ignore_errors=True)
    if failures:
        print("%d / %d programs mismatched" % (failures, count))
        return 1
    print("[PASS] JIT matches the reference model (registers and memory) on %d random "
          "multi-function programs plus 2 directed loops" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
