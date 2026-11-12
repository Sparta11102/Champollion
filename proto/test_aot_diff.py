"""
Differential test for the AOT translator.

Random ARM64 programs (using an independent encoder below) are
  1. executed by a small Python reference model of ARM64 semantics, and
  2. translated to x86-64, assembled with gcc, and run natively,
then every guest register is compared. Needs an x86-64 host with gcc; skips otherwise.
"""
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aot_translator import translate_function  # noqa: E402

M64, M32 = (1 << 64) - 1, (1 << 32) - 1

HARNESS = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
extern uint64_t _champollion_aot_entry(uint64_t *ctx);
int main(int argc, char **argv) {
    uint64_t ctx[32];
    for (int i = 0; i < 32; i++) ctx[i] = strtoull(argv[i + 1], 0, 16);
    _champollion_aot_entry(ctx);
    for (int i = 0; i < 32; i++) printf("%llx ", (unsigned long long)ctx[i]);
    printf("\n");
    return 0;
}
"""


# ---- independent ARM64 encoder (field-by-field, not shared with the decoder) ----
def movw(sf, opc, hw, imm16, rd):
    return (sf << 31) | (opc << 29) | (0x25 << 23) | (hw << 21) | (imm16 << 5) | rd

def addsub_reg(sf, op, s, rm, rn, rd):
    return (sf << 31) | (op << 30) | (s << 29) | (0x0B << 24) | (rm << 16) | (rn << 5) | rd

def addsub_imm(sf, op, s, sh, imm12, rn, rd):
    return (sf << 31) | (op << 30) | (s << 29) | (0x22 << 23) | (sh << 22) | (imm12 << 10) | (rn << 5) | rd

def logic_reg(sf, opc, rm, rn, rd):
    return (sf << 31) | (opc << 29) | (0x0A << 24) | (rm << 16) | (rn << 5) | rd

def b_cond(cond, off):
    return 0x54000000 | (((off >> 2) & 0x7FFFF) << 5) | cond

def cbz(sf, nz, rt, off):
    return (sf << 31) | (0x1A << 25) | (nz << 24) | (((off >> 2) & 0x7FFFF) << 5) | rt

def tbz(nz, rt, bit, off):
    return ((bit >> 5) << 31) | (0x1B << 25) | (nz << 24) | ((bit & 31) << 19) | (((off >> 2) & 0x3FFF) << 5) | rt

RET = 0xD65F03C0


# ---- reference model ------------------------------------------------------------
class Ref:
    def __init__(self, regs):
        self.r = list(regs)      # r[0..30], r[31] = SP slot
        self.n = self.z = self.c = self.v = 0

    def get(self, i, sf, sp=False):
        v = 0 if (i == 31 and not sp) else self.r[i]
        return v & (M64 if sf else M32)

    def set(self, i, v, sf, sp=False):
        if i == 31 and not sp:
            return
        self.r[i] = v & (M64 if sf else M32)

    def addsub(self, sf, sub, s, a, b, rd, sp_rd):
        bits = 64 if sf else 32
        mask = (1 << bits) - 1
        if sub:
            b_eff, cin = (~b) & mask, 1
        else:
            b_eff, cin = b, 0
        total = a + b_eff + cin
        res = total & mask
        if s:
            self.n = res >> (bits - 1)
            self.z = int(res == 0)
            self.c = int(total > mask)
            sa, sb_ = a >> (bits - 1), b_eff >> (bits - 1)
            self.v = int(sa == sb_ and sa != (res >> (bits - 1)))
        self.set(rd, res, sf, sp=sp_rd)

    def cond(self, c):
        base = {0: self.z, 1: not self.z, 2: self.c, 3: not self.c, 4: self.n, 5: not self.n,
                6: self.v, 7: not self.v, 8: self.c and not self.z, 9: (not self.c) or self.z,
                10: self.n == self.v, 11: self.n != self.v,
                12: (not self.z) and self.n == self.v, 13: self.z or self.n != self.v,
                14: 1, 15: 1}
        return bool(base[c])


def run_ref(prog, regs):
    st = Ref(regs)
    pc = 0
    while True:
        op = prog[pc // 4]
        if op == RET:
            return st.r
        sf = op >> 31
        if (op >> 23) & 0x3F == 0x25:                        # move wide
            opc, hw, imm = (op >> 29) & 3, (op >> 21) & 3, (op >> 5) & 0xFFFF
            rd, sh = op & 31, ((op >> 21) & 3) * 16
            mask = M64 if sf else M32
            if opc == 2:
                st.set(rd, imm << sh, sf)
            elif opc == 0:
                st.set(rd, (~(imm << sh)) & mask, sf)
            else:
                st.set(rd, (st.get(rd, sf) & ~(0xFFFF << sh)) | (imm << sh), sf)
        elif (op >> 23) & 0x3F == 0x22:                      # add/sub immediate
            sub, s, sh = (op >> 30) & 1, (op >> 29) & 1, (op >> 22) & 1
            imm = ((op >> 10) & 0xFFF) << (12 if sh else 0)
            rn, rd = (op >> 5) & 31, op & 31
            st.addsub(sf, sub, s, st.get(rn, sf, sp=True), imm, rd, sp_rd=not s)
        elif (op & 0x1F200000) == 0x0B000000:                # add/sub shifted (no shift)
            sub, s = (op >> 30) & 1, (op >> 29) & 1
            rm, rn, rd = (op >> 16) & 31, (op >> 5) & 31, op & 31
            st.addsub(sf, sub, s, st.get(rn, sf), st.get(rm, sf), rd, sp_rd=False)
        elif (op & 0x1F200000) == 0x0A000000:                # logical shifted (no shift)
            opc = (op >> 29) & 3
            rm, rn, rd = (op >> 16) & 31, (op >> 5) & 31, op & 31
            a, b = st.get(rn, sf), st.get(rm, sf)
            res = (a & b, a | b, a ^ b, a & b)[opc]
            bits = 64 if sf else 32
            if opc == 3:
                st.n, st.z, st.c, st.v = res >> (bits - 1), int(res == 0), 0, 0
            st.set(rd, res, sf)
        elif (op & 0xFF000010) == 0x54000000:                # b.cond
            off = ((op >> 5) & 0x7FFFF)
            off = (off - (1 << 19) if off >> 18 else off) << 2
            if st.cond(op & 0xF):
                pc += off
                continue
        elif (op & 0x7E000000) == 0x34000000:                # cbz / cbnz
            rt, nz = op & 31, (op >> 24) & 1
            off = (op >> 5) & 0x7FFFF
            off = (off - (1 << 19) if off >> 18 else off) << 2
            if (st.get(rt, sf) == 0) != bool(nz):
                pc += off
                continue
        elif (op & 0x7E000000) == 0x36000000:                # tbz / tbnz
            rt, nz = op & 31, (op >> 24) & 1
            bit = ((op >> 31) << 5) | ((op >> 19) & 31)
            off = (op >> 5) & 0x3FFF
            off = (off - (1 << 13) if off >> 13 else off) << 2
            if (((st.get(rt, 1) >> bit) & 1) == 0) != bool(nz):
                pc += off
                continue
        else:
            raise AssertionError("reference model: unhandled 0x%08x" % op)
        pc += 4


# ---- random program generator ----------------------------------------------------
def rand_reg(rng, allow31=True):
    return 31 if (allow31 and rng.random() < 0.15) else rng.randrange(0, 10)

def gen_straight(rng, n):
    out = []
    for _ in range(n):
        kind = rng.choice(["movw", "movw", "addsub", "addsub", "imm", "imm", "logic"])
        sf = rng.getrandbits(1)
        if kind == "movw":
            opc = rng.choice([0, 2, 3])
            hw = rng.randrange(0, 4 if sf else 2)
            out.append(movw(sf, opc, hw, rng.getrandbits(16), rand_reg(rng, False)))
        elif kind == "addsub":
            out.append(addsub_reg(sf, rng.getrandbits(1), rng.getrandbits(1),
                                  rand_reg(rng), rand_reg(rng), rand_reg(rng)))
        elif kind == "imm":
            out.append(addsub_imm(sf, rng.getrandbits(1), rng.getrandbits(1), rng.getrandbits(1),
                                  rng.choice([0, 1, 0xFFF, rng.getrandbits(12)]),
                                  rand_reg(rng), rand_reg(rng)))
        else:
            out.append(logic_reg(sf, rng.randrange(4), rand_reg(rng), rand_reg(rng), rand_reg(rng)))
    return out

def gen_program(rng):
    prog = gen_straight(rng, rng.randrange(2, 9))
    # force a flag setter so conditions see meaningful flags
    sf = rng.getrandbits(1)
    prog.append(rng.choice([
        addsub_reg(sf, 1, 1, rand_reg(rng), rand_reg(rng), 31),            # cmp
        addsub_reg(sf, 0, 1, rand_reg(rng), rand_reg(rng), 31),            # cmn
        addsub_imm(sf, 1, 1, 0, rng.getrandbits(12), rand_reg(rng), 31),   # cmp imm
        logic_reg(sf, 3, rand_reg(rng), rand_reg(rng), 31),                # tst
    ]))
    kind = rng.choice(["cond", "cond", "cond", "cbz", "tbz"])
    if kind == "cond":
        branch = b_cond(rng.randrange(16 if False else 15), 12)
    elif kind == "cbz":
        branch = cbz(rng.getrandbits(1), rng.getrandbits(1), rng.randrange(0, 10), 12)
    else:
        branch = tbz(rng.getrandbits(1), rng.randrange(0, 10), rng.randrange(64), 12)
    prog += [branch, movw(1, 2, 0, 1, 0), RET, movw(1, 2, 0, 2, 0), RET]
    return prog


def rand_value(rng):
    return rng.choice([0, 1, M64, M64 - 1, 1 << 63, (1 << 63) - 1, M32, 1 << 31,
                       rng.getrandbits(64), rng.getrandbits(32), rng.getrandbits(8)])


def main(count=400, seed=20261109):
    if platform.machine() not in ("x86_64", "AMD64") or not shutil.which("gcc"):
        print("SKIP: needs an x86-64 host with gcc")
        return 0
    rng = random.Random(seed)
    tmp = tempfile.mkdtemp(prefix="aotdiff_")
    (open(os.path.join(tmp, "h.c"), "w")).write(HARNESS)
    # Compile the harness once; each program is assembled into its own binary.
    subprocess.run(["gcc", "-c", "-O0", os.path.join(tmp, "h.c"), "-o", os.path.join(tmp, "h.o")], check=True)
    failures = 0
    for n in range(count):
        prog = gen_program(rng)
        regs = [rand_value(rng) for _ in range(31)] + [0x7FFF0000 + rng.getrandbits(12) * 16]
        words = {i * 4: w for i, w in enumerate(prog)}
        asm = translate_function(lambda a: words[a].to_bytes(4, "little") if a in words else b"", 0)
        s_path, exe = os.path.join(tmp, "p.s"), os.path.join(tmp, "p")
        open(s_path, "w").write(asm)
        subprocess.run(["gcc", "-no-pie", os.path.join(tmp, "h.o"), s_path, "-o", exe,
                        "-Wl,-z,noexecstack"], check=True, capture_output=True)
        out = subprocess.run([exe] + ["%x" % r for r in regs], check=True,
                             capture_output=True, text=True).stdout.split()
        got = [int(x, 16) for x in out]
        want = run_ref(prog, regs)
        if got != want:
            failures += 1
            if failures <= 3:
                print("MISMATCH program %d:" % n)
                print("  words:", " ".join("%08x" % w for w in prog))
                for i, (g, w) in enumerate(zip(got, want)):
                    if g != w:
                        print("  reg %d: x86=%x ref=%x" % (i, g, w))
    shutil.rmtree(tmp, ignore_errors=True)
    if failures:
        print("%d / %d programs mismatched" % (failures, count))
        return 1
    print("[PASS] %d random programs: translated x86-64 matches the ARM64 reference model" % count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
