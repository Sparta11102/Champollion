"""
Differential test for loads/stores, the stack and calls.

Random multi-function ARM64 programs (prologues, locals, bl / blr / br / b tail calls,
every load/store width, sign extension, addressing mode and pair form) are
  1. run by a Python reference model with real ARM semantics (ret jumps to x30), and
  2. translated to x86-64 (guest memory identity-mapped at the same addresses),
     assembled with gcc and run natively.
Every register and a CRC of the whole 128 KiB memory window must match.
Needs an x86-64 host with gcc; skips otherwise.
"""
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aot_translator import translate_function  # noqa: E402
from test_aot_diff import (M32, M64, Ref, addsub_imm, addsub_reg, b_cond, logic_reg,  # noqa: E402
                           movw, rand_value)

MEM_BASE, MEM_SIZE = 0x40000000, 0x20000
BUF = MEM_BASE + 0x8000          # x20: data buffer pointer (never modified net)
SP0 = MEM_BASE + 0x1E000         # initial stack pointer
SENTINEL = 0xDEAD0000            # initial x30: returning here ends the program
CODE_BASE, FUNC_STRIDE = 0x10000, 0x400


def initial_memory():
    return bytearray(((i * 37 + 11) & 0xFF) for i in range(MEM_SIZE))


# ---- C harness: identical memory window, runs the translated code ----------------
HARNESS = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
extern uint64_t _champollion_aot_entry(uint64_t *ctx);
static uint32_t crc32_of(const uint8_t *p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (-(int32_t)(c & 1)));
    }
    return ~c;
}
int main(int argc, char **argv) {
    const uint64_t base = 0x40000000ull, size = 0x20000ull;
    uint8_t *mem = mmap((void *)base, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mem != (uint8_t *)base) { fprintf(stderr, "mmap failed\n"); return 3; }
    for (size_t i = 0; i < size; i++) mem[i] = (uint8_t)(i * 37 + 11);
    uint64_t ctx[32];
    for (int i = 0; i < 32; i++) ctx[i] = strtoull(argv[i + 1], 0, 16);
    _champollion_aot_entry(ctx);
    for (int i = 0; i < 32; i++) printf("%llx ", (unsigned long long)ctx[i]);
    printf("%x\n", crc32_of(mem, size));
    return 0;
}
"""


# ---- independent encoders ----------------------------------------------------------
def ldst_imm(size, opc, imm12, rn, rt):
    return (size << 30) | (0x39 << 24) | (opc << 22) | (imm12 << 10) | (rn << 5) | rt

def ldst_ix(size, opc, imm9, mode, rn, rt):          # mode: 0 unscaled, 1 post, 3 pre
    return (size << 30) | (0x38 << 24) | (opc << 22) | ((imm9 & 0x1FF) << 12) | (mode << 10) | (rn << 5) | rt

def ldst_reg(size, opc, rm, option, s, rn, rt):
    return ((size << 30) | (0x38 << 24) | (opc << 22) | (1 << 21) | (rm << 16) | (option << 13)
            | (s << 12) | (2 << 10) | (rn << 5) | rt)

def pair(opc, load, mode, imm7, rt2, rn, rt):        # mode: 1 post, 2 offset, 3 pre
    return ((opc << 30) | (0x5 << 27) | (mode << 23) | (load << 22) | ((imm7 & 0x7F) << 15)
            | (rt2 << 10) | (rn << 5) | rt)

def bl(off):   return 0x94000000 | ((off >> 2) & 0x3FFFFFF)
def b(off):    return 0x14000000 | ((off >> 2) & 0x3FFFFFF)
def blr(rn):   return 0xD63F0000 | (rn << 5)
def br(rn):    return 0xD61F0000 | (rn << 5)
RET = 0xD65F03C0


# ---- reference model -----------------------------------------------------------------
def sext(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class RefMem(Ref):
    def __init__(self, regs):
        super().__init__(regs)
        self.mem = initial_memory()

    def rd(self, addr, n):
        off = addr - MEM_BASE
        if not (0 <= off and off + n <= MEM_SIZE):
            raise AssertionError("reference: access out of bounds 0x%x" % addr)
        return int.from_bytes(self.mem[off:off + n], "little")

    def wr(self, addr, n, v):
        off = addr - MEM_BASE
        if not (0 <= off and off + n <= MEM_SIZE):
            raise AssertionError("reference: access out of bounds 0x%x" % addr)
        self.mem[off:off + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")


def run_ref(prog, entry, regs, max_steps=20000):
    st = RefMem(regs)
    pc = entry
    steps = 0
    while pc != SENTINEL:
        steps += 1
        if steps > max_steps:
            raise AssertionError("reference: runaway program")
        op = prog[pc]
        sf = op >> 31
        nxt = pc + 4
        if (op >> 23) & 0x3F == 0x25:                                   # move wide
            opc, imm, rd, sh = (op >> 29) & 3, (op >> 5) & 0xFFFF, op & 31, ((op >> 21) & 3) * 16
            mask = M64 if sf else M32
            if opc == 2:
                st.set(rd, imm << sh, sf)
            elif opc == 0:
                st.set(rd, (~(imm << sh)) & mask, sf)
            else:
                st.set(rd, (st.get(rd, sf) & ~(0xFFFF << sh)) | (imm << sh), sf)
        elif (op >> 23) & 0x3F == 0x22:                                 # add/sub immediate
            sub, s, sh = (op >> 30) & 1, (op >> 29) & 1, (op >> 22) & 1
            imm = ((op >> 10) & 0xFFF) << (12 if sh else 0)
            rn, rd = (op >> 5) & 31, op & 31
            st.addsub(sf, sub, s, st.get(rn, sf, sp=True), imm, rd, sp_rd=not s)
        elif (op & 0x1F200000) == 0x0B000000:                           # add/sub shifted (no shift)
            sub, s = (op >> 30) & 1, (op >> 29) & 1
            rm, rn, rd = (op >> 16) & 31, (op >> 5) & 31, op & 31
            st.addsub(sf, sub, s, st.get(rn, sf), st.get(rm, sf), rd, sp_rd=False)
        elif (op & 0x1F200000) == 0x0A000000:                           # logical shifted (no shift)
            opc = (op >> 29) & 3
            rm, rn, rd = (op >> 16) & 31, (op >> 5) & 31, op & 31
            a, bb = st.get(rn, sf), st.get(rm, sf)
            res = (a & bb, a | bb, a ^ bb, a & bb)[opc]
            if opc == 3:
                bits = 64 if sf else 32
                st.n, st.z, st.c, st.v = res >> (bits - 1), int(res == 0), 0, 0
            st.set(rd, res, sf)
        elif (op & 0xFF000010) == 0x54000000:                           # b.cond
            off = sext((op >> 5) & 0x7FFFF, 19) << 2
            if st.cond(op & 0xF):
                nxt = pc + off
        elif (op & 0x3E000000) == 0x38000000:                           # load/store register
            size, opc = (op >> 30) & 3, (op >> 22) & 3
            rn, rt = (op >> 5) & 31, op & 31
            base = st.get(rn, 1, sp=True)
            n = 1 << size
            if (op >> 24) & 3 == 1:                                     # unsigned immediate
                addr, wb = base + (((op >> 10) & 0xFFF) << size), None
            elif (op >> 21) & 1:                                        # register offset
                rm, option, s = (op >> 16) & 31, (op >> 13) & 7, (op >> 12) & 1
                idx = st.get(rm, 1)
                idx = {2: idx & M32, 3: idx, 6: sext(idx, 32), 7: idx}[option] & M64
                addr, wb = base + ((idx << (size if s else 0)) & M64), None
            else:
                imm, mode = sext((op >> 12) & 0x1FF, 9), (op >> 10) & 3
                if mode == 0:
                    addr, wb = base + imm, None
                elif mode == 1:
                    addr, wb = base, base + imm
                else:
                    addr = base + imm
                    wb = addr
            addr &= M64
            if opc == 0:                                                # store
                st.wr(addr, n, st.get(rt, 1 if size == 3 else 0))
            else:                                                       # load
                v = st.rd(addr, n)
                dest64 = (size == 3) if opc == 1 else (opc == 2)
                if opc >= 2:
                    v = sext(v, 8 * n)
                st.set(rt, v, 1 if dest64 else 0)
            if wb is not None:
                st.set(rn, wb & M64, 1, sp=True)
        elif (op & 0x3E000000) == 0x28000000:                           # load/store pair
            opc, load, mode = (op >> 30) & 3, (op >> 22) & 1, (op >> 23) & 3
            rt2, rn, rt = (op >> 10) & 31, (op >> 5) & 31, op & 31
            size = 3 if opc == 2 else 2
            n = 1 << size
            imm = sext((op >> 15) & 0x7F, 7) << size
            base = st.get(rn, 1, sp=True)
            addr = base if mode == 1 else base + imm
            addr &= M64
            if load:
                v1, v2 = st.rd(addr, n), st.rd(addr + n, n)
                if opc == 1:                                            # ldpsw
                    st.set(rt, sext(v1, 32), 1)
                    st.set(rt2, sext(v2, 32), 1)
                else:
                    st.set(rt, v1, 1 if size == 3 else 0)
                    st.set(rt2, v2, 1 if size == 3 else 0)
            else:
                w = 1 if size == 3 else 0
                st.wr(addr, n, st.get(rt, w))
                st.wr(addr + n, n, st.get(rt2, w))
            if mode in (1, 3):
                st.set(rn, (base + imm) & M64, 1, sp=True)
        elif (op & 0x7C000000) == 0x14000000:                           # b / bl
            off = sext(op & 0x3FFFFFF, 26) << 2
            if op >> 31:
                st.r[30] = pc + 4
            nxt = pc + off
        elif (op & 0xFFFFFC1F) in (0xD63F0000, 0xD61F0000):             # blr / br
            target = st.r[(op >> 5) & 31]
            if (op & 0xFFFFFC1F) == 0xD63F0000:
                st.r[30] = pc + 4
            nxt = target
        elif op == RET:
            nxt = st.r[30]
        else:
            raise AssertionError("reference: unhandled 0x%08x" % op)
        pc = nxt
    return st.r, zlib.crc32(bytes(st.mem))


# ---- random program generator ----------------------------------------------------------
def dreg(rng):                      # data registers: never x20/x21/sp
    return rng.randrange(0, 9)

def dsrc(rng):
    return 31 if rng.random() < 0.12 else rng.randrange(0, 10)

def gen_data(rng):
    kind = rng.choice(["movw", "addsub", "imm", "logic"])
    sf = rng.getrandbits(1)
    if kind == "movw":
        return movw(sf, rng.choice([0, 2, 3]), rng.randrange(0, 4 if sf else 2), rng.getrandbits(16), dreg(rng))
    if kind == "addsub":
        return addsub_reg(sf, rng.getrandbits(1), rng.getrandbits(1), dsrc(rng), dsrc(rng), dsrc(rng))
    if kind == "imm":
        s = rng.getrandbits(1)
        rd = 31 if s and rng.random() < 0.3 else dreg(rng)      # cmp/cmn with immediate
        return addsub_imm(sf, rng.getrandbits(1), s, rng.getrandbits(1),
                          rng.choice([0, 1, 0xFFF, rng.getrandbits(12)]), dreg(rng), rd)
    return logic_reg(sf, rng.randrange(4), dsrc(rng), dsrc(rng), dsrc(rng))

def gen_flagset(rng):
    sf = rng.getrandbits(1)
    return rng.choice([addsub_reg(sf, 1, 1, dsrc(rng), dsrc(rng), 31),
                       addsub_reg(sf, 0, 1, dsrc(rng), dsrc(rng), 31),
                       addsub_imm(sf, 1, 1, 0, rng.getrandbits(12), dreg(rng), 31),
                       logic_reg(sf, 3, dsrc(rng), dsrc(rng), 31)])

def gen_mem(rng, have_locals, reg_options=(2, 3, 6, 7)):
    """A list of words forming one self-contained memory operation (balanced if it writes back)."""
    base_kind = rng.choice(["buf", "buf", "sp"]) if have_locals else "buf"
    rn = 20 if base_kind == "buf" else 31
    form = rng.choice(["imm", "imm", "unscaled", "reg", "wb", "pair", "pair", "pairwb"])
    if base_kind == "sp" and form in ("reg",):
        form = "imm"
    load = rng.getrandbits(1)

    def offset(size, scaled_max):
        if base_kind == "sp":
            return rng.randrange(0, scaled_max)
        return rng.randrange(-0x40, 0x40)

    if form in ("imm", "unscaled", "wb", "reg"):
        size = rng.randrange(4)
        opc = (rng.choice([1, 2, 3]) if size < 2 else rng.choice([1, 2]) if size == 2 else 1) if load else 0
        if size == 3 and load:
            opc = 1
        rt = 31 if (not load and rng.random() < 0.15) else dreg(rng)
        if form == "imm":
            imm12 = rng.randrange(0, 0x30 >> size) if base_kind == "sp" else rng.randrange(0, 0x100)
            return [ldst_imm(size, opc, imm12, rn, rt)]
        if form == "unscaled":
            imm9 = rng.randrange(0, 0x30) if base_kind == "sp" else rng.randrange(-0x80, 0x80)
            return [ldst_ix(size, opc, imm9, 0, rn, rt)]
        if form == "reg":
            option = rng.choice(reg_options)
            return [ldst_reg(size, opc, 21, option, rng.getrandbits(1), rn, rt)]
        imm9 = rng.randrange(-0x40, 0x40)                          # writeback on x20 (undone afterwards)
        mode = rng.choice([1, 3])
        undo = addsub_imm(1, 0 if imm9 < 0 else 1, 0, 0, abs(imm9), 20, 20)
        return [ldst_ix(size, opc, imm9, mode, 20, rt), undo]
    # pairs
    opc = rng.choice([0, 2]) if not load else rng.choice([0, 1, 2])
    size = 3 if opc == 2 else 2
    r1 = dreg(rng)
    r2 = rng.choice([x for x in range(9) if x != r1])
    if form == "pair":
        imm7 = rng.randrange(0, (0x30 >> size)) if base_kind == "sp" else rng.randrange(-0x20, 0x20)
        return [pair(opc, load, 2, imm7, r2, rn, r1)]
    if base_kind == "sp":                                          # push/pop pair on the stack
        return [pair(opc if not load else opc, 0, 3, -2 if size == 3 else -4, r2, 31, r1),
                pair(opc, 1, 1, 2 if size == 3 else 4, r2, 31, r1)] if opc != 1 else \
               [pair(0, 0, 3, -4, r2, 31, r1), pair(0, 1, 1, 4, r2, 31, r1)]
    imm7 = rng.randrange(-0x10, 0x10)
    mode = rng.choice([1, 3])
    undo = addsub_imm(1, 0 if imm7 < 0 else 1, 0, 0, abs(imm7 << size), 20, 20)
    return [pair(opc, load, mode, imm7, r2, 20, r1), undo]

def pick_index(rng):
    """x21 value plus the extend options that keep the access in bounds for it."""
    kind = rng.choice(["small", "neg64", "neg32", "high"])
    if kind == "small":
        return rng.randrange(0, 0x400), (2, 3, 6, 7)
    if kind == "neg64":
        return (-rng.randrange(1, 0x200)) & M64, (3, 6, 7)        # lsl / sxtw / sxtx
    if kind == "neg32":
        return 0x100000000 - rng.randrange(1, 0x200), (6,)        # only sxtw sees it as negative
    return (rng.getrandbits(32) << 32) | rng.randrange(0, 0x400), (2, 6)   # uxtw / sxtw ignore the top half


def gen_program(rng):
    index, reg_options = pick_index(rng)
    nfuncs = rng.randrange(1, 5)
    funcs = []
    for i in range(nfuncs):
        can_call = i < nfuncs - 1
        calls = can_call and rng.random() < 0.6
        frame = calls or rng.random() < 0.4
        locals_ = rng.random() < 0.7
        items = []
        if frame:
            items.append(pair(2, 0, 3, -2, 30, 31, 29))               # stp x29, x30, [sp, #-16]!
        if locals_:
            items.append(addsub_imm(1, 1, 0, 0, 0x40, 31, 31))         # sub sp, sp, #0x40
        for _ in range(rng.randrange(3, 12)):
            r = rng.random()
            if r < 0.30:
                items.append(gen_data(rng))
            elif r < 0.65:
                items += gen_mem(rng, locals_, reg_options)
            elif r < 0.80:
                items += [gen_flagset(rng), b_cond(rng.randrange(14), 8),
                          gen_data(rng)]
            elif calls:
                j = rng.randrange(i + 1, nfuncs)
                items.append(("bl", j) if rng.random() < 0.5 else ("blr", j))
        tail = None
        if locals_:
            items.append(addsub_imm(1, 0, 0, 0, 0x40, 31, 31))         # add sp, sp, #0x40
        if frame:
            items.append(pair(2, 1, 1, 2, 30, 31, 29))                 # ldp x29, x30, [sp], #16
        elif can_call and rng.random() < 0.3:                          # tail call, no frame
            j = rng.randrange(i + 1, nfuncs)
            items.append(("btail", j) if rng.random() < 0.5 else ("brtail", j))
            tail = True
        if tail is None:
            items.append(RET)
        funcs.append(items)

    def width(item):
        return 2 if isinstance(item, tuple) and item[0] in ("blr", "brtail") else 1

    base = [CODE_BASE + k * FUNC_STRIDE for k in range(nfuncs)]
    prog = {}
    for k, items in enumerate(funcs):
        pc = base[k]
        for item in items:
            if isinstance(item, int):
                prog[pc] = item
                pc += 4
                continue
            kind, j = item
            target = base[j]
            if kind in ("bl", "btail"):
                prog[pc] = (bl if kind == "bl" else b)(target - pc)
                pc += 4
            else:                                                      # blr / br through x9
                prog[pc] = movw(1, 2, 0, target & 0xFFFF, 9)
                prog[pc + 4] = movw(1, 3, 1, (target >> 16) & 0xFFFF, 9)
                prog[pc + 8] = (blr if kind == "blr" else br)(9)
                pc += 12
        assert pc - base[k] < FUNC_STRIDE
    return prog, base[0], base, index


def directed_programs():
    """Loops with backward branches and post-indexed memory access: array sum, byte copy."""
    base = CODE_BASE
    total = [movw(1, 2, 0, 0, 0), movw(1, 2, 0, 64, 2),               # x0 = 0 ; x2 = 64
             ldst_ix(3, 1, 8, 1, 1, 3),                                  # loop: ldr x3, [x1], #8
             addsub_reg(1, 0, 0, 3, 0, 0),                               #       add x0, x0, x3
             addsub_imm(1, 1, 1, 0, 1, 2, 2),                            #       subs x2, x2, #1
             b_cond(1, -12),                                             #       b.ne loop
             RET]
    copy = [movw(1, 2, 0, 200, 2),                                       # x2 = 200
            ldst_ix(0, 1, 1, 1, 1, 3),                                   # loop: ldrb w3, [x1], #1
            ldst_ix(0, 0, 1, 1, 4, 3),                                   #       strb w3, [x4], #1
            addsub_imm(1, 1, 1, 0, 1, 2, 2),                             #       subs x2, x2, #1
            b_cond(1, -12),                                              #       b.ne loop
            RET]
    out = []
    for words, patch in ((total, {1: BUF}), (copy, {1: BUF, 4: BUF + 0x1000})):
        prog = {base + 4 * i: w for i, w in enumerate(words)}
        out.append((prog, base, [base], patch))
    return out


def initial_regs(rng, index):
    regs = [rand_value(rng) for _ in range(31)] + [SP0]
    regs[20] = BUF
    regs[21] = index
    regs[30] = SENTINEL
    return regs


def main(count=500, seed=20261110):
    if platform.machine() not in ("x86_64", "AMD64") or not shutil.which("gcc"):
        print("SKIP: needs an x86-64 host with gcc")
        return 0
    rng = random.Random(seed)
    tmp = tempfile.mkdtemp(prefix="aotmem_")
    open(os.path.join(tmp, "h.c"), "w").write(HARNESS)
    subprocess.run(["gcc", "-c", "-O0", os.path.join(tmp, "h.c"), "-o", os.path.join(tmp, "h.o")], check=True)
    failures = 0
    mem_ops = calls = 0
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
        mem_ops += sum(1 for w in prog.values() if (w & 0x3E000000) in (0x38000000, 0x28000000))
        calls += sum(1 for w in prog.values() if (w & 0xFC000000) == 0x94000000 or (w & 0xFFFFFC1F) == 0xD63F0000)
        asm = translate_function(lambda a: prog[a].to_bytes(4, "little") if a in prog else b"",
                                 entry, extra_entries=funcs)
        s_path, exe = os.path.join(tmp, "p.s"), os.path.join(tmp, "p")
        open(s_path, "w").write(asm)
        subprocess.run(["gcc", "-no-pie", os.path.join(tmp, "h.o"), s_path, "-o", exe,
                        "-Wl,-z,noexecstack"], check=True, capture_output=True)
        out = subprocess.run([exe] + ["%x" % r for r in regs], check=True,
                             capture_output=True, text=True).stdout.split()
        got = [int(x, 16) for x in out]
        want_regs, want_crc = run_ref(prog, entry, regs)
        if got != want_regs + [want_crc]:
            failures += 1
            if failures <= 3:
                print("MISMATCH program %d" % n)
                for i, (g, w) in enumerate(zip(got[:32], want_regs)):
                    if g != w:
                        print("  reg %d: x86=%x ref=%x" % (i, g, w))
                if got[32] != want_crc:
                    print("  memory crc: x86=%x ref=%x" % (got[32], want_crc))
                for a in sorted(prog):
                    print("   %x: %08x" % (a, prog[a]))
    shutil.rmtree(tmp, ignore_errors=True)
    if failures:
        print("%d / %d programs mismatched" % (failures, count))
        return 1
    print("[PASS] %d random multi-function programs (%d memory ops, %d calls): translated code "
          "matches the reference model, registers and memory" % (count, mem_ops, calls))
    return 0


if __name__ == "__main__":
    sys.exit(main())
