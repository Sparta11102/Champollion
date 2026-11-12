"""Decoder tests: known-answer encodings (from the ARM ARM / real compiler output)
plus a fuzz pass proving the decoder never raises."""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from arm64_decode import Arm64Decoder  # noqa: E402

ADDR = 0x1000
# (opcode, mnemonic, alias, operands)
KNOWN = [
    (0xD2800020, "movz", "", "x0, #0x1"),
    (0xF2A24680, "movk", "", "x0, #0x1234, lsl #16"),
    (0x8B020020, "add", "", "x0, x1, x2"),
    (0xCB020020, "sub", "", "x0, x1, x2"),
    (0xEB020020, "subs", "", "x0, x1, x2"),
    (0xEB02003F, "subs", "cmp", "x1, x2"),
    (0x91001020, "add", "", "x0, x1, #0x4"),
    (0xD10043FF, "sub", "", "sp, sp, #0x10"),
    (0x910003FD, "add", "mov", "x29, sp"),
    (0xAA0103E0, "orr", "mov", "x0, x1"),
    (0x92401C20, "and", "", "x0, x1, #0xff"),
    (0x9B027C20, "madd", "mul", "x0, x1, x2"),
    (0x9AC20820, "udiv", "", "x0, x1, x2"),
    (0x9AC20C20, "sdiv", "", "x0, x1, x2"),
    (0x9AC22020, "lslv", "lsl", "x0, x1, x2"),
    (0xD37CEC20, "ubfm", "lsl", "x0, x1, #60, #59"),
    (0xD344FC20, "ubfm", "lsr", "x0, x1, #4, #63"),
    (0x93407C20, "sbfm", "sxtw", "x0, x1, #0, #31"),
    (0x9A820020, "csel", "", "x0, x1, x2, eq"),
    (0x1A9F17E0, "csinc", "cset", "w0, eq"),
    (0x90000000, "adrp", "", "x0, #0x1000"),
    (0xF9400020, "ldr", "", "x0, [x1]"),
    (0xF90007E0, "str", "", "x0, [sp, #8]"),
    (0xB9000401, "str", "", "w1, [x0, #4]"),
    (0x39400420, "ldrb", "", "w0, [x1, #1]"),
    (0xB9800020, "ldrsw", "", "x0, [x1]"),
    (0xF85F8020, "ldur", "", "x0, [x1, #-8]"),
    (0xF8626820, "ldr", "", "x0, [x1, x2]"),
    (0x58000040, "ldr", "", "x0, #0x1008"),
    (0x18000040, "ldr", "", "w0, #0x1008"),
    (0x3DC00020, "ldr", "", "q0, [x1]"),
    (0xFD0007E0, "str", "", "d0, [sp, #8]"),
    (0xA9BF7BFD, "stp", "", "x29, x30, [sp, #-16]!"),
    (0xA8C17BFD, "ldp", "", "x29, x30, [sp], #16"),
    (0xA9017BFD, "stp", "", "x29, x30, [sp, #16]"),
    (0xC85F7C20, "ldxr", "", "x0, [x1]"),
    (0xC8027C20, "stxr", "", "w2, x0, [x1]"),
    (0x94000040, "bl", "", "#0x1100"),
    (0x14000002, "b", "", "#0x1008"),
    (0xD65F03C0, "ret", "", ""),
    (0xD61F0200, "br", "", "x16"),
    (0xD63F0100, "blr", "", "x8"),
    (0xB4000040, "cbz", "", "x0, #0x1008"),
    (0x54000040, "b.eq", "", "#0x1008"),
    (0x36180040, "tbz", "", "w0, #3, #0x1008"),
    (0xB7080040, "tbnz", "", "x0, #33, #0x1008"),
    (0xD503201F, "nop", "", ""),
    (0xD4001001, "svc", "", "#0x80"),
]


def check_known():
    d = Arm64Decoder()
    failures = 0
    for op, mn, alias, operands in KNOWN:
        r = d.decode(ADDR, op.to_bytes(4, "little"))
        got = (r.inst.mnemonic, r.inst.alias, r.inst.operands)
        ok = r.error is None and got == (mn, alias, operands)
        print("[%s] 0x%08x %-8s want=%r got=%r" % ("PASS" if ok else "FAIL", op, mn, (mn, alias, operands), got))
        failures += not ok
    return failures


def check_flags():
    d = Arm64Decoder()

    def dec(op):
        return d.decode(ADDR, op.to_bytes(4, "little")).inst

    failures = 0
    checks = [
        ("ret is return", dec(0xD65F03C0).is_return and dec(0xD65F03C0).is_branch),
        ("br is indirect, not call", dec(0xD61F0200).is_indirect and not dec(0xD61F0200).is_call),
        ("blr is indirect call", dec(0xD63F0100).is_indirect and dec(0xD63F0100).is_call),
        ("bl is direct call", dec(0x94000040).is_call and not dec(0x94000040).is_indirect),
        ("b.cond cond code", int(dec(0x54000041).cond) == 1),
        ("pacibsp is PAC", dec(0xD503237F).is_pac and dec(0xD503237F).is_system),
        ("retaa is PAC return", dec(0xD65F0BFF).is_pac and dec(0xD65F0BFF).is_return),
        ("fadd is valid but unsupported", not dec(0x1E622820).supported and not dec(0x1E622820).is_unallocated),
        ("zero word is unallocated", dec(0).is_unallocated),
        ("subs sets flags", dec(0xEB020020).set_flags),
        ("sub sp imm: rd is sp", dec(0xD10043FF).rd_is_sp),
        ("ldp pre-index", dec(0xA9BF7BFD).mem_mode == "pre" and dec(0xA9BF7BFD).imm == -16),
        ("ldr offset scaled", dec(0xF90007E0).imm == 8 and dec(0xF90007E0).is_store),
        ("ldrsw is signed load", dec(0xB9800020).is_signed and dec(0xB9800020).is_load),
        ("literal target", dec(0x58000040).imm == 8),
    ]
    for name, ok in checks:
        print("[%s] %s" % ("PASS" if ok else "FAIL", name))
        failures += not ok
    return failures


def check_fuzz(n=200000):
    d = Arm64Decoder()
    rng = random.Random(1234)
    for _ in range(n):
        op = rng.getrandbits(32)
        r = d.decode(rng.getrandbits(40) & ~3, op.to_bytes(4, "little"))
        assert r.inst.opcode == op
        assert (r.error is not None) == r.inst.is_unallocated, hex(op)
    print("[PASS] fuzz: %d random words decoded without exceptions" % n)
    return 0


def check_decode_block():
    d = Arm64Decoder()
    code = (0xD2800020).to_bytes(4, "little") + (0x91001020).to_bytes(4, "little") + \
           (0xD65F03C0).to_bytes(4, "little") + (0xD503201F).to_bytes(4, "little")
    out = d.decode_block(0x1000, code, len(code))
    ok = [i.mnemonic for i in out] == ["movz", "add", "ret"]
    print("[%s] decode_block stops at ret: %s" % ("PASS" if ok else "FAIL", [i.mnemonic for i in out]))
    return not ok


if __name__ == "__main__":
    fails = check_known() + check_flags() + check_decode_block() + check_fuzz()
    if fails:
        print("\n%d DECODER TEST(S) FAILED" % fails)
        sys.exit(1)
    print("\nALL DECODER TESTS PASSED")
