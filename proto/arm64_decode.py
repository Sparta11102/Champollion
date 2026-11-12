"""
ARM64 (AArch64) decoder, written against the ARM Architecture Reference Manual
top-level encoding groups.

Covers the integer base ISA real compiled code uses: PC-relative, add/sub,
logical, move-wide, bitfield, extract, every branch form, loads/stores
(immediate, register, pair, literal, exclusive), conditional select/compare,
multiply/divide, shifts, bit-reverse/clz, and the common system/hint ops.

Valid-but-undecoded instructions (SIMD/FP, LSE atomics, ...) come back with
supported=False and a mnemonic starting with "."; reserved encodings set
is_unallocated and DecodeResult.error.

Python 3.8 compatible (macOS 11 command line tools ship Python 3.8).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class ArmCond(IntEnum):
    EQ = 0; NE = 1; HS = 2; LO = 3; MI = 4; PL = 5; VS = 6; VC = 7
    HI = 8; LS = 9; GE = 10; LT = 11; GT = 12; LE = 13; AL = 14; NV = 15


class ArmRegClass(IntEnum):
    GPR = 0
    VREG = 1


COND = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
M64 = 0xFFFFFFFFFFFFFFFF


@dataclass
class Arm64Inst:
    opcode: int = 0
    address: int = 0
    mnemonic: str = ""
    operands: str = ""
    alias: str = ""          # preferred disassembly alias (mov, cmp, lsl, ...)
    reg_class: ArmRegClass = ArmRegClass.GPR
    rd: int = 0; rn: int = 0; rm: int = 0; ra: int = 0; rt2: int = 0
    size: int = 0            # access size log2 for loads/stores (0=b .. 4=q)
    sf: int = 0              # 0=32-bit, 1=64-bit
    imm: int = 0
    shift: int = 0
    shift_type: str = ""     # lsl/lsr/asr/ror, or extend name
    cond: ArmCond = ArmCond.AL
    mem_mode: str = ""       # offset / pre / post / reg / unscaled / literal / exclusive
    set_flags: bool = False
    is_load: bool = False
    is_store: bool = False
    is_signed: bool = False
    is_pair: bool = False
    rd_is_sp: bool = False   # register 31 means SP instead of ZR
    rn_is_sp: bool = False
    is_branch: bool = False
    is_call: bool = False
    is_return: bool = False
    is_cond_branch: bool = False
    is_indirect: bool = False
    is_system: bool = False
    is_pac: bool = False
    is_unallocated: bool = False
    supported: bool = True


@dataclass
class DecodeResult:
    inst: Arm64Inst = field(default_factory=Arm64Inst)
    size: int = 4
    error: Optional[str] = None


def bits(insn: int, lsb: int, msb: int) -> int:
    return (insn >> lsb) & ((1 << (msb - lsb + 1)) - 1)


def sext(value: int, bit_count: int) -> int:
    value &= (1 << bit_count) - 1
    return value - (1 << bit_count) if value >> (bit_count - 1) else value


def R(i: int, sf: int, sp: bool = False) -> str:
    """General register name. Index 31 is SP when sp=True, otherwise XZR/WZR."""
    if i == 31:
        return ("sp" if sf else "wsp") if sp else ("xzr" if sf else "wzr")
    return ("x%d" if sf else "w%d") % i


def cond_name(c) -> str:
    return COND[int(c)]


def decode_bitmask(n: int, imms: int, immr: int, datasize: int) -> Optional[int]:
    """AArch64 DecodeBitMasks (wmask only). None for reserved encodings."""
    x = (n << 6) | (~imms & 0x3F)
    if x == 0:
        return None
    length = x.bit_length() - 1
    if length < 1:
        return None
    esize = 1 << length
    if esize > datasize:
        return None
    levels = esize - 1
    s, r = imms & levels, immr & levels
    if s == levels:
        return None
    welem = (1 << (s + 1)) - 1
    mask_e = (1 << esize) - 1
    rot = ((welem >> r) | (welem << (esize - r))) & mask_e
    out = 0
    for i in range(0, datasize, esize):
        out |= rot << i
    return out


_PAC_HINTS = {7: "xpaclri", 8: "pacia1716", 10: "pacib1716", 12: "autia1716",
              14: "autib1716", 24: "paciaz", 25: "paciasp", 26: "pacibz",
              27: "pacibsp", 28: "autiaz", 29: "autiasp", 30: "autibz",
              31: "autibsp"}
_HINTS = {0: "nop", 1: "yield", 2: "wfe", 3: "wfi", 4: "sev", 5: "sevl",
          16: "esb", 17: "psb", 18: "tsb", 20: "csdb"}
_SIMD_SZ = {0: "b", 1: "h", 2: "s", 3: "d", 4: "q"}
_STYPES = ("lsl", "lsr", "asr", "ror")


def _vreg(idx: int, log2: int) -> str:
    return "%s%d" % (_SIMD_SZ[log2], idx)


class Arm64Decoder:
    # ------------------------------------------------------------------ API
    def decode(self, addr: int, code: bytes) -> DecodeResult:
        insn = int.from_bytes(code[:4], "little")
        inst = Arm64Inst(opcode=insn, address=addr)
        res = DecodeResult(inst=inst)
        op0 = (insn >> 25) & 0xF
        if insn == 0:
            inst.is_unallocated, inst.mnemonic = True, "udf"
        elif (op0 >> 1) == 0x4:
            self._dp_imm(insn, addr, inst)
        elif (op0 >> 1) == 0x5:
            self._branch_sys(insn, addr, inst)
        elif (op0 & 0x5) == 0x4:
            self._load_store(insn, addr, inst)
        elif (op0 & 0x7) == 0x5:
            self._dp_reg(insn, inst)
        elif (op0 & 0x7) == 0x7:
            inst.supported, inst.mnemonic = False, ".simd_fp"
            inst.reg_class = ArmRegClass.VREG
        else:
            inst.is_unallocated, inst.mnemonic = True, ".reserved"
        if inst.is_unallocated:
            res.error = "unallocated opcode"
        return res

    def decode_block(self, start_addr: int, code: bytes, limit: int) -> List[Arm64Inst]:
        out: List[Arm64Inst] = []
        cur, off = start_addr, 0
        while off + 4 <= limit and off + 4 <= len(code):
            res = self.decode(cur, code[off:off + 4])
            if res.error:
                break
            out.append(res.inst)
            cur += 4
            off += 4
            if res.inst.is_branch:
                break
        return out

    @staticmethod
    def _bad(i: Arm64Inst) -> None:
        i.is_unallocated = True
        i.mnemonic = ".unallocated"

    @staticmethod
    def _unsupported(i: Arm64Inst, name: str) -> None:
        i.supported = False
        i.mnemonic = name

    # ------------------------------------------- data processing (immediate)
    def _dp_imm(self, insn: int, addr: int, i: Arm64Inst) -> None:
        sf = bits(insn, 31, 31)
        i.sf = sf
        rd, rn = bits(insn, 0, 4), bits(insn, 5, 9)
        i.rd, i.rn = rd, rn
        group = bits(insn, 23, 25)

        if group in (0, 1):                      # ADR / ADRP
            imm = sext((bits(insn, 5, 23) << 2) | bits(insn, 29, 30), 21)
            i.sf = 1
            if sf:
                i.mnemonic, i.imm = "adrp", imm << 12
                target = (addr & ~0xFFF) + i.imm
            else:
                i.mnemonic, i.imm = "adr", imm
                target = addr + imm
            i.operands = "%s, #0x%x" % (R(rd, 1), target & M64)
        elif group == 2:                         # ADD/SUB (immediate)
            op, s, sh = bits(insn, 30, 30), bits(insn, 29, 29), bits(insn, 22, 22)
            imm = bits(insn, 10, 21) << (12 if sh else 0)
            i.imm, i.shift, i.set_flags = imm, (12 if sh else 0), bool(s)
            i.rn_is_sp, i.rd_is_sp = True, not s
            i.mnemonic = ("sub" if op else "add") + ("s" if s else "")
            if s and rd == 31:
                i.alias = "cmp" if op else "cmn"
                i.operands = "%s, #0x%x" % (R(rn, sf, True), imm)
            elif not s and not op and imm == 0 and (rd == 31 or rn == 31):
                i.alias = "mov"
                i.operands = "%s, %s" % (R(rd, sf, True), R(rn, sf, True))
            else:
                i.operands = "%s, %s, #0x%x" % (R(rd, sf, not s), R(rn, sf, True), imm)
        elif group == 4:                         # logical (immediate)
            opc, n = bits(insn, 29, 30), bits(insn, 22, 22)
            immr, imms = bits(insn, 16, 21), bits(insn, 10, 15)
            if not sf and n:
                return self._bad(i)
            mask = decode_bitmask(n, imms, immr, 64 if sf else 32)
            if mask is None:
                return self._bad(i)
            i.imm = mask
            i.mnemonic = ("and", "orr", "eor", "ands")[opc]
            i.set_flags, i.rd_is_sp = opc == 3, opc != 3
            if opc == 3 and rd == 31:
                i.alias = "tst"
                i.operands = "%s, #0x%x" % (R(rn, sf), mask)
            elif opc == 1 and rn == 31:
                i.alias = "mov"
                i.operands = "%s, #0x%x" % (R(rd, sf, True), mask)
            else:
                i.operands = "%s, %s, #0x%x" % (R(rd, sf, opc != 3), R(rn, sf), mask)
        elif group == 5:                         # move wide
            opc, hw = bits(insn, 29, 30), bits(insn, 21, 22)
            if opc == 1 or (not sf and hw > 1):
                return self._bad(i)
            imm16 = bits(insn, 5, 20)
            i.imm, i.shift = imm16, hw * 16
            i.mnemonic = {0: "movn", 2: "movz", 3: "movk"}[opc]
            i.operands = "%s, #0x%x" % (R(rd, sf), imm16)
            if hw:
                i.operands += ", lsl #%d" % (hw * 16)
        elif group == 6:                         # bitfield
            opc, n = bits(insn, 29, 30), bits(insn, 22, 22)
            immr, imms = bits(insn, 16, 21), bits(insn, 10, 15)
            if opc == 3 or n != sf or (not sf and (immr > 31 or imms > 31)):
                return self._bad(i)
            width = 64 if sf else 32
            i.mnemonic = ("sbfm", "bfm", "ubfm")[opc]
            i.imm, i.shift = (immr << 8) | imms, immr
            i.operands = "%s, %s, #%d, #%d" % (R(rd, sf), R(rn, sf), immr, imms)
            if opc == 2 and imms != width - 1 and imms + 1 == immr:
                i.alias = "lsl"
            elif opc == 2 and imms == width - 1:
                i.alias = "lsr"
            elif opc == 0 and imms == width - 1:
                i.alias = "asr"
            elif opc == 0 and immr == 0 and imms in (7, 15, 31):
                i.alias = {7: "sxtb", 15: "sxth", 31: "sxtw"}[imms]
            elif opc == 2 and immr == 0 and imms in (7, 15):
                i.alias = {7: "uxtb", 15: "uxth"}[imms]
        else:                                    # group 7: extract (3 = tags)
            if group == 3:
                return self._unsupported(i, ".dp_imm_tags")
            op21, n, o0 = bits(insn, 29, 30), bits(insn, 22, 22), bits(insn, 21, 21)
            imms, rm = bits(insn, 10, 15), bits(insn, 16, 20)
            if op21 != 0 or n != sf or o0 or (not sf and imms > 31):
                return self._bad(i)
            i.mnemonic, i.rm, i.imm = "extr", rm, imms
            i.alias = "ror" if rn == rm else ""
            i.operands = "%s, %s, %s, #%d" % (R(rd, sf), R(rn, sf), R(rm, sf), imms)

    # -------------------------------------------------- branches and system
    def _branch_sys(self, insn: int, addr: int, i: Arm64Inst) -> None:
        if (insn & 0x7C000000) == 0x14000000:    # B / BL
            link = bool(insn >> 31)
            i.imm = sext(bits(insn, 0, 25), 26) << 2
            i.is_branch, i.is_call = True, link
            i.mnemonic = "bl" if link else "b"
            i.operands = "#0x%x" % ((addr + i.imm) & M64)
        elif (insn & 0x7E000000) == 0x34000000:  # CBZ / CBNZ
            i.sf, i.rd = bits(insn, 31, 31), bits(insn, 0, 4)
            i.imm = sext(bits(insn, 5, 23), 19) << 2
            i.is_branch = i.is_cond_branch = True
            i.mnemonic = "cbnz" if bits(insn, 24, 24) else "cbz"
            i.operands = "%s, #0x%x" % (R(i.rd, i.sf), (addr + i.imm) & M64)
        elif (insn & 0x7E000000) == 0x36000000:  # TBZ / TBNZ
            i.rd = bits(insn, 0, 4)
            bit = (bits(insn, 31, 31) << 5) | bits(insn, 19, 23)
            i.sf, i.shift = (1 if bit >= 32 else 0), bit
            i.imm = sext(bits(insn, 5, 18), 14) << 2
            i.is_branch = i.is_cond_branch = True
            i.mnemonic = "tbnz" if bits(insn, 24, 24) else "tbz"
            i.operands = "%s, #%d, #0x%x" % (R(i.rd, i.sf), bit, (addr + i.imm) & M64)
        elif (insn & 0xFF000010) == 0x54000000:  # B.cond
            i.cond = ArmCond(bits(insn, 0, 3))
            i.imm = sext(bits(insn, 5, 23), 19) << 2
            i.is_branch = i.is_cond_branch = True
            i.mnemonic = "b." + cond_name(i.cond)
            i.operands = "#0x%x" % ((addr + i.imm) & M64)
        elif (insn & 0xFE000000) == 0xD6000000:  # branch (register)
            self._branch_reg(insn, i)
        elif (insn & 0xFF000000) == 0xD4000000:  # exception generation
            opc, ll = bits(insn, 21, 23), bits(insn, 0, 1)
            name = {(0, 1): "svc", (0, 2): "hvc", (0, 3): "smc",
                    (1, 0): "brk", (2, 0): "hlt"}.get((opc, ll))
            if bits(insn, 2, 4) or not name:
                return self._bad(i)
            i.mnemonic, i.imm, i.is_system = name, bits(insn, 5, 20), True
            i.operands = "#0x%x" % i.imm
        elif (insn & 0xFFC00000) == 0xD5000000:  # system
            self._system(insn, i)
        else:
            self._bad(i)

    def _branch_reg(self, insn: int, i: Arm64Inst) -> None:
        opc, op2 = bits(insn, 21, 24), bits(insn, 16, 20)
        op3, rn, op4 = bits(insn, 10, 15), bits(insn, 5, 9), bits(insn, 0, 4)
        i.rn = rn
        if op2 != 0x1F:
            return self._bad(i)
        if op3 == 0 and op4 == 0 and opc in (0, 1, 2):
            i.mnemonic = ("br", "blr", "ret")[opc]
            i.is_branch = True
            i.is_indirect, i.is_call, i.is_return = opc != 2, opc == 1, opc == 2
            i.operands = ("" if rn == 30 else R(rn, 1)) if opc == 2 else R(rn, 1)
        elif op3 == 0 and op4 == 0 and opc in (4, 5) and rn == 31:
            i.mnemonic = "eret" if opc == 4 else "drps"
            i.is_branch = i.is_system = True
            i.is_return = opc == 4
        elif op3 in (2, 3):                      # PAC branch forms (arm64e)
            i.is_pac = i.is_branch = True
            key = "a" if op3 == 2 else "b"
            if opc in (0, 1) and op4 == 31:
                i.mnemonic = ("br", "blr")[opc] + "a" + key + "z"
                i.is_indirect, i.is_call = True, opc == 1
                i.operands = R(rn, 1)
            elif opc in (8, 9):
                i.mnemonic = ("br", "blr")[opc - 8] + "a" + key
                i.is_indirect, i.is_call = True, opc == 9
                i.operands = "%s, %s" % (R(rn, 1), R(op4, 1, True))
            elif opc == 2 and rn == 31 and op4 == 31:
                i.mnemonic = "reta" + key
                i.is_return = True
            else:
                self._bad(i)
        else:
            self._bad(i)

    def _system(self, insn: int, i: Arm64Inst) -> None:
        i.is_system = True
        if (insn & 0xFFFFF01F) == 0xD503201F:    # HINT
            h = bits(insn, 5, 11)
            if h in _PAC_HINTS:
                i.mnemonic, i.is_pac = _PAC_HINTS[h], True
            elif h in _HINTS:
                i.mnemonic = _HINTS[h]
            elif h in (32, 34, 36, 38):
                i.mnemonic = "bti"
            else:
                i.mnemonic, i.imm = "hint", h
        elif (insn & 0xFFFFF01F) == 0xD503301F:  # barriers / clrex
            names = {2: "clrex", 4: "dsb", 5: "dmb", 6: "isb"}
            op2 = bits(insn, 5, 7)
            if op2 not in names:
                return self._bad(i)
            i.mnemonic, i.imm = names[op2], bits(insn, 8, 11)
        elif (insn & 0xFFF00000) == 0xD5300000:
            i.mnemonic, i.rd, i.imm = "mrs", bits(insn, 0, 4), bits(insn, 5, 19)
        elif (insn & 0xFFF00000) == 0xD5100000:
            i.mnemonic, i.rd, i.imm = "msr", bits(insn, 0, 4), bits(insn, 5, 19)
        else:
            self._unsupported(i, ".system")

    # ------------------------------------------------------ loads and stores
    def _load_store(self, insn: int, addr: int, i: Arm64Inst) -> None:
        v = bits(insn, 26, 26)
        rt, rn = bits(insn, 0, 4), bits(insn, 5, 9)
        i.rd, i.rn, i.rn_is_sp = rt, rn, True
        kind = bits(insn, 27, 29)

        if (insn & 0x3F000000) == 0x08000000 and not v:      # exclusive / ordered
            return self._exclusive(insn, i)
        if kind == 3 and bits(insn, 24, 25) == 0:            # literal
            opc = bits(insn, 30, 31)
            i.imm = sext(bits(insn, 5, 23), 19) << 2
            i.mem_mode, i.is_load = "literal", True
            tgt = (addr + i.imm) & M64
            if v:
                if opc == 3:
                    return self._bad(i)
                i.size, i.reg_class, i.mnemonic = 2 + opc, ArmRegClass.VREG, "ldr"
                i.operands = "%s, #0x%x" % (_vreg(rt, i.size), tgt)
            elif opc == 3:
                i.is_load = False
                self._unsupported(i, "prfm")
            elif opc == 2:
                i.mnemonic, i.size, i.is_signed, i.sf = "ldrsw", 2, True, 1
                i.operands = "%s, #0x%x" % (R(rt, 1), tgt)
            else:
                i.mnemonic, i.size, i.sf = "ldr", 2 + opc, opc
                i.operands = "%s, #0x%x" % (R(rt, opc), tgt)
        elif kind == 5:
            self._pair(insn, i)
        elif kind == 7:
            self._ldst_reg(insn, i)
        else:
            self._unsupported(i, ".ldst")

    def _exclusive(self, insn: int, i: Arm64Inst) -> None:
        size = bits(insn, 30, 31)
        o2, l, o1, o0 = (bits(insn, 23, 23), bits(insn, 22, 22),
                         bits(insn, 21, 21), bits(insn, 15, 15))
        rs, rt, rn = bits(insn, 16, 20), bits(insn, 0, 4), bits(insn, 5, 9)
        if o1:                                   # exclusive pair or CAS
            return self._unsupported(i, ".excl_pair_or_cas")
        if o2 == 0:
            base = ("ldaxr" if o0 else "ldxr") if l else ("stlxr" if o0 else "stxr")
        else:
            base = ("ldar" if o0 else "ldlar") if l else ("stlr" if o0 else "stllr")
        i.mnemonic = base + {0: "b", 1: "h", 2: "", 3: ""}[size]
        i.size, i.sf = size, (1 if size == 3 else 0)
        i.is_load, i.is_store = bool(l), not l
        i.rm, i.mem_mode = rs, "exclusive"
        regs = "%s, [%s]" % (R(rt, i.sf), R(rn, 1, True))
        i.operands = ("%s, %s" % (R(rs, 0), regs)) if (o2 == 0 and not l) else regs

    def _pair(self, insn: int, i: Arm64Inst) -> None:
        opc, v, l = bits(insn, 30, 31), bits(insn, 26, 26), bits(insn, 22, 22)
        mode_bits, rt2 = bits(insn, 23, 24), bits(insn, 10, 14)
        i.rt2, i.is_pair, i.is_load, i.is_store = rt2, True, bool(l), not l
        if mode_bits == 0:
            return self._unsupported(i, ".ldnp_stnp")
        i.mem_mode = {1: "post", 2: "offset", 3: "pre"}[mode_bits]
        if v:
            if opc == 3:
                return self._bad(i)
            log2 = 2 + opc
            i.reg_class, i.size = ArmRegClass.VREG, log2
            regs = "%s, %s" % (_vreg(i.rd, log2), _vreg(rt2, log2))
            i.mnemonic = "ldp" if l else "stp"
        else:
            if opc == 3 or (opc == 1 and not l):
                return self._bad(i)
            log2 = 3 if opc == 2 else 2
            i.size, i.sf, i.is_signed = log2, (1 if opc == 2 else 0), opc == 1
            wide = 1 if opc in (1, 2) else 0
            regs = "%s, %s" % (R(i.rd, wide), R(rt2, wide))
            i.mnemonic = "ldpsw" if opc == 1 else ("ldp" if l else "stp")
        i.imm = sext(bits(insn, 15, 21), 7) << log2
        base = R(i.rn, 1, True)
        if i.mem_mode == "offset":
            i.operands = "%s, [%s, #%d]" % (regs, base, i.imm)
        elif i.mem_mode == "pre":
            i.operands = "%s, [%s, #%d]!" % (regs, base, i.imm)
        else:
            i.operands = "%s, [%s], #%d" % (regs, base, i.imm)

    def _ldst_reg(self, insn: int, i: Arm64Inst) -> None:
        size, v, opc = bits(insn, 30, 31), bits(insn, 26, 26), bits(insn, 22, 23)
        rt, rn = i.rd, i.rn
        form, sub = bits(insn, 24, 25), bits(insn, 10, 11)

        if v:
            if size != 0 and opc >= 2:
                return self._bad(i)
            log2 = 4 if (size == 0 and opc >= 2) else size
            i.reg_class, i.size = ArmRegClass.VREG, log2
            i.is_load = bool(opc & 1)
            i.is_store = not i.is_load
            name = "ldr" if i.is_load else "str"
            tname = _vreg(rt, log2)
        else:
            i.size = size
            if opc == 0:
                i.is_store, name, i.sf = True, "str", (1 if size == 3 else 0)
            elif opc == 1:
                i.is_load, name, i.sf = True, "ldr", (1 if size == 3 else 0)
            else:                                # sign-extending loads / prfm
                if size == 3:
                    if opc == 2:
                        return self._unsupported(i, "prfm")
                    return self._bad(i)
                if size == 2 and opc == 3:
                    return self._bad(i)
                i.is_load, i.is_signed, i.sf = True, True, (1 if opc == 2 else 0)
                name = "ldrs" + {0: "b", 1: "h", 2: "w"}[size]
            if opc < 2 and size < 2:
                name += {0: "b", 1: "h"}[size]
            tname = R(rt, i.sf)
        base = R(rn, 1, True)

        if form == 1:                            # unsigned immediate
            i.mem_mode, i.mnemonic = "offset", name
            i.imm = bits(insn, 10, 21) << i.size
            i.operands = "%s, [%s%s]" % (tname, base, (", #%d" % i.imm) if i.imm else "")
        elif form == 0 and not bits(insn, 21, 21):
            i.imm = sext(bits(insn, 12, 20), 9)
            if sub == 0:                         # unscaled (LDUR/STUR)
                i.mem_mode = "unscaled"
                i.mnemonic = name.replace("ldr", "ldur").replace("str", "stur")
                i.operands = "%s, [%s, #%d]" % (tname, base, i.imm)
            elif sub == 1:
                i.mem_mode, i.mnemonic = "post", name
                i.operands = "%s, [%s], #%d" % (tname, base, i.imm)
            elif sub == 3:
                i.mem_mode, i.mnemonic = "pre", name
                i.operands = "%s, [%s, #%d]!" % (tname, base, i.imm)
            else:
                self._unsupported(i, ".ldtr_sttr")
        elif form == 0 and bits(insn, 21, 21) and sub == 2:      # register offset
            option, s = bits(insn, 13, 15), bits(insn, 12, 12)
            ext = {2: "uxtw", 3: "lsl", 6: "sxtw", 7: "sxtx"}.get(option)
            if ext is None:
                return self._bad(i)
            rm = bits(insn, 16, 20)
            i.rm, i.mem_mode, i.shift_type, i.mnemonic = rm, "reg", ext, name
            i.shift = i.size if s else 0
            extra = (", %s #%d" % (ext, i.shift)) if s else ("" if ext == "lsl" else ", " + ext)
            i.operands = "%s, [%s, %s%s]" % (
                tname, base, R(rm, 1 if option in (3, 7) else 0), extra)
        else:
            self._unsupported(i, ".ldst_atomic")

    # ------------------------------------------- data processing (register)
    def _dp_reg(self, insn: int, i: Arm64Inst) -> None:
        sf = bits(insn, 31, 31)
        i.sf = sf
        rd, rn, rm = bits(insn, 0, 4), bits(insn, 5, 9), bits(insn, 16, 20)
        i.rd, i.rn, i.rm = rd, rn, rm
        top = insn & 0x1F000000
        sel = insn & 0x1FE00000

        if top == 0x0A000000:                    # logical (shifted register)
            opc, shift, n = bits(insn, 29, 30), bits(insn, 22, 23), bits(insn, 21, 21)
            imm6 = bits(insn, 10, 15)
            if not sf and imm6 > 31:
                return self._bad(i)
            i.shift, i.shift_type, i.imm, i.set_flags = imm6, _STYPES[shift], imm6, opc == 3
            i.mnemonic = (("and", "orr", "eor", "ands"), ("bic", "orn", "eon", "bics"))[n][opc]
            sh = (", %s #%d" % (_STYPES[shift], imm6)) if imm6 else ""
            if opc == 1 and not n and rn == 31 and not imm6 and not shift:
                i.alias = "mov"
                i.operands = "%s, %s" % (R(rd, sf), R(rm, sf))
            elif opc == 3 and not n and rd == 31:
                i.alias = "tst"
                i.operands = "%s, %s%s" % (R(rn, sf), R(rm, sf), sh)
            else:
                i.operands = "%s, %s, %s%s" % (R(rd, sf), R(rn, sf), R(rm, sf), sh)
        elif top == 0x0B000000:                  # add/sub shifted / extended
            op, s = bits(insn, 30, 30), bits(insn, 29, 29)
            i.set_flags = bool(s)
            i.mnemonic = ("sub" if op else "add") + ("s" if s else "")
            if not bits(insn, 21, 21):           # shifted register
                shift, imm6 = bits(insn, 22, 23), bits(insn, 10, 15)
                if shift == 3 or (not sf and imm6 > 31):
                    return self._bad(i)
                i.shift, i.shift_type, i.imm = imm6, _STYPES[shift], imm6
                sh = (", %s #%d" % (_STYPES[shift], imm6)) if imm6 else ""
                if s and rd == 31:
                    i.alias = "cmp" if op else "cmn"
                    i.operands = "%s, %s%s" % (R(rn, sf), R(rm, sf), sh)
                elif op and rn == 31 and not s:
                    i.alias = "neg"
                    i.operands = "%s, %s%s" % (R(rd, sf), R(rm, sf), sh)
                else:
                    i.operands = "%s, %s, %s%s" % (R(rd, sf), R(rn, sf), R(rm, sf), sh)
            else:                                # extended register
                option, imm3 = bits(insn, 13, 15), bits(insn, 10, 12)
                if bits(insn, 22, 23) or imm3 > 4:
                    return self._bad(i)
                ext = ("uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx")[option]
                i.shift_type, i.shift = ext, imm3
                i.rn_is_sp, i.rd_is_sp = True, not s
                i.operands = "%s, %s, %s, %s #%d" % (
                    R(rd, sf, not s), R(rn, sf, True),
                    R(rm, 1 if option in (3, 7) else 0), ext, imm3)
        elif sel == 0x1A000000:                  # add/sub with carry
            if bits(insn, 10, 15):
                return self._bad(i)
            op, s = bits(insn, 30, 30), bits(insn, 29, 29)
            i.set_flags = bool(s)
            i.mnemonic = ("sbc" if op else "adc") + ("s" if s else "")
            i.operands = "%s, %s, %s" % (R(rd, sf), R(rn, sf), R(rm, sf))
        elif sel == 0x1A400000:                  # conditional compare
            if not bits(insn, 29, 29) or bits(insn, 10, 10) or bits(insn, 4, 4):
                return self._bad(i)
            op, imm_form = bits(insn, 30, 30), bits(insn, 11, 11)
            i.cond, i.imm, i.set_flags = ArmCond(bits(insn, 12, 15)), bits(insn, 0, 3), True
            i.mnemonic = "ccmp" if op else "ccmn"
            if imm_form:
                i.shift_type = "imm"
            second = ("#%d" % rm) if imm_form else R(rm, sf)
            i.operands = "%s, %s, #%d, %s" % (R(rn, sf), second, i.imm, cond_name(i.cond))
        elif sel == 0x1A800000:                  # conditional select
            op, s, o2 = bits(insn, 30, 30), bits(insn, 29, 29), bits(insn, 10, 11)
            if s or (o2 & 2):
                return self._bad(i)
            i.cond = ArmCond(bits(insn, 12, 15))
            i.mnemonic = {(0, 0): "csel", (0, 1): "csinc",
                          (1, 0): "csinv", (1, 1): "csneg"}[(op, o2)]
            ops = "%s, %s, %s, %s" % (R(rd, sf), R(rn, sf), R(rm, sf), cond_name(i.cond))
            inv = cond_name(ArmCond(int(i.cond) ^ 1))
            real = int(i.cond) < 14
            if i.mnemonic == "csinc" and rn == 31 and rm == 31 and real:
                i.alias, ops = "cset", "%s, %s" % (R(rd, sf), inv)
            elif i.mnemonic == "csinv" and rn == 31 and rm == 31 and real:
                i.alias, ops = "csetm", "%s, %s" % (R(rd, sf), inv)
            elif i.mnemonic == "csinc" and rn == rm and rn != 31 and real:
                i.alias, ops = "cinc", "%s, %s, %s" % (R(rd, sf), R(rn, sf), inv)
            i.operands = ops
        elif sel == 0x1AC00000:                  # 1-source / 2-source
            opcode = bits(insn, 10, 15)
            if bits(insn, 30, 30):               # data-processing (1 source)
                if bits(insn, 29, 29) or bits(insn, 16, 20):
                    return self._bad(i)
                names = {0: "rbit", 1: "rev16", 2: "rev32" if sf else "rev",
                         3: "rev", 4: "clz", 5: "cls"}
                if opcode not in names:
                    return self._unsupported(i, ".dp1src_pac")
                if opcode == 3 and not sf:
                    return self._bad(i)
                i.mnemonic = names[opcode]
                i.operands = "%s, %s" % (R(rd, sf), R(rn, sf))
            else:                                # data-processing (2 source)
                if bits(insn, 29, 29):
                    return self._bad(i)
                names = {2: "udiv", 3: "sdiv", 8: "lslv", 9: "lsrv", 10: "asrv", 11: "rorv"}
                if opcode not in names:
                    return self._unsupported(i, ".dp2src_other")
                i.mnemonic = names[opcode]
                if opcode >= 8:
                    i.alias = {8: "lsl", 9: "lsr", 10: "asr", 11: "ror"}[opcode]
                i.operands = "%s, %s, %s" % (R(rd, sf), R(rn, sf), R(rm, sf))
        elif top == 0x1B000000:                  # data-processing (3 source)
            if bits(insn, 29, 30):
                return self._bad(i)
            op31, o0, ra = bits(insn, 21, 23), bits(insn, 15, 15), bits(insn, 10, 14)
            i.ra = ra
            table = {(0, 0): "madd", (0, 1): "msub", (1, 0): "smaddl", (1, 1): "smsubl",
                     (2, 0): "smulh", (5, 0): "umaddl", (5, 1): "umsubl", (6, 0): "umulh"}
            if (op31, o0) not in table or (op31 != 0 and not sf):
                return self._bad(i)
            i.mnemonic = table[(op31, o0)]
            if op31 in (2, 6):
                i.operands = "%s, %s, %s" % (R(rd, 1), R(rn, 1), R(rm, 1))
            elif op31 == 0:
                if ra == 31:
                    i.alias = "mul" if o0 == 0 else "mneg"
                    i.operands = "%s, %s, %s" % (R(rd, sf), R(rn, sf), R(rm, sf))
                else:
                    i.operands = "%s, %s, %s, %s" % (R(rd, sf), R(rn, sf), R(rm, sf), R(ra, sf))
            else:
                i.operands = "%s, %s, %s, %s" % (R(rd, 1), R(rn, 0), R(rm, 0), R(ra, 1))
        else:
            self._bad(i)
