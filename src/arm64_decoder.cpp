// ARM64 decoder: C++ port of proto/arm64_decode.py (keep the two in sync).
#include <champollion/arm64_decoder.h>

namespace champollion {
namespace {

constexpr uint64_t M64 = ~0ULL;

inline uint32_t bits(uint32_t insn, int lsb, int msb) {
    return (insn >> lsb) & ((1u << (msb - lsb + 1)) - 1u);
}

inline int64_t sext(uint64_t value, int n) {
    value &= (n == 64) ? M64 : ((1ULL << n) - 1);
    return (value >> (n - 1)) ? static_cast<int64_t>(value) - (1LL << n) : static_cast<int64_t>(value);
}

const char* kCond[16] = {"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
                         "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};

// DecodeBitMasks (wmask only); returns false for reserved encodings.
bool decode_bitmask(uint32_t n, uint32_t imms, uint32_t immr, int datasize, uint64_t& out) {
    uint32_t x = (n << 6) | (~imms & 0x3F);
    if (x == 0) return false;
    int len = 31 - __builtin_clz(x);
    if (len < 1) return false;
    uint32_t esize = 1u << len;
    if (static_cast<int>(esize) > datasize) return false;
    uint32_t levels = esize - 1;
    uint32_t s = imms & levels, r = immr & levels;
    if (s == levels) return false;
    uint64_t welem = (s + 1 >= 64) ? M64 : ((1ULL << (s + 1)) - 1);
    uint64_t mask_e = (esize >= 64) ? M64 : ((1ULL << esize) - 1);
    uint64_t rot = r ? (((welem >> r) | (welem << (esize - r))) & mask_e) : (welem & mask_e);
    uint64_t res = 0;
    for (int i = 0; i < datasize; i += static_cast<int>(esize)) res |= rot << i;
    out = res;
    return true;
}

void bad(Arm64Inst& i) { i.is_unallocated = true; i.mnemonic = ".unallocated"; }
void unsupported(Arm64Inst& i, const char* n) { i.supported = false; i.mnemonic = n; }

const char* pac_hint(uint32_t h) {
    switch (h) {
        case 7: return "xpaclri";   case 8: return "pacia1716"; case 10: return "pacib1716";
        case 12: return "autia1716"; case 14: return "autib1716"; case 24: return "paciaz";
        case 25: return "paciasp";  case 26: return "pacibz";   case 27: return "pacibsp";
        case 28: return "autiaz";   case 29: return "autiasp";  case 30: return "autibz";
        case 31: return "autibsp";  default: return nullptr;
    }
}
const char* plain_hint(uint32_t h) {
    switch (h) {
        case 0: return "nop"; case 1: return "yield"; case 2: return "wfe"; case 3: return "wfi";
        case 4: return "sev"; case 5: return "sevl";  case 16: return "esb"; case 17: return "psb";
        case 18: return "tsb"; case 20: return "csdb"; default: return nullptr;
    }
}
const char* kStype[4] = {"lsl", "lsr", "asr", "ror"};

// ---------------------------------------------------------------- dp (imm)
void dp_imm(uint32_t insn, uint64_t addr, Arm64Inst& i) {
    (void)addr;
    uint32_t sf = bits(insn, 31, 31);
    i.sf = sf;
    uint32_t rd = bits(insn, 0, 4), rn = bits(insn, 5, 9);
    i.rd = rd; i.rn = rn;
    uint32_t group = bits(insn, 23, 25);

    if (group <= 1) {
        int64_t imm = sext((static_cast<uint64_t>(bits(insn, 5, 23)) << 2) | bits(insn, 29, 30), 21);
        i.sf = 1;
        if (sf) { i.mnemonic = "adrp"; i.imm = imm * 4096; }
        else    { i.mnemonic = "adr";  i.imm = imm; }
    } else if (group == 2) {
        uint32_t op = bits(insn, 30, 30), s = bits(insn, 29, 29), sh = bits(insn, 22, 22);
        int64_t imm = static_cast<int64_t>(bits(insn, 10, 21)) << (sh ? 12 : 0);
        i.imm = imm; i.shift = sh ? 12 : 0; i.set_flags = s;
        i.rn_is_sp = true; i.rd_is_sp = !s;
        i.mnemonic = std::string(op ? "sub" : "add") + (s ? "s" : "");
        if (s && rd == 31) i.alias = op ? "cmp" : "cmn";
        else if (!s && !op && imm == 0 && (rd == 31 || rn == 31)) i.alias = "mov";
    } else if (group == 4) {
        uint32_t opc = bits(insn, 29, 30), n = bits(insn, 22, 22);
        uint32_t immr = bits(insn, 16, 21), imms = bits(insn, 10, 15);
        if (!sf && n) return bad(i);
        uint64_t mask;
        if (!decode_bitmask(n, imms, immr, sf ? 64 : 32, mask)) return bad(i);
        i.imm = static_cast<int64_t>(mask);
        static const char* nm[4] = {"and", "orr", "eor", "ands"};
        i.mnemonic = nm[opc];
        i.set_flags = opc == 3; i.rd_is_sp = opc != 3;
        if (opc == 3 && rd == 31) i.alias = "tst";
        else if (opc == 1 && rn == 31) i.alias = "mov";
    } else if (group == 5) {
        uint32_t opc = bits(insn, 29, 30), hw = bits(insn, 21, 22);
        if (opc == 1 || (!sf && hw > 1)) return bad(i);
        i.imm = bits(insn, 5, 20); i.shift = hw * 16;
        i.mnemonic = opc == 0 ? "movn" : (opc == 2 ? "movz" : "movk");
    } else if (group == 6) {
        uint32_t opc = bits(insn, 29, 30), n = bits(insn, 22, 22);
        uint32_t immr = bits(insn, 16, 21), imms = bits(insn, 10, 15);
        if (opc == 3 || n != sf || (!sf && (immr > 31 || imms > 31))) return bad(i);
        uint32_t width = sf ? 64 : 32;
        static const char* nm[3] = {"sbfm", "bfm", "ubfm"};
        i.mnemonic = nm[opc];
        i.imm = (immr << 8) | imms; i.shift = immr;
        if (opc == 2 && imms != width - 1 && imms + 1 == immr) i.alias = "lsl";
        else if (opc == 2 && imms == width - 1) i.alias = "lsr";
        else if (opc == 0 && imms == width - 1) i.alias = "asr";
        else if (opc == 0 && immr == 0 && imms == 7) i.alias = "sxtb";
        else if (opc == 0 && immr == 0 && imms == 15) i.alias = "sxth";
        else if (opc == 0 && immr == 0 && imms == 31) i.alias = "sxtw";
        else if (opc == 2 && immr == 0 && imms == 7) i.alias = "uxtb";
        else if (opc == 2 && immr == 0 && imms == 15) i.alias = "uxth";
    } else {
        if (group == 3) return unsupported(i, ".dp_imm_tags");
        uint32_t op21 = bits(insn, 29, 30), n = bits(insn, 22, 22), o0 = bits(insn, 21, 21);
        uint32_t imms = bits(insn, 10, 15), rm = bits(insn, 16, 20);
        if (op21 != 0 || n != sf || o0 || (!sf && imms > 31)) return bad(i);
        i.mnemonic = "extr"; i.rm = rm; i.imm = imms;
        if (rn == rm) i.alias = "ror";
    }
}

// ----------------------------------------------------- branches / system
void branch_reg(uint32_t insn, Arm64Inst& i) {
    uint32_t opc = bits(insn, 21, 24), op2 = bits(insn, 16, 20);
    uint32_t op3 = bits(insn, 10, 15), rn = bits(insn, 5, 9), op4 = bits(insn, 0, 4);
    i.rn = rn;
    if (op2 != 0x1F) return bad(i);
    if (op3 == 0 && op4 == 0 && opc <= 2) {
        static const char* nm[3] = {"br", "blr", "ret"};
        i.mnemonic = nm[opc];
        i.is_branch = true;
        i.is_indirect = opc != 2; i.is_call = opc == 1; i.is_return = opc == 2;
    } else if (op3 == 0 && op4 == 0 && (opc == 4 || opc == 5) && rn == 31) {
        i.mnemonic = opc == 4 ? "eret" : "drps";
        i.is_branch = i.is_system = true;
        i.is_return = opc == 4;
    } else if (op3 == 2 || op3 == 3) {
        i.is_pac = i.is_branch = true;
        std::string key = op3 == 2 ? "a" : "b";
        if ((opc == 0 || opc == 1) && op4 == 31) {
            i.mnemonic = std::string(opc ? "blr" : "br") + "a" + key + "z";
            i.is_indirect = true; i.is_call = opc == 1;
        } else if (opc == 8 || opc == 9) {
            i.mnemonic = std::string(opc == 9 ? "blr" : "br") + "a" + key;
            i.is_indirect = true; i.is_call = opc == 9;
        } else if (opc == 2 && rn == 31 && op4 == 31) {
            i.mnemonic = "reta" + key;
            i.is_return = true;
        } else {
            bad(i);
        }
    } else {
        bad(i);
    }
}

void system_insn(uint32_t insn, Arm64Inst& i) {
    i.is_system = true;
    if ((insn & 0xFFFFF01F) == 0xD503201F) {
        uint32_t h = bits(insn, 5, 11);
        if (const char* p = pac_hint(h)) { i.mnemonic = p; i.is_pac = true; }
        else if (const char* q = plain_hint(h)) i.mnemonic = q;
        else if (h == 32 || h == 34 || h == 36 || h == 38) i.mnemonic = "bti";
        else { i.mnemonic = "hint"; i.imm = h; }
    } else if ((insn & 0xFFFFF01F) == 0xD503301F) {
        uint32_t op2 = bits(insn, 5, 7);
        if (op2 == 2) i.mnemonic = "clrex";
        else if (op2 == 4) i.mnemonic = "dsb";
        else if (op2 == 5) i.mnemonic = "dmb";
        else if (op2 == 6) i.mnemonic = "isb";
        else return bad(i);
        i.imm = bits(insn, 8, 11);
    } else if ((insn & 0xFFF00000) == 0xD5300000) {
        i.mnemonic = "mrs"; i.rd = bits(insn, 0, 4); i.imm = bits(insn, 5, 19);
    } else if ((insn & 0xFFF00000) == 0xD5100000) {
        i.mnemonic = "msr"; i.rd = bits(insn, 0, 4); i.imm = bits(insn, 5, 19);
    } else {
        unsupported(i, ".system");
    }
}

void branch_sys(uint32_t insn, uint64_t addr, Arm64Inst& i) {
    (void)addr;
    if ((insn & 0x7C000000) == 0x14000000) {
        bool link = insn >> 31;
        i.imm = sext(bits(insn, 0, 25), 26) * 4;
        i.is_branch = true; i.is_call = link;
        i.mnemonic = link ? "bl" : "b";
    } else if ((insn & 0x7E000000) == 0x34000000) {
        i.sf = bits(insn, 31, 31); i.rd = bits(insn, 0, 4);
        i.imm = sext(bits(insn, 5, 23), 19) * 4;
        i.is_branch = i.is_cond_branch = true;
        i.mnemonic = bits(insn, 24, 24) ? "cbnz" : "cbz";
    } else if ((insn & 0x7E000000) == 0x36000000) {
        i.rd = bits(insn, 0, 4);
        uint32_t bit = (bits(insn, 31, 31) << 5) | bits(insn, 19, 23);
        i.sf = bit >= 32; i.shift = bit;
        i.imm = sext(bits(insn, 5, 18), 14) * 4;
        i.is_branch = i.is_cond_branch = true;
        i.mnemonic = bits(insn, 24, 24) ? "tbnz" : "tbz";
    } else if ((insn & 0xFF000010) == 0x54000000) {
        i.cond = static_cast<ArmCond>(bits(insn, 0, 3));
        i.imm = sext(bits(insn, 5, 23), 19) * 4;
        i.is_branch = i.is_cond_branch = true;
        i.mnemonic = std::string("b.") + kCond[bits(insn, 0, 3)];
    } else if ((insn & 0xFE000000) == 0xD6000000) {
        branch_reg(insn, i);
    } else if ((insn & 0xFF000000) == 0xD4000000) {
        uint32_t opc = bits(insn, 21, 23), ll = bits(insn, 0, 1);
        const char* name = nullptr;
        if (opc == 0 && ll == 1) name = "svc";
        else if (opc == 0 && ll == 2) name = "hvc";
        else if (opc == 0 && ll == 3) name = "smc";
        else if (opc == 1 && ll == 0) name = "brk";
        else if (opc == 2 && ll == 0) name = "hlt";
        if (bits(insn, 2, 4) || !name) return bad(i);
        i.mnemonic = name; i.imm = bits(insn, 5, 20); i.is_system = true;
    } else if ((insn & 0xFFC00000) == 0xD5000000) {
        system_insn(insn, i);
    } else {
        bad(i);
    }
}

// ------------------------------------------------------- loads and stores
void exclusive(uint32_t insn, Arm64Inst& i) {
    uint32_t size = bits(insn, 30, 31);
    uint32_t o2 = bits(insn, 23, 23), l = bits(insn, 22, 22), o1 = bits(insn, 21, 21), o0 = bits(insn, 15, 15);
    uint32_t rs = bits(insn, 16, 20);
    if (o1) return unsupported(i, ".excl_pair_or_cas");
    std::string base;
    if (o2 == 0) base = l ? (o0 ? "ldaxr" : "ldxr") : (o0 ? "stlxr" : "stxr");
    else         base = l ? (o0 ? "ldar" : "ldlar") : (o0 ? "stlr" : "stllr");
    static const char* suf[4] = {"b", "h", "", ""};
    i.mnemonic = base + suf[size];
    i.size = size; i.sf = size == 3;
    i.is_load = l; i.is_store = !l;
    i.rm = rs; i.mem_mode = "exclusive";
}

void pair(uint32_t insn, Arm64Inst& i) {
    uint32_t opc = bits(insn, 30, 31), v = bits(insn, 26, 26), l = bits(insn, 22, 22);
    uint32_t mode_bits = bits(insn, 23, 24);
    i.rt2 = bits(insn, 10, 14); i.is_pair = true; i.is_load = l; i.is_store = !l;
    if (mode_bits == 0) return unsupported(i, ".ldnp_stnp");
    i.mem_mode = mode_bits == 1 ? "post" : (mode_bits == 2 ? "offset" : "pre");
    uint32_t log2;
    if (v) {
        if (opc == 3) return bad(i);
        log2 = 2 + opc;
        i.reg_class = ArmRegClass::VREG; i.size = log2;
        i.mnemonic = l ? "ldp" : "stp";
    } else {
        if (opc == 3 || (opc == 1 && !l)) return bad(i);
        log2 = opc == 2 ? 3 : 2;
        i.size = log2; i.sf = opc == 2; i.is_signed = opc == 1;
        i.mnemonic = opc == 1 ? "ldpsw" : (l ? "ldp" : "stp");
    }
    i.imm = sext(bits(insn, 15, 21), 7) * (1LL << log2);
}

void ldst_reg(uint32_t insn, Arm64Inst& i) {
    uint32_t size = bits(insn, 30, 31), v = bits(insn, 26, 26), opc = bits(insn, 22, 23);
    uint32_t form = bits(insn, 24, 25), sub = bits(insn, 10, 11);
    std::string name;
    if (v) {
        if (size != 0 && opc >= 2) return bad(i);
        uint32_t log2 = (size == 0 && opc >= 2) ? 4 : size;
        i.reg_class = ArmRegClass::VREG; i.size = log2;
        i.is_load = opc & 1; i.is_store = !i.is_load;
        name = i.is_load ? "ldr" : "str";
    } else {
        i.size = size;
        if (opc == 0)      { i.is_store = true; name = "str"; i.sf = size == 3; }
        else if (opc == 1) { i.is_load = true;  name = "ldr"; i.sf = size == 3; }
        else {
            if (size == 3) { if (opc == 2) return unsupported(i, "prfm"); return bad(i); }
            if (size == 2 && opc == 3) return bad(i);
            i.is_load = true; i.is_signed = true; i.sf = opc == 2;
            name = std::string("ldrs") + (size == 0 ? "b" : (size == 1 ? "h" : "w"));
        }
        if (opc < 2 && size < 2) name += (size == 0 ? "b" : "h");
    }

    if (form == 1) {
        i.mem_mode = "offset"; i.mnemonic = name;
        i.imm = static_cast<int64_t>(bits(insn, 10, 21)) << i.size;
    } else if (form == 0 && !bits(insn, 21, 21)) {
        i.imm = sext(bits(insn, 12, 20), 9);
        if (sub == 0) {
            i.mem_mode = "unscaled";
            std::string m = name;
            size_t p;
            if ((p = m.find("ldr")) != std::string::npos) m.replace(p, 3, "ldur");
            else if ((p = m.find("str")) != std::string::npos) m.replace(p, 3, "stur");
            i.mnemonic = m;
        } else if (sub == 1) { i.mem_mode = "post"; i.mnemonic = name; }
        else if (sub == 3)   { i.mem_mode = "pre";  i.mnemonic = name; }
        else unsupported(i, ".ldtr_sttr");
    } else if (form == 0 && bits(insn, 21, 21) && sub == 2) {
        uint32_t option = bits(insn, 13, 15), s = bits(insn, 12, 12);
        const char* ext = option == 2 ? "uxtw" : option == 3 ? "lsl" : option == 6 ? "sxtw" : option == 7 ? "sxtx" : nullptr;
        if (!ext) return bad(i);
        i.rm = bits(insn, 16, 20); i.mem_mode = "reg"; i.shift_type = ext; i.mnemonic = name;
        i.shift = s ? i.size : 0;
    } else {
        unsupported(i, ".ldst_atomic");
    }
}

void load_store(uint32_t insn, uint64_t addr, Arm64Inst& i) {
    (void)addr;
    uint32_t v = bits(insn, 26, 26);
    i.rd = bits(insn, 0, 4); i.rn = bits(insn, 5, 9); i.rn_is_sp = true;
    uint32_t kind = bits(insn, 27, 29);
    if ((insn & 0x3F000000) == 0x08000000 && !v) return exclusive(insn, i);
    if (kind == 3 && bits(insn, 24, 25) == 0) {
        uint32_t opc = bits(insn, 30, 31);
        i.imm = sext(bits(insn, 5, 23), 19) * 4;
        i.mem_mode = "literal"; i.is_load = true;
        if (v) {
            if (opc == 3) return bad(i);
            i.size = 2 + opc; i.reg_class = ArmRegClass::VREG; i.mnemonic = "ldr";
        } else if (opc == 3) {
            i.is_load = false; unsupported(i, "prfm");
        } else if (opc == 2) {
            i.mnemonic = "ldrsw"; i.size = 2; i.is_signed = true; i.sf = 1;
        } else {
            i.mnemonic = "ldr"; i.size = 2 + opc; i.sf = opc;
        }
    } else if (kind == 5) pair(insn, i);
    else if (kind == 7) ldst_reg(insn, i);
    else unsupported(i, ".ldst");
}

// --------------------------------------------------------- dp (register)
void dp_reg(uint32_t insn, Arm64Inst& i) {
    uint32_t sf = bits(insn, 31, 31);
    i.sf = sf;
    uint32_t rd = bits(insn, 0, 4), rn = bits(insn, 5, 9), rm = bits(insn, 16, 20);
    i.rd = rd; i.rn = rn; i.rm = rm;
    uint32_t top = insn & 0x1F000000, sel = insn & 0x1FE00000;

    if (top == 0x0A000000) {
        uint32_t opc = bits(insn, 29, 30), shift = bits(insn, 22, 23), n = bits(insn, 21, 21);
        uint32_t imm6 = bits(insn, 10, 15);
        if (!sf && imm6 > 31) return bad(i);
        i.shift = imm6; i.shift_type = kStype[shift]; i.imm = imm6; i.set_flags = opc == 3;
        static const char* t0[4] = {"and", "orr", "eor", "ands"};
        static const char* t1[4] = {"bic", "orn", "eon", "bics"};
        i.mnemonic = n ? t1[opc] : t0[opc];
        if (opc == 1 && !n && rn == 31 && !imm6 && !shift) i.alias = "mov";
        else if (opc == 3 && !n && rd == 31) i.alias = "tst";
    } else if (top == 0x0B000000) {
        uint32_t op = bits(insn, 30, 30), s = bits(insn, 29, 29);
        i.set_flags = s;
        i.mnemonic = std::string(op ? "sub" : "add") + (s ? "s" : "");
        if (!bits(insn, 21, 21)) {
            uint32_t shift = bits(insn, 22, 23), imm6 = bits(insn, 10, 15);
            if (shift == 3 || (!sf && imm6 > 31)) return bad(i);
            i.shift = imm6; i.shift_type = kStype[shift]; i.imm = imm6;
            if (s && rd == 31) i.alias = op ? "cmp" : "cmn";
            else if (op && rn == 31 && !s) i.alias = "neg";
        } else {
            uint32_t option = bits(insn, 13, 15), imm3 = bits(insn, 10, 12);
            if (bits(insn, 22, 23) || imm3 > 4) return bad(i);
            static const char* ex[8] = {"uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};
            i.shift_type = ex[option]; i.shift = imm3;
            i.rn_is_sp = true; i.rd_is_sp = !s;
        }
    } else if (sel == 0x1A000000) {
        if (bits(insn, 10, 15)) return bad(i);
        uint32_t op = bits(insn, 30, 30), s = bits(insn, 29, 29);
        i.set_flags = s;
        i.mnemonic = std::string(op ? "sbc" : "adc") + (s ? "s" : "");
    } else if (sel == 0x1A400000) {
        if (!bits(insn, 29, 29) || bits(insn, 10, 10) || bits(insn, 4, 4)) return bad(i);
        uint32_t op = bits(insn, 30, 30), imm_form = bits(insn, 11, 11);
        i.cond = static_cast<ArmCond>(bits(insn, 12, 15)); i.imm = bits(insn, 0, 3); i.set_flags = true;
        i.mnemonic = op ? "ccmp" : "ccmn";
        if (imm_form) i.shift_type = "imm";
    } else if (sel == 0x1A800000) {
        uint32_t op = bits(insn, 30, 30), s = bits(insn, 29, 29), o2 = bits(insn, 10, 11);
        if (s || (o2 & 2)) return bad(i);
        i.cond = static_cast<ArmCond>(bits(insn, 12, 15));
        i.mnemonic = op ? (o2 ? "csneg" : "csinv") : (o2 ? "csinc" : "csel");
        bool real = bits(insn, 12, 15) < 14;
        if (i.mnemonic == "csinc" && rn == 31 && rm == 31 && real) i.alias = "cset";
        else if (i.mnemonic == "csinv" && rn == 31 && rm == 31 && real) i.alias = "csetm";
        else if (i.mnemonic == "csinc" && rn == rm && rn != 31 && real) i.alias = "cinc";
    } else if (sel == 0x1AC00000) {
        uint32_t opcode = bits(insn, 10, 15);
        if (bits(insn, 30, 30)) {
            if (bits(insn, 29, 29) || bits(insn, 16, 20)) return bad(i);
            const char* nm = nullptr;
            switch (opcode) {
                case 0: nm = "rbit"; break;  case 1: nm = "rev16"; break;
                case 2: nm = sf ? "rev32" : "rev"; break;
                case 3: nm = "rev"; break;   case 4: nm = "clz"; break;  case 5: nm = "cls"; break;
            }
            if (!nm) return unsupported(i, ".dp1src_pac");
            if (opcode == 3 && !sf) return bad(i);
            i.mnemonic = nm;
        } else {
            if (bits(insn, 29, 29)) return bad(i);
            const char* nm = nullptr;
            switch (opcode) {
                case 2: nm = "udiv"; break; case 3: nm = "sdiv"; break; case 8: nm = "lslv"; break;
                case 9: nm = "lsrv"; break; case 10: nm = "asrv"; break; case 11: nm = "rorv"; break;
            }
            if (!nm) return unsupported(i, ".dp2src_other");
            i.mnemonic = nm;
            if (opcode >= 8) {
                static const char* al[4] = {"lsl", "lsr", "asr", "ror"};
                i.alias = al[opcode - 8];
            }
        }
    } else if (top == 0x1B000000) {
        if (bits(insn, 29, 30)) return bad(i);
        uint32_t op31 = bits(insn, 21, 23), o0 = bits(insn, 15, 15), ra = bits(insn, 10, 14);
        i.ra = ra;
        const char* nm = nullptr;
        if (op31 == 0) nm = o0 ? "msub" : "madd";
        else if (op31 == 1) nm = o0 ? "smsubl" : "smaddl";
        else if (op31 == 2 && !o0) nm = "smulh";
        else if (op31 == 5) nm = o0 ? "umsubl" : "umaddl";
        else if (op31 == 6 && !o0) nm = "umulh";
        if (!nm || (op31 != 0 && !sf)) return bad(i);
        i.mnemonic = nm;
        if (op31 == 0 && ra == 31) i.alias = o0 ? "mneg" : "mul";
    } else {
        bad(i);
    }
}

}  // namespace

DecodeResult Arm64Decoder::decode(uint64_t addr, const uint8_t* code) {
    DecodeResult res;
    Arm64Inst& i = res.inst;
    uint32_t insn = static_cast<uint32_t>(code[0]) | (static_cast<uint32_t>(code[1]) << 8) |
                    (static_cast<uint32_t>(code[2]) << 16) | (static_cast<uint32_t>(code[3]) << 24);
    i.opcode = insn;
    i.address = addr;
    uint32_t op0 = (insn >> 25) & 0xF;
    if (insn == 0) { i.is_unallocated = true; i.mnemonic = "udf"; }
    else if ((op0 >> 1) == 0x4) dp_imm(insn, addr, i);
    else if ((op0 >> 1) == 0x5) branch_sys(insn, addr, i);
    else if ((op0 & 0x5) == 0x4) load_store(insn, addr, i);
    else if ((op0 & 0x7) == 0x5) dp_reg(insn, i);
    else if ((op0 & 0x7) == 0x7) { i.supported = false; i.mnemonic = ".simd_fp"; i.reg_class = ArmRegClass::VREG; }
    else { i.is_unallocated = true; i.mnemonic = ".reserved"; }
    if (i.is_unallocated) res.error = std::make_error_code(std::errc::illegal_byte_sequence);
    return res;
}

std::vector<Arm64Inst> Arm64Decoder::decode_block(uint64_t start_addr, const uint8_t* code,
                                                  uint64_t limit) {
    std::vector<Arm64Inst> out;
    uint64_t cur = start_addr, off = 0;
    while (off + 4 <= limit) {
        DecodeResult r = decode(cur, code + off);
        if (r.error) break;
        out.push_back(r.inst);
        cur += 4; off += 4;
        if (r.inst.is_branch) break;
    }
    return out;
}

}  // namespace champollion
