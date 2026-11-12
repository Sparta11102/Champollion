#include <champollion/x64_backend.h>
#include <champollion/arm64_decoder.h>

#include <cstring>
#include <map>
#include <set>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#endif
#if defined(__APPLE__)
#include <pthread.h>
#endif

namespace champollion {

namespace {
X64Backend* g_backend = nullptr;
constexpr uint64_t kDefaultArena = 4ull << 20;

inline std::error_code unsupported() {
    return std::make_error_code(std::errc::function_not_supported);
}

#if defined(__x86_64__) || defined(_M_X64)

// ---- minimal x86-64 emitter. The context pointer lives in r12; r10 holds addresses,
// ---- r11 and rax hold values. Memory ops use only mov/lea/movzx/movsx (flags untouched).
struct Asm {
    std::vector<uint8_t> b;
    void u8(uint8_t v) { b.push_back(v); }
    void u32(uint32_t v) { for (int k = 0; k < 4; ++k) b.push_back(uint8_t(v >> (8 * k))); }
    void u64(uint64_t v) { for (int k = 0; k < 8; ++k) b.push_back(uint8_t(v >> (8 * k))); }
    static uint8_t rex(bool w, int reg, int index, int base) {
        return uint8_t(0x40 | (w ? 8 : 0) | (reg >= 8 ? 4 : 0) | (index >= 8 ? 2 : 0) | (base >= 8 ? 1 : 0));
    }

    void prologue() { u8(0x41); u8(0x54); u8(0x49); u8(0x89); u8(0xFC); }   // push r12; mov r12, rdi
    void epilogue() {                                                         // mov rax,[r12]; pop r12; ret
        u8(0x49); u8(0x8B); u8(0x04); u8(0x24); u8(0x41); u8(0x5C); u8(0xC3);
    }
    void ret() { u8(0xC3); }
    void pushfq() { u8(0x9C); }
    void popfq() { u8(0x9D); }
    void cmc() { u8(0xF5); }
    void ud2() { u8(0x0F); u8(0x0B); }

    // [r12 + 8*idx] <-> register (idx = guest register slot; slot 31 is SP)
    void load(int reg, uint32_t idx, bool w64) {
        u8(rex(w64, reg, 0, 12)); u8(0x8B); u8(uint8_t(0x84 | ((reg & 7) << 3))); u8(0x24); u32(idx * 8);
    }
    void load_sx32(int reg, uint32_t idx) {                                   // movslq
        u8(rex(true, reg, 0, 12)); u8(0x63); u8(uint8_t(0x84 | ((reg & 7) << 3))); u8(0x24); u32(idx * 8);
    }
    void store(uint32_t idx, int reg) {
        u8(rex(true, reg, 0, 12)); u8(0x89); u8(uint8_t(0x84 | ((reg & 7) << 3))); u8(0x24); u32(idx * 8);
    }
    void zero(int reg) { if (reg >= 8) u8(0x41); u8(uint8_t(0xB8 + (reg & 7))); u32(0); }   // mov reg_d, 0
    void movabs(int reg, uint64_t v) { u8(rex(true, 0, 0, reg)); u8(uint8_t(0xB8 + (reg & 7))); u64(v); }

    // op r10, r11   (01 add, 09 or, 21 and, 29 sub, 31 xor)
    void alu_rr(uint8_t op, bool w64) { u8(w64 ? 0x4D : 0x45); u8(op); u8(0xDA); }
    // op r10, imm32 (digit: 0 add, 5 sub)
    void alu_ri(uint8_t digit, uint32_t imm, bool w64) {
        u8(w64 ? 0x49 : 0x41); u8(0x81); u8(uint8_t(0xC2 | (digit << 3))); u32(imm);
    }
    void cmp_r10_r11() { u8(0x4D); u8(0x39); u8(0xDA); }
    void test_r10(bool w64) { u8(w64 ? 0x4D : 0x45); u8(0x85); u8(0xD2); }
    void bt_r10(uint8_t bit) { u8(0x49); u8(0x0F); u8(0xBA); u8(0xE2); u8(bit); }

    // [r10 + disp32] operands
    void mem(bool opsize16, bool w, int val, std::initializer_list<uint8_t> opcode, int32_t disp) {
        if (opsize16) u8(0x66);
        u8(rex(w, val, 0, 10));
        for (uint8_t o : opcode) u8(o);
        u8(uint8_t(0x80 | ((val & 7) << 3) | 2));
        u32(uint32_t(disp));
    }
    void lea_r10_disp(int32_t disp) { u8(0x4D); u8(0x8D); u8(0x92); u32(uint32_t(disp)); }
    void lea_r10_index(int scale_log2) { u8(0x4F); u8(0x8D); u8(0x14); u8(uint8_t((scale_log2 << 6) | 0x1A)); }

    void jcc_raw(uint8_t cc, int32_t rel) { u8(0x0F); u8(uint8_t(0x80 | cc)); u32(uint32_t(rel)); }
    void jmp_raw(int32_t rel) { u8(0xE9); u32(uint32_t(rel)); }
    // Emit control flow to a guest address; returns the position of the rel32 for fixup.
    size_t jcc_fix(uint8_t cc) { u8(0x0F); u8(uint8_t(0x80 | cc)); size_t p = b.size(); u32(0); return p; }
    size_t jmp_fix() { u8(0xE9); size_t p = b.size(); u32(0); return p; }
    size_t call_fix() { u8(0xE8); size_t p = b.size(); u32(0); return p; }
    void patch(size_t pos, size_t target) {
        int32_t rel = int32_t(int64_t(target) - int64_t(pos + 4));
        for (int k = 0; k < 4; ++k) b[pos + k] = uint8_t(uint32_t(rel) >> (8 * k));
    }
};

// x86 condition codes
enum : uint8_t { CC_O = 0, CC_NO = 1, CC_B = 2, CC_AE = 3, CC_E = 4, CC_NE = 5, CC_BE = 6, CC_A = 7,
                 CC_S = 8, CC_NS = 9, CC_L = 12, CC_GE = 13, CC_LE = 14, CC_G = 15 };

bool is_hint_nop(const Arm64Inst& i) { return i.mnemonic == "nop"; }

// Mirrors _memory_supported in proto/aot_translator.py.
bool memory_supported(const Arm64Inst& i) {
    if (!(i.is_load || i.is_store) || !i.supported || i.is_unallocated) return false;
    if (i.reg_class != ArmRegClass::GPR) return false;
    const std::string& m = i.mem_mode;
    if (m != "offset" && m != "unscaled" && m != "pre" && m != "post" && m != "reg") return false;
    bool writeback = (m == "pre" || m == "post");
    if (writeback && i.rn != 31 && (i.rd == i.rn || (i.is_pair && i.rt2 == i.rn))) return false;
    if (i.is_pair && i.is_load && i.rd == i.rt2 && i.rd != 31) return false;
    return true;
}

// Mirrors _emit_memory in proto/aot_translator.py.
void lower_memory(Asm& a, const Arm64Inst& i) {
    const uint32_t rn = i.rn, rd = i.rd, rt2 = i.rt2, size = i.size;
    const bool sf = i.sf != 0;
    a.load(10, rn, true);                                   // base register; slot 31 holds SP
    int32_t disp = static_cast<int32_t>(i.imm);
    if (i.mem_mode == "reg") {
        if (i.rm == 31) a.zero(11);
        else if (i.shift_type == "uxtw") a.load(11, i.rm, false);
        else if (i.shift_type == "sxtw") a.load_sx32(11, i.rm);
        else a.load(11, i.rm, true);
        a.lea_r10_index(static_cast<int>(i.shift));
        disp = 0;
    } else if (i.mem_mode == "pre") {
        a.lea_r10_disp(disp);
        a.store(rn, 10);
        disp = 0;
    } else if (i.mem_mode == "post") {
        disp = 0;
    }
    auto value = [&](uint32_t reg, int scratch) { if (reg == 31) a.zero(scratch); else a.load(scratch, reg, true); };

    if (i.is_pair) {
        const int32_t step = 1 << size;
        if (i.is_store) {
            value(rd, 11); value(rt2, 0);
            if (size == 3) { a.mem(false, true, 11, {0x89}, disp); a.mem(false, true, 0, {0x89}, disp + 8); }
            else           { a.mem(false, false, 11, {0x89}, disp); a.mem(false, false, 0, {0x89}, disp + 4); }
        } else {
            if (size == 3)         { a.mem(false, true, 11, {0x8B}, disp); a.mem(false, true, 0, {0x8B}, disp + 8); }
            else if (i.is_signed)  { a.mem(false, true, 11, {0x63}, disp); a.mem(false, true, 0, {0x63}, disp + step); }
            else                   { a.mem(false, false, 11, {0x8B}, disp); a.mem(false, false, 0, {0x8B}, disp + 4); }
            if (rd != 31) a.store(rd, 11);
            if (rt2 != 31) a.store(rt2, 0);
        }
    } else if (i.is_store) {
        value(rd, 11);
        switch (size) {
            case 3: a.mem(false, true, 11, {0x89}, disp); break;
            case 2: a.mem(false, false, 11, {0x89}, disp); break;
            case 1: a.mem(true, false, 11, {0x89}, disp); break;
            default: a.mem(false, false, 11, {0x88}, disp); break;
        }
    } else {
        if (!i.is_signed) {
            switch (size) {
                case 3: a.mem(false, true, 11, {0x8B}, disp); break;
                case 2: a.mem(false, false, 11, {0x8B}, disp); break;
                case 1: a.mem(false, false, 11, {0x0F, 0xB7}, disp); break;
                default: a.mem(false, false, 11, {0x0F, 0xB6}, disp); break;
            }
        } else if (size == 2) {
            a.mem(false, true, 11, {0x63}, disp);
        } else if (size == 1) {
            a.mem(false, sf, 11, {0x0F, 0xBF}, disp);
        } else {
            a.mem(false, sf, 11, {0x0F, 0xBE}, disp);
        }
        if (rd != 31) a.store(rd, 11);
    }

    if (i.mem_mode == "post") {
        a.lea_r10_disp(static_cast<int32_t>(i.imm));
        a.store(rn, 10);
    }
}

// Lower one non-control instruction; false if outside the supported subset.
bool lower_data(Asm& a, const Arm64Inst& i) {
    const bool w64 = i.sf != 0;
    const std::string& m = i.mnemonic;
    if (is_hint_nop(i)) return true;
    if (!i.supported || i.is_unallocated) return false;

    if (memory_supported(i)) {
        lower_memory(a, i);
        return true;
    }

    if (m == "movz" || m == "movn" || m == "movk") {
        const uint64_t mask = w64 ? ~0ull : 0xFFFFFFFFull;
        const uint64_t shifted = (uint64_t(i.imm) << i.shift) & mask;
        if (m == "movz") {
            a.movabs(10, shifted);
        } else if (m == "movn") {
            a.movabs(10, mask ^ shifted);
        } else {
            a.pushfq();
            if (i.rd == 31) a.zero(10); else a.load(10, i.rd, w64);
            a.movabs(11, mask ^ (0xFFFFull << i.shift));
            a.alu_rr(0x21, true);
            a.movabs(11, shifted);
            a.alu_rr(0x09, true);
            a.popfq();
        }
        if (i.rd != 31) a.store(i.rd, 10);
        return true;
    }

    const bool is_arith = (m == "add" || m == "sub" || m == "adds" || m == "subs");
    const bool is_logic = (m == "and" || m == "orr" || m == "eor" || m == "ands");

    if (is_arith && i.shift_type.empty()) {                      // add/sub immediate
        const bool sub = m[0] == 's', flags = i.set_flags;
        if (!flags) a.pushfq();
        a.load(10, i.rn, w64);                                   // Rn == 31 is SP (slot 31)
        a.alu_ri(sub ? 5 : 0, uint32_t(i.imm), w64);
        if (flags && sub) a.cmc();
        if (i.rd != 31 || !flags) a.store(i.rd, 10);
        if (!flags) a.popfq();
        return true;
    }
    if ((is_arith || is_logic) && i.shift_type == "lsl" && i.shift == 0) {   // shifted register
        const bool flags = i.set_flags;
        if (!flags) a.pushfq();
        if (i.rn == 31) a.zero(10); else a.load(10, i.rn, w64);
        if (i.rm == 31) a.zero(11); else a.load(11, i.rm, w64);
        uint8_t op;
        if (m[0] == 'a' && m[1] == 'd' && m[2] == 'd') op = 0x01;       // add / adds
        else if (m[0] == 's') op = 0x29;                                 // sub / subs
        else if (m[0] == 'a') op = 0x21;                                 // and / ands
        else if (m[0] == 'o') op = 0x09;                                 // orr
        else op = 0x31;                                                  // eor
        a.alu_rr(op, w64);
        if (flags && m == "subs") a.cmc();
        if (i.rd != 31) a.store(i.rd, 10);
        if (!flags) a.popfq();
        return true;
    }
    return false;
}

#endif  // x86_64
}  // namespace

X64Backend& global_backend() {
    if (!g_backend) g_backend = new X64Backend();
    return *g_backend;
}

X64Backend::X64Backend() = default;
X64Backend::~X64Backend() { shutdown(); }

std::error_code X64Backend::allocate_exec_memory(uint64_t size) {
    if (arena_.base) return std::make_error_code(std::errc::invalid_argument);
#if defined(__unix__) || defined(__APPLE__)
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#if defined(__APPLE__)
    flags |= MAP_JIT;   // required for executable memory under the hardened runtime
#endif
    void* addr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, flags, -1, 0);
    if (addr == MAP_FAILED) return std::make_error_code(std::errc::not_enough_memory);
    arena_.base = static_cast<uint8_t*>(addr);
    arena_.capacity = size;
    arena_.used = 0;
    return {};
#else
    (void)size;
    return unsupported();
#endif
}

bool X64Backend::commit(const std::vector<uint8_t>& bytes, uint64_t& offset) {
    if (arena_.used + bytes.size() > arena_.capacity) return false;
#if defined(__APPLE__) && defined(__aarch64__)
    pthread_jit_write_protect_np(0);
#endif
    std::memcpy(arena_.base + arena_.used, bytes.data(), bytes.size());
#if defined(__APPLE__) && defined(__aarch64__)
    pthread_jit_write_protect_np(1);
#endif
    offset = arena_.used;
    arena_.used += bytes.size();
    return true;
}

std::error_code X64Backend::compile(const IrFunction&, X64CodeBlock&) {
    return unsupported();
}

std::error_code X64Backend::compile_guest(const uint8_t* code, uint64_t region_base, uint64_t size,
                                          uint64_t guest_addr, X64CodeBlock& out,
                                          const std::vector<uint64_t>& extra_entries) {
#if !(defined(__x86_64__) || defined(_M_X64))
    (void)code; (void)region_base; (void)size; (void)guest_addr; (void)out; (void)extra_entries;
    return unsupported();   // this backend emits x86-64, so it can only run on an x86-64 host
#else
    if (guest_addr % 4 || guest_addr < region_base || guest_addr >= region_base + size)
        return std::make_error_code(std::errc::invalid_argument);
    if (!arena_.base) {
        if (auto ec = allocate_exec_memory(kDefaultArena)) return ec;
    }

    // Pass 1: discover reachable instructions and function entry points.
    Arm64Decoder dec;
    std::map<uint64_t, Arm64Inst> insts;
    std::set<uint64_t> entries{guest_addr};
    for (uint64_t e : extra_entries) entries.insert(e);
    std::vector<uint64_t> pending(entries.begin(), entries.end());
    bool has_ret = false;
    while (!pending.empty()) {
        uint64_t pc = pending.back();
        pending.pop_back();
        while (!insts.count(pc)) {
            if (pc % 4 || pc < region_base || pc + 4 > region_base + size) return unsupported();
            if (insts.size() >= 4096) return std::make_error_code(std::errc::file_too_large);
            DecodeResult r = dec.decode(pc, code + (pc - region_base));
            const Arm64Inst& i = r.inst;
            if (r.error) return unsupported();
            if (i.is_branch) {
                if (i.is_pac || i.is_system) return unsupported();
                if (i.is_return) {
                    if (i.rn != 30) return unsupported();
                    insts[pc] = i; has_ret = true; break;
                }
                if (i.is_indirect) {                              // blr / br: targets are known entries
                    insts[pc] = i;
                    if (i.is_call) { pc += 4; continue; }
                    break;
                }
                insts[pc] = i;
                const uint64_t target = pc + i.imm;
                if (i.is_call) { entries.insert(target); pending.push_back(target); pc += 4; continue; }
                pending.push_back(target);
                if (!i.is_cond_branch) break;                     // unconditional b
                pc += 4;
                continue;
            }
            Asm probe;                                            // support check = try to lower it
            if (!lower_data(probe, i)) return unsupported();
            insts[pc] = i;
            pc += 4;
        }
    }
    if (!has_ret) return unsupported();

    // Pass 2: emit. Layout: entry stub, then every instruction in address order.
    Asm a;
    std::map<uint64_t, size_t> label;
    struct Fix { size_t pos; uint64_t target; };
    std::vector<Fix> fixes;
    a.prologue();
    fixes.push_back({a.call_fix(), guest_addr});
    a.epilogue();
    for (auto& kv : insts) {
        const uint64_t pc = kv.first;
        const Arm64Inst& i = kv.second;
        label[pc] = a.b.size();
        if (!i.is_branch) {
            lower_data(a, i);
            continue;
        }
        const std::string& m = i.mnemonic;
        const uint64_t target = pc + i.imm;
        if (i.is_return) {
            a.ret();
        } else if (i.is_indirect) {                               // blr / br through the function table
            const bool is_call = i.is_call;
            a.pushfq();
            if (i.rn == 31) a.zero(10); else a.load(10, i.rn, true);
            if (is_call) { a.movabs(11, pc + 4); a.store(30, 11); }
            std::vector<size_t> to_done;
            for (uint64_t e : entries) {
                a.movabs(11, e);
                a.cmp_r10_r11();
                a.jcc_raw(CC_NE, 1 + 5 + (is_call ? 5 : 0));      // skip popfq + call/jmp [+ jmp done]
                a.popfq();
                fixes.push_back({is_call ? a.call_fix() : a.jmp_fix(), e});
                if (is_call) to_done.push_back(a.jmp_fix());
            }
            a.popfq();
            a.ud2();                                              // not a known function entry
            for (size_t p : to_done) a.patch(p, a.b.size());
        } else if (i.is_call) {                                   // bl
            a.movabs(10, pc + 4);
            a.store(30, 10);
            fixes.push_back({a.call_fix(), target});
        } else if (m == "b") {
            fixes.push_back({a.jmp_fix(), target});
        } else if (m.rfind("b.", 0) == 0) {
            static const int8_t cc_map[16] = {CC_E, CC_NE, CC_B, CC_AE, CC_S, CC_NS, CC_O, CC_NO,
                                              -1, -1, CC_GE, CC_L, CC_G, CC_LE, -2, -2};
            uint32_t c = static_cast<uint32_t>(i.cond);
            if (c == 14 || c == 15) {
                fixes.push_back({a.jmp_fix(), target});
            } else if (c == 8) {                      // HI: C && !Z   (CF holds ARM C)
                a.jcc_raw(CC_AE, 6 + 5); a.jcc_raw(CC_E, 5);
                fixes.push_back({a.jmp_fix(), target});
            } else if (c == 9) {                      // LS: !C || Z
                fixes.push_back({a.jcc_fix(CC_AE), target});
                fixes.push_back({a.jcc_fix(CC_E), target});
            } else {
                fixes.push_back({a.jcc_fix(static_cast<uint8_t>(cc_map[c])), target});
            }
        } else if (m == "cbz" || m == "cbnz") {
            a.pushfq();
            if (i.rd == 31) a.zero(10); else a.load(10, i.rd, i.sf);
            a.test_r10(i.sf);
            a.jcc_raw(m == "cbz" ? CC_NE : CC_E, 1 + 5);   // skip popfq + jmp
            a.popfq();
            fixes.push_back({a.jmp_fix(), target});
            a.popfq();
        } else if (m == "tbz" || m == "tbnz") {
            a.pushfq();
            if (i.rd == 31) a.zero(10); else a.load(10, i.rd, i.sf);
            a.bt_r10(static_cast<uint8_t>(i.shift));
            a.jcc_raw(m == "tbz" ? CC_B : CC_AE, 1 + 5);
            a.popfq();
            fixes.push_back({a.jmp_fix(), target});
            a.popfq();
        } else {
            return unsupported();
        }
    }
    for (const Fix& f : fixes) {
        auto it = label.find(f.target);
        if (it == label.end()) return unsupported();
        a.patch(f.pos, it->second);
    }

    uint64_t off = 0;
    if (!commit(a.b, off)) return std::make_error_code(std::errc::not_enough_memory);
    out.code = a.b;
    out.guest_addr = guest_addr;
    out.entry_offset = off;     // offset into the arena
    out.host_addr = reinterpret_cast<uint64_t>(arena_.base + off);
    out.executable = true;
    host_by_guest_[guest_addr] = out.host_addr;
    return {};
#endif
}

std::error_code X64Backend::resolve_indirect_branch(uint64_t guest_addr, uint64_t& host_addr) {
    auto it = host_by_guest_.find(guest_addr);
    if (it == host_by_guest_.end()) return std::make_error_code(std::errc::no_such_process);
    host_addr = it->second;
    return {};
}

void* X64Backend::code_pointer(const X64CodeBlock& block) const {
    if (!arena_.base || !block.executable) return nullptr;
    return arena_.base + block.entry_offset;
}

GuestFunction X64Backend::entry_point(const X64CodeBlock& block) const {
    return reinterpret_cast<GuestFunction>(code_pointer(block));
}

void X64Backend::shutdown() {
#if defined(__unix__) || defined(__APPLE__)
    if (arena_.base) munmap(arena_.base, arena_.capacity);
#endif
    arena_ = ExecArena{};
    host_by_guest_.clear();
}

}  // namespace champollion
