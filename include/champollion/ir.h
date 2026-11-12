#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <variant>
#include <unordered_map>
#include <system_error>

namespace champollion {

// ============================================================================
// Intermediate Representation (ToDo.txt Phase 4: IR and context)
// SSA IR with vector and flag types, guest context struct, IR verifier.
// ============================================================================

// IR value types
enum class IrType : uint8_t {
    I8, I16, I32, I64,        // integers
    F32, F64, F128,           // floating point
    V8I8, V16I8, V4I16, V8I16, V2I32, V4I32, V2I64, V1I64,  // vectors
    V2F32, V4F32, V2F64,      // vector float
    FLAGS,                     // guest condition flags (NZCV)
    PTR                        // guest pointer
};

// A virtual register in SSA form
struct IrReg {
    uint32_t id = 0;
    IrType type = IrType::I64;
    bool is_guest_reg = false;   // true if maps to a guest ARM64 register
    uint32_t guest_reg_index = 0; // guest register index if is_guest_reg
};

// IR constant
struct IrConst {
    IrType type = IrType::I64;
    uint64_t u64 = 0;
    double f64 = 0.0;
};

// An IR instruction (three-address code, SSA)
struct IrInst {
    enum class Op : uint16_t {
        // Copies / moves
        MOV,
        // Integer ALU
        ADD, SUB, MUL, UDIV, SDIV, UREM, SREM,
        AND, ORR, EOR, BIC,
        LSL, LSR, ASR, ROR, RORV, LSLV, LSRV, ASRV,
        SXTB, SXTH, SXTW, UXTB, UXTH, UXTW,
        // Flags
        ADDS, SUBS, CMP, CMN,
        // Logical flag shifts
        // Floating point
        FADD, FSUB, FMUL, FDIV, FSQRT, FNEG,
        FCMP, FCMPZ, FCMPE,
        // Conversions
        SCVT_F, UCVT_F, FCVT_S, FCVT_U, FCVT_ZS, FCVT_ZU,
        // Vector / SIMD (placeholder ops, expanded in Phase 8)
        VADD, VSUB, VMUL, VDIV, VNEG, VMAX, VMIN,
        // Load / store
        LOAD, STORE,
        LOAD8, LOAD16, LOAD32, LOAD64,
        STORE8, STORE16, STORE32, STORE64,
        LOAD_EXCLUSIVE, STORE_EXCLUSIVE,  // Phase 7 atomics
        // Branches
        B, B_COND, CBZ, CBNZ, TBZ, TBNZ,
        BL, RET, BR, BLR,
        // System / PAC (no-op)
        SYS, NOP,
        // Pseudo / meta
        PHI, PARAM, RETURN, LABEL, UNREACHABLE
    };

    Op op = Op::MOV;
    IrType type = IrType::I64;
    std::vector<IrReg> srcs;
    std::vector<IrReg> dsts;
    std::variant<std::monostate, IrConst, int64_t, std::string> imm;
    uint64_t guest_addr = 0;   // guest address of originating instruction
    bool sets_flags = false;
    bool is_terminator = false;
};

// A basic block of IR instructions
struct IrBlock {
    uint32_t id = 0;
    uint64_t guest_addr = 0;   // guest address this block starts at
    std::vector<IrInst> insts;
    std::vector<uint32_t> successors;
    std::vector<uint32_t> predecessors;
    bool is_entry = false;
};

// Guest CPU context (architectural state visible to translated code)
// This struct is mirrored in memory by the JIT backend so translated code
// can read/write guest registers directly.
struct GuestContext {
    // General purpose registers (x0-x30)
    uint64_t x[31] = {};
    // Program counter
    uint64_t pc = 0;
    // Condition flags (NZCV)
    uint32_t nzcv = 0;
    // Stack pointer (x31 alias) and link register (x30)
    uint64_t sp = 0;
    uint64_t lr = 0;
    // Floating point / SIMD registers (q0-q31), stored as 4x uint64
    uint64_t q[32][2] = {};
    // FPCR / FPSR (Phase 8)
    uint32_t fpcr = 0;
    uint32_t fpsr = 0;
    // Exclusive monitor (Phase 7)
    uint64_t exclusive_addr = 0;
    bool exclusive_valid = false;
};

// A compiled IR function (one guest basic block or region)
struct IrFunction {
    std::string name;
    uint64_t guest_addr = 0;
    std::vector<IrBlock> blocks;
    std::vector<IrReg> params;
    IrReg return_reg{};
    bool verified = false;
};

// IR verifier (Phase 4)
// Returns std::error_code if the IR is malformed.
std::error_code verify_ir(const IrFunction& func);

// Dump IR to human-readable text (for debugging)
std::string ir_to_string(const IrFunction& func);

} // namespace champollion
