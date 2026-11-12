#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <system_error>

namespace champollion {

// ============================================================================
// ARM64 decoder. C++ port of proto/arm64_decode.py; tests/diff_decoder.py
// checks the two agree on every field except `operands` (left empty here).
// ============================================================================

enum class ArmCond : uint8_t {
    EQ = 0, NE = 1, CS = 2, CC = 3, MI = 4, PL = 5, VS = 6, VC = 7,
    HI = 8, LS = 9, GE = 10, LT = 11, GT = 12, LE = 13, AL = 14, NV = 15
};

enum class ArmRegClass : uint8_t { GPR, VREG };

struct Arm64Inst {
    uint32_t opcode = 0;
    uint64_t address = 0;
    std::string mnemonic;
    std::string operands;      // not populated by the C++ decoder
    std::string alias;         // preferred alias (mov, cmp, lsl, ...)
    std::string shift_type;
    std::string mem_mode;      // offset / pre / post / reg / unscaled / literal / exclusive

    ArmRegClass reg_class = ArmRegClass::GPR;
    uint32_t rd = 0, rn = 0, rm = 0, ra = 0, rt2 = 0;
    uint32_t size = 0;         // access size log2 for loads/stores (0=b .. 4=q)
    uint32_t sf = 0;           // 0=32-bit, 1=64-bit
    int64_t imm = 0;
    uint32_t shift = 0;
    ArmCond cond = ArmCond::AL;

    bool set_flags = false;
    bool is_load = false, is_store = false, is_signed = false, is_pair = false;
    bool rd_is_sp = false, rn_is_sp = false;   // register 31 means SP, not ZR
    bool is_branch = false, is_call = false, is_return = false;
    bool is_cond_branch = false, is_indirect = false;
    bool is_system = false, is_pac = false;
    bool is_unallocated = false;
    bool supported = true;     // false: valid encoding that is not decoded in detail
};

struct DecodeResult {
    Arm64Inst inst;
    uint32_t size = 4;
    std::error_code error;
};

class Arm64Decoder {
public:
    Arm64Decoder() = default;

    // Decode one instruction at guest address `addr`; `code` must hold 4 bytes.
    DecodeResult decode(uint64_t addr, const uint8_t* code);

    // Decode until a branch, an error, or `limit` bytes.
    std::vector<Arm64Inst> decode_block(uint64_t start_addr, const uint8_t* code,
                                        uint64_t limit);
};

}  // namespace champollion
