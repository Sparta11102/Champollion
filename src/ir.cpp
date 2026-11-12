#include <champollion/ir.h>

#include <sstream>

namespace champollion {

std::error_code verify_ir(const IrFunction& func) {
    // Phase 4: IR verifier
    // Ensure every virtual register is defined before use (SSA dominance check
    // placeholder), blocks are reachable, terminators are well-formed.
    if (func.blocks.empty()) {
        return std::make_error_code(std::errc::invalid_argument);
    }
    for (const auto& block : func.blocks) {
        if (block.insts.empty()) continue;
        const auto& last = block.insts.back();
        if (last.is_terminator) {
            switch (last.op) {
                case IrInst::Op::B:
                case IrInst::Op::B_COND:
                case IrInst::Op::CBZ:
                case IrInst::Op::CBNZ:
                case IrInst::Op::TBZ:
                case IrInst::Op::TBNZ:
                    if (block.successors.empty()) {
                        return std::make_error_code(std::errc::invalid_argument);
                    }
                    break;
                default:
                    break;
            }
        }
    }
    return {};
}

std::string ir_to_string(const IrFunction& func) {
    std::ostringstream os;
    os << "function " << func.name << " @ 0x" << std::hex << func.guest_addr << "\n";
    for (const auto& block : func.blocks) {
        os << "  block" << block.id << " @ 0x" << std::hex << block.guest_addr << ":\n";
        for (const auto& inst : block.insts) {
            os << "    " << static_cast<int>(inst.op);
            for (const auto& d : inst.dsts) os << " <- r" << d.id;
            for (const auto& s : inst.srcs) os << " <- r" << s.id;
            os << "\n";
        }
    }
    return os.str();
}

} // namespace champollion
