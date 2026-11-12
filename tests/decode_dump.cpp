// Reads hex instruction words from stdin and prints decoded fields, one line per word.
// Used by tests/diff_decoder.py to check the C++ decoder against the Python one.
#include <champollion/arm64_decoder.h>
#include <cstdio>
using namespace champollion;
int main() {
    unsigned long long addr; unsigned int word;
    Arm64Decoder d;
    while (std::scanf("%llx %x", &addr, &word) == 2) {
        uint8_t b[4] = {uint8_t(word), uint8_t(word >> 8), uint8_t(word >> 16), uint8_t(word >> 24)};
        DecodeResult r = d.decode(addr, b);
        const Arm64Inst& i = r.inst;
        unsigned flags = (i.set_flags << 0) | (i.is_load << 1) | (i.is_store << 2) | (i.is_signed << 3) |
                         (i.is_pair << 4) | (i.rd_is_sp << 5) | (i.rn_is_sp << 6) | (i.is_branch << 7) |
                         (i.is_call << 8) | (i.is_return << 9) | (i.is_cond_branch << 10) |
                         (i.is_indirect << 11) | (i.is_system << 12) | (i.is_pac << 13) |
                         (i.is_unallocated << 14) | (i.supported << 15);
        std::printf("%s|%s|%s|%s|%u|%u|%u|%u|%u|%u|%u|%u|%llu|%u|%u|%u\n", i.mnemonic.c_str(), i.alias.c_str(),
                    i.shift_type.c_str(), i.mem_mode.c_str(), i.sf, i.rd, i.rn, i.rm, i.ra, i.rt2, i.size,
                    i.shift, (unsigned long long)i.imm, (unsigned)i.cond, flags, (unsigned)i.reg_class);
    }
    return 0;
}
