#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <system_error>
#include "ir.h"

namespace champollion {

// ============================================================================
// x86-64 JIT backend.
//
// compile_guest() decodes ARM64 code and emits x86-64 directly for a supported
// subset: move-wide, add/sub immediate and register, logical register, general-register
// loads/stores (all widths, sign extension, every addressing mode, pairs), branches, and
// calls (bl; blr/br to known function entries). Guest memory is accessed at the guest
// address (identity mapping), so the loader must map the image at its own addresses.
// Guest calls are host calls, so `ret` is a host `ret` (x30 is still set on calls).
// Anything else makes it return std::errc::function_not_supported - it never emits
// placeholder code.
// compile(IrFunction) is not implemented: the IR has no lowering from the decoder.
//
// Generated functions have the C signature   uint64_t fn(uint64_t* ctx)
// where ctx[0..30] = x0..x30 and ctx[31] = SP. They return ctx[0].
// ============================================================================

struct X64CodeBlock {
    std::vector<uint8_t> code;      // emitted machine code
    uint64_t guest_addr = 0;        // guest address this block translates
    uint64_t host_addr = 0;         // host address where code lives
    uint64_t entry_offset = 0;      // offset of the entry point within `code`
    bool executable = false;
};

using GuestFunction = uint64_t (*)(uint64_t* ctx);

class X64Backend {
public:
    X64Backend();
    ~X64Backend();
    X64Backend(const X64Backend&) = delete;
    X64Backend& operator=(const X64Backend&) = delete;

    // Reserve `size` bytes of executable memory. The arena never moves, so pointers
    // to compiled code stay valid; when it is full compilation fails.
    std::error_code allocate_exec_memory(uint64_t size);

    // Translate the guest function starting at `guest_addr`. `code` holds `size` bytes of
    // guest memory starting at `region_base`.
    // `extra_entries` lists functions reached only through blr/br (indirect targets must be
    // known function entries; anything else traps with ud2).
    std::error_code compile_guest(const uint8_t* code, uint64_t region_base, uint64_t size,
                                  uint64_t guest_addr, X64CodeBlock& out,
                                  const std::vector<uint64_t>& extra_entries = {});

    // Not implemented (returns function_not_supported): the IR has no decoder lowering yet.
    std::error_code compile(const IrFunction& func, X64CodeBlock& out);

    // Look up the host address of an already compiled guest function.
    std::error_code resolve_indirect_branch(uint64_t guest_addr, uint64_t& host_addr);

    GuestFunction entry_point(const X64CodeBlock& block) const;
    void* code_pointer(const X64CodeBlock& block) const;

    void shutdown();

private:
    struct ExecArena {
        uint8_t* base = nullptr;
        uint64_t capacity = 0;
        uint64_t used = 0;
    };
    ExecArena arena_;
    std::unordered_map<uint64_t, uint64_t> host_by_guest_;   // guest addr -> host addr

    bool commit(const std::vector<uint8_t>& bytes, uint64_t& offset);
};

X64Backend& global_backend();

}  // namespace champollion
