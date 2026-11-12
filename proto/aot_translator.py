"""Translate a supported ARM64 Mach-O entry function to x86-64 assembly."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Callable, Iterable

try:
    from .arm64_decode import Arm64Decoder, Arm64Inst, ArmRegClass
    from .macho import CPU_TYPE_ARM64, VM_PROT_EXEC, load_macho
except ImportError:
    from arm64_decode import Arm64Decoder, Arm64Inst, ArmRegClass
    from macho import CPU_TYPE_ARM64, VM_PROT_EXEC, load_macho


class TranslationError(ValueError):
    """The input function is outside the translator's supported subset."""


def _sign_extend(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return (value ^ sign) - sign


def _is_wide_move(opcode: int) -> bool:
    return ((opcode >> 23) & 0x3F) == 0x25


def _is_addsub_imm(opcode: int) -> bool:
    return ((opcode >> 23) & 0x3F) == 0x22


def _supported_data_instruction(opcode: int) -> bool:
    if opcode == 0xD503201F:
        return True
    if _is_wide_move(opcode):
        opc = (opcode >> 29) & 0x3
        sf = (opcode >> 31) & 1
        hw = (opcode >> 21) & 0x3
        return opc in (0, 2, 3) and (sf or hw < 2)
    if _is_addsub_imm(opcode):
        return True
    if (opcode & 0x1F200000) == 0x0B000000:
        return ((opcode >> 22) & 0x3) == 0 and ((opcode >> 10) & 0x3F) == 0
    if (opcode & 0x1F200000) == 0x0A000000:
        return (
            ((opcode >> 21) & 1) == 0
            and ((opcode >> 22) & 0x3) == 0
            and ((opcode >> 10) & 0x3F) == 0
        )
    return False


_MEM_MODES = ("offset", "unscaled", "pre", "post", "reg")


def _memory_supported(inst: Arm64Inst) -> bool:
    """General-register loads/stores (single and pair) with every addressing mode except literal."""
    if not (inst.is_load or inst.is_store) or not inst.supported or inst.is_unallocated:
        return False
    if inst.reg_class != ArmRegClass.GPR or inst.mem_mode not in _MEM_MODES:
        return False
    writeback = inst.mem_mode in ("pre", "post")
    if writeback and inst.rn != 31 and (inst.rd == inst.rn or (inst.is_pair and inst.rt2 == inst.rn)):
        return False                                  # UNPREDICTABLE on real hardware
    if inst.is_pair and inst.is_load and inst.rd == inst.rt2 and inst.rd != 31:
        return False                                  # UNPREDICTABLE
    return True


def _control_kind(opcode: int, inst: Arm64Inst) -> str | None:
    if (opcode & 0xFFFFFC1F) == 0xD65F0000:
        return "ret"
    if (opcode & 0xFC000000) == 0x14000000:
        return "b"
    if (opcode & 0xFC000000) == 0x94000000:
        return "call"
    if (opcode & 0xFF000010) == 0x54000000:
        return "b.cond"
    if (opcode & 0x7E000000) == 0x34000000:
        return "cbnz" if (opcode >> 24) & 1 else "cbz"
    if (opcode & 0x7E000000) == 0x36000000:
        return "tbnz" if (opcode >> 24) & 1 else "tbz"
    if inst.mnemonic == "blr":
        return "blr"
    if inst.mnemonic == "br":
        return "br"
    if inst.is_indirect or inst.is_call or inst.is_pac or inst.is_system:
        return "unsupported_branch"
    return None


def _target(inst: Arm64Inst) -> int:
    return inst.address + inst.imm


def _collect_function(
    read_instruction: Callable[[int], bytes],
    entry: int,
    max_instructions: int,
    extra_entries: Iterable[int] = (),
) -> tuple[dict[int, Arm64Inst], set[int]]:
    """Discover every reachable instruction. Returns (instructions, function entry points)."""
    decoder = Arm64Decoder()
    instructions: dict[int, Arm64Inst] = {}
    entries: set[int] = {entry, *extra_entries}
    pending = sorted(entries, reverse=True)

    while pending:
        address = pending.pop()
        while address not in instructions:
            if len(instructions) >= max_instructions:
                raise TranslationError(
                    f"Function exceeded the instruction limit ({max_instructions}).")
            code = read_instruction(address)
            if len(code) != 4:
                raise TranslationError(f"Cannot read an instruction at 0x{address:x}.")
            inst = decoder.decode(address, code).inst
            opcode = inst.opcode
            control = _control_kind(opcode, inst)

            if control is None and not (_supported_data_instruction(opcode) or _memory_supported(inst)):
                raise TranslationError(
                    f"Unsupported ARM64 instruction at 0x{address:x}: 0x{opcode:08x}.")
            if control == "unsupported_branch":
                raise TranslationError(
                    f"Unsupported branch at 0x{address:x}: 0x{opcode:08x}.")
            instructions[address] = inst

            if control == "ret":
                if inst.rn != 30:
                    raise TranslationError(f"Return through x{inst.rn} at 0x{address:x} is not supported.")
                break
            if control == "call":                 # the callee is a new function; execution resumes after it
                entries.add(_target(inst))
                pending.append(_target(inst))
                address += 4
                continue
            if control == "blr":                  # target must be a known function entry
                address += 4
                continue
            if control == "br":
                break
            if control == "b":
                pending.append(_target(inst))
                break
            if control in ("b.cond", "cbz", "cbnz", "tbz", "tbnz"):
                pending.append(_target(inst))
            address += 4

    for address, inst in instructions.items():
        kind = _control_kind(inst.opcode, inst)
        if kind in ("b", "b.cond", "cbz", "cbnz", "tbz", "tbnz", "call"):
            if _target(inst) not in instructions:
                raise TranslationError(
                    f"Branch at 0x{address:x} targets code outside the translated function.")
    return instructions, entries


def _load_register(index: int, width: int, scratch: str) -> list[str]:
    if index == 31:
        suffix = "q" if width == 64 else "l"
        target = f"%{scratch}" if width == 64 else f"%{scratch}d"
        return [f"mov{suffix} $0, {target}"]
    suffix = "q" if width == 64 else "l"
    source = f"{index * 8}(%r12)"
    target = f"%{scratch}" if width == 64 else f"%{scratch}d"
    return [f"mov{suffix} {source}, {target}"]


def _store_register(index: int, scratch: str) -> list[str]:
    if index == 31:
        return []
    return [f"movq %{scratch}, {index * 8}(%r12)"]


def _emit_data(opcode: int, address: int) -> list[str]:
    sf = (opcode >> 31) & 1
    width = 64 if sf else 32
    suffix = "q" if sf else "l"
    rd = opcode & 0x1F
    rn = (opcode >> 5) & 0x1F
    rm = (opcode >> 16) & 0x1F

    if opcode == 0xD503201F:
        return ["nop"]

    if _is_wide_move(opcode):
        opc = (opcode >> 29) & 0x3
        shift = ((opcode >> 21) & 0x3) * 16
        immediate = (opcode >> 5) & 0xFFFF
        register_mask = (1 << width) - 1
        shifted = (immediate << shift) & register_mask
        lines: list[str] = []
        if opc == 2:
            lines.append(f"movabsq ${shifted}, %r10")
        elif opc == 0:
            lines.append(f"movabsq ${register_mask ^ shifted}, %r10")
        else:
            clear_mask = register_mask ^ (0xFFFF << shift)
            lines.extend(["pushfq", *_load_register(rd, width, "r10")])
            lines.append(f"movabsq ${clear_mask}, %r11")
            lines.append("andq %r11, %r10")
            lines.append(f"movabsq ${shifted}, %r11")
            lines.append("orq %r11, %r10")
            lines.append("popfq")
        lines.extend(_store_register(rd, "r10"))
        return lines

    if _is_addsub_imm(opcode):
        is_sub = bool((opcode >> 30) & 1)
        sets_flags = bool((opcode >> 29) & 1)
        immediate = ((opcode >> 10) & 0xFFF) << (12 if (opcode >> 22) & 1 else 0)
        op = "sub" if is_sub else "add"
        lines = [] if sets_flags else ["pushfq"]
        # Rn == 31 is SP (context slot 31); Rd == 31 is SP unless flags are set (then XZR).
        mov = "movq" if width == 64 else "movl"
        target = "%r10" if width == 64 else "%r10d"
        lines.append(f"{mov} {rn * 8}(%r12), {target}")
        lines.append(f"{op}{suffix} ${immediate}, {target}")
        if sets_flags and is_sub:
            lines.append("cmc")
        if rd != 31 or not sets_flags:
            lines.append(f"movq %r10, {rd * 8}(%r12)")
        if not sets_flags:
            lines.append("popfq")
        return lines

    if (opcode & 0x1F200000) == 0x0B000000:
        is_sub = bool((opcode >> 30) & 1)
        sets_flags = bool((opcode >> 29) & 1)
        op = "sub" if is_sub else "add"
        lines = [] if sets_flags else ["pushfq"]
        lines.extend(_load_register(rn, width, "r10"))
        lines.extend(_load_register(rm, width, "r11"))
        lines.append(f"{op}{suffix} %r11{'d' if not sf else ''}, %r10{'d' if not sf else ''}")
        if sets_flags and is_sub:
            lines.append("cmc")
        lines.extend(_store_register(rd, "r10"))
        if not sets_flags:
            lines.append("popfq")
        return lines

    if (opcode & 0x1F200000) == 0x0A000000:
        opc = (opcode >> 29) & 0x3
        op = ("and", "or", "xor", "and")[opc]
        sets_flags = opc == 3
        lines = [] if sets_flags else ["pushfq"]
        lines.extend(_load_register(rn, width, "r10"))
        lines.extend(_load_register(rm, width, "r11"))
        lines.append(f"{op}{suffix} %r11{'d' if not sf else ''}, %r10{'d' if not sf else ''}")
        lines.extend(_store_register(rd, "r10"))
        if not sets_flags:
            lines.append("popfq")
        return lines

    raise TranslationError(f"Unsupported ARM64 instruction at 0x{address:x}: 0x{opcode:08x}.")


def _emit_memory(inst: Arm64Inst) -> list[str]:
    """Loads and stores. Only mov/lea/movzx/movsx are used, so x86 flags are never disturbed.
    Guest memory is accessed at the guest address (identity mapping)."""
    rn, rd, rt2, size, sf = inst.rn, inst.rd, inst.rt2, inst.size, inst.sf
    lines = [f"movq {rn * 8}(%r12), %r10"]            # base register; slot 31 holds SP
    mode = inst.mem_mode
    disp = inst.imm
    if mode == "reg":
        if inst.rm == 31:
            lines.append("movq $0, %r11")
        elif inst.shift_type == "uxtw":
            lines.append(f"movl {inst.rm * 8}(%r12), %r11d")
        elif inst.shift_type == "sxtw":
            lines.append(f"movslq {inst.rm * 8}(%r12), %r11")
        else:
            lines.append(f"movq {inst.rm * 8}(%r12), %r11")
        lines.append(f"leaq (%r10,%r11,{1 << inst.shift}), %r10")
        disp = 0
    elif mode == "pre":
        lines += [f"leaq {disp}(%r10), %r10", f"movq %r10, {rn * 8}(%r12)"]
        disp = 0
    elif mode == "post":
        disp = 0

    def value(reg: int, scratch: str) -> str:
        return f"movq $0, %{scratch}" if reg == 31 else f"movq {reg * 8}(%r12), %{scratch}"

    if inst.is_pair:
        step = 1 << size
        if inst.is_store:
            lines += [value(rd, "r11"), value(rt2, "rax")]
            if size == 3:
                lines += [f"movq %r11, {disp}(%r10)", f"movq %rax, {disp + 8}(%r10)"]
            else:
                lines += [f"movl %r11d, {disp}(%r10)", f"movl %eax, {disp + 4}(%r10)"]
        else:
            if size == 3:
                lines += [f"movq {disp}(%r10), %r11", f"movq {disp + 8}(%r10), %rax"]
            elif inst.is_signed:                      # ldpsw
                lines += [f"movslq {disp}(%r10), %r11", f"movslq {disp + step}(%r10), %rax"]
            else:
                lines += [f"movl {disp}(%r10), %r11d", f"movl {disp + 4}(%r10), %eax"]
            if rd != 31:
                lines.append(f"movq %r11, {rd * 8}(%r12)")
            if rt2 != 31:
                lines.append(f"movq %rax, {rt2 * 8}(%r12)")
    elif inst.is_store:
        lines.append(value(rd, "r11"))
        store = {3: "movq %r11", 2: "movl %r11d", 1: "movw %r11w", 0: "movb %r11b"}[size]
        lines.append(f"{store}, {disp}(%r10)")
    else:
        if not inst.is_signed:
            load = {3: "movq", 2: "movl", 1: "movzwl", 0: "movzbl"}[size]
            dest = "%r11" if size == 3 else "%r11d"
        else:
            load = {2: "movslq", 1: "movswq" if sf else "movswl", 0: "movsbq" if sf else "movsbl"}[size]
            dest = "%r11" if (sf or size == 2) else "%r11d"
        lines.append(f"{load} {disp}(%r10), {dest}")
        if rd != 31:
            lines.append(f"movq %r11, {rd * 8}(%r12)")

    if mode == "post":
        lines += [f"leaq {inst.imm}(%r10), %r10", f"movq %r10, {rn * 8}(%r12)"]
    return lines


def _emit_call(inst: Arm64Inst, entries: set[int], kind: str) -> list[str]:
    """bl / blr / br. Guest calls are host calls, so `ret` is a host `retq`; x30 is still
    set to the guest return address so code that saves or inspects it behaves the same."""
    address = inst.address
    ret_addr = address + 4
    if kind == "call":
        return [f"movabsq ${ret_addr}, %r10", f"movq %r10, {30 * 8}(%r12)",
                f"callq .L_{_target(inst):x}"]
    lines = ["pushfq"]
    lines += _load_register(inst.rn, 64, "r10")
    if kind == "blr":
        lines += [f"movabsq ${ret_addr}, %r11", f"movq %r11, {30 * 8}(%r12)"]
    done = f".L_ind_{address:x}_done"
    for entry in sorted(entries):
        nxt = f".L_ind_{address:x}_{entry:x}"
        lines += [f"movabsq ${entry}, %r11", "cmpq %r11, %r10", f"jne {nxt}", "popfq"]
        lines.append(f"callq .L_{entry:x}" if kind == "blr" else f"jmp .L_{entry:x}")
        if kind == "blr":
            lines.append(f"jmp {done}")
        lines.append(f"{nxt}:")
    lines += ["popfq", "ud2"]                         # target is not a known function entry
    if kind == "blr":
        lines.append(f"{done}:")
    return lines


def _emit_conditional(inst: Arm64Inst) -> list[str]:
    opcode = inst.opcode
    address = inst.address
    target = f".L_{_target(inst):x}"
    control = _control_kind(opcode, inst)

    if control == "b.cond":
        cond = opcode & 0xF
        conditions = {
            0: "e", 1: "ne", 2: "b", 3: "ae", 4: "s", 5: "ns",
            6: "o", 7: "no", 10: "ge", 11: "l",
            12: "g", 13: "le",
        }
        if cond in (14, 15):                      # AL and NV both always branch
            return [f"jmp {target}"]
        # CF holds the ARM carry flag here (sub is followed by cmc), so
        # HI (C && !Z) and LS (!C || Z) have no single x86 condition code.
        if cond == 8:
            skip = f".L_hi_{address:x}"
            return [f"jae {skip}", f"je {skip}", f"jmp {target}", f"{skip}:"]
        if cond == 9:
            return [f"jae {target}", f"je {target}"]
        return [f"j{conditions[cond]} {target}"]

    if control in ("cbz", "cbnz"):
        width = 64 if (opcode >> 31) & 1 else 32
        register = opcode & 0x1F
        skip = f".L_after_{address:x}"
        lines = ["pushfq", *_load_register(register, width, "r10")]
        suffix = "q" if width == 64 else "l"
        source = "%r10" if width == 64 else "%r10d"
        lines.append(f"test{suffix} {source}, {source}")
        skip_condition = "ne" if control == "cbz" else "e"
        lines.extend([f"j{skip_condition} {skip}", "popfq", f"jmp {target}", f"{skip}:", "popfq"])
        return lines

    if control in ("tbz", "tbnz"):
        width = 64 if (opcode >> 31) & 1 else 32
        register = opcode & 0x1F
        bit_index = (((opcode >> 31) & 1) << 5) | ((opcode >> 19) & 0x1F)
        if bit_index >= width:
            raise TranslationError(f"Invalid test-bit index at 0x{address:x}.")
        skip = f".L_after_{address:x}"
        lines = ["pushfq", *_load_register(register, width, "r10"), f"btq ${bit_index}, %r10"]
        skip_condition = "c" if control == "tbz" else "nc"
        lines.extend([f"j{skip_condition} {skip}", "popfq", f"jmp {target}", f"{skip}:", "popfq"])
        return lines

    raise TranslationError(f"Unsupported branch at 0x{address:x}.")


def emit_x86_64_assembly(instructions: dict[int, Arm64Inst], entry: int,
                         entries: set[int] | None = None) -> str:
    entries = entries if entries is not None else {entry}
    lines = [
        "# Guest memory is read and written at guest addresses (identity mapping):",
        "# the loader must map the guest image at its own virtual addresses.",
        ".text",
        ".globl _champollion_aot_entry",
        ".p2align 4",
        "_champollion_aot_entry:",
        "pushq %r12",
        "movq %rdi, %r12",
        f"callq .L_{entry:x}",
        "movq 0(%r12), %rax",
        "popq %r12",
        "retq",
    ]
    for address in sorted(instructions):
        inst = instructions[address]
        lines.extend([f".L_{address:x}:", f"# ARM64 0x{address:x}: 0x{inst.opcode:08x} {inst.mnemonic}"])
        control = _control_kind(inst.opcode, inst)
        if control == "ret":
            lines.append("retq")
        elif control in ("b.cond", "cbz", "cbnz", "tbz", "tbnz"):
            lines.extend(_emit_conditional(inst))
        elif control == "b":
            lines.append(f"jmp .L_{_target(inst):x}")
        elif control in ("call", "blr", "br"):
            lines.extend(_emit_call(inst, entries, control))
        elif _memory_supported(inst) and control is None and (inst.is_load or inst.is_store):
            lines.extend(_emit_memory(inst))
        else:
            lines.extend(_emit_data(inst.opcode, address))
    return "\n".join(lines) + "\n"


def translate_function(
    read_instruction: Callable[[int], bytes],
    entry: int,
    max_instructions: int = 1024,
    extra_entries: Iterable[int] = (),
) -> str:
    """Translate the code reachable from `entry` (including functions it calls with bl).
    `extra_entries` lists functions that are only reached through blr/br."""
    if entry < 0 or entry % 4:
        raise TranslationError("The entry address must be a non-negative, 4-byte-aligned address.")
    instructions, entries = _collect_function(read_instruction, entry, max_instructions, extra_entries)
    if not any(_control_kind(inst.opcode, inst) == "ret" for inst in instructions.values()):
        raise TranslationError("No return instruction was found in the reachable function.")
    return emit_x86_64_assembly(instructions, entry, entries)


def translate_macho(path: str | Path, output: str | Path, max_instructions: int = 1024) -> int:
    image = load_macho(str(path))
    if image.cputype != CPU_TYPE_ARM64:
        raise TranslationError(f"Expected an ARM64 Mach-O image, got CPU type 0x{image.cputype:x}.")
    if not image.is_little_endian:
        raise TranslationError("Big-endian Mach-O images are not supported.")
    entry = image.entry_vaddr
    segment = next(
        (
            item for item in image.segments
            if item.initprot & VM_PROT_EXEC
            and item.vmaddr <= entry < item.vmaddr + item.filesize
        ),
        None,
    )
    if segment is None:
        raise TranslationError("Could not locate file-backed executable code at the Mach-O entry point.")

    def read_instruction(address: int) -> bytes:
        if address < segment.vmaddr or address + 4 > segment.vmaddr + segment.filesize:
            return b""
        file_offset = segment.fileoff + address - segment.vmaddr
        return image.file_data[file_offset:file_offset + 4]

    assembly = translate_function(read_instruction, entry, max_instructions)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(assembly, encoding="utf-8")
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Translate a supported ARM64 Mach-O entry function to x86-64 assembly."
    )
    parser.add_argument("input", help="thin ARM64 Mach-O input")
    parser.add_argument("output", help="output x86-64 assembly (.s)")
    parser.add_argument("--max-instructions", type=int, default=1024)
    args = parser.parse_args()
    try:
        entry = translate_macho(args.input, args.output, args.max_instructions)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"AOT translation failed: {error}\n")
    print(f"Translated entry function at 0x{entry:x} to {args.output}")
    print("Output is x86-64 assembly for one function, not a complete macOS app.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())