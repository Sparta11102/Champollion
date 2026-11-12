import struct
import tempfile
import unittest
from pathlib import Path

try:
    from .aot_translator import TranslationError, translate_function, translate_macho
    from .macho import CPU_TYPE_ARM64, FAT_MAGIC, FAT_MAGIC_64, LC_MAIN, LC_SEGMENT_64, MH_MAGIC_64, VM_PROT_EXEC, VM_PROT_READ, load_macho
except ImportError:
    from aot_translator import TranslationError, translate_function, translate_macho
    from macho import CPU_TYPE_ARM64, FAT_MAGIC, FAT_MAGIC_64, LC_MAIN, LC_SEGMENT_64, MH_MAGIC_64, VM_PROT_EXEC, VM_PROT_READ, load_macho


def arm64_words(*words):
    code = struct.pack("<" + "I" * len(words), *words)
    return lambda address: code[address:address + 4] if address < len(code) else b""


def write_synthetic_macho(path):
    code = struct.pack("<II", 0xD28000E0, 0xD65F03C0)
    code_offset = 32 + 152 + 24
    header = struct.pack(
        "<IIIIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, 0, 2, 2, 176, 0, 0
    )
    segment = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        152,
        b"__TEXT\0".ljust(16, b"\0"),
        0x1000,
        0x1000,
        code_offset,
        len(code),
        VM_PROT_READ | VM_PROT_EXEC,
        VM_PROT_READ | VM_PROT_EXEC,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text\0".ljust(16, b"\0"),
        b"__TEXT\0".ljust(16, b"\0"),
        0x1000,
        len(code),
        code_offset,
        2,
        0,
        3,
        0x80000006,
        0,
        0,
        0,
    )
    main = struct.pack("<IIQQ", LC_MAIN, 24, code_offset, 0)
    path.write_bytes(header + segment + section + main + code)


class AotTranslatorTests(unittest.TestCase):
    def test_translates_wide_moves_add_and_ret(self):
        read_instruction = arm64_words(
            0xD28000E0,  # movz x0, #7
            0xD2800061,  # movz x1, #3
            0x8B010000,  # add x0, x0, x1
            0xD65F03C0,  # ret x30
        )
        assembly = translate_function(read_instruction, 0)
        self.assertIn("movabsq $7, %r10", assembly)
        self.assertIn("addq %r11, %r10", assembly)
        self.assertIn("movq 0(%r12), %rax", assembly)
        self.assertIn("retq", assembly)

    def test_translates_subs_and_conditional_branch(self):
        read_instruction = arm64_words(
            0xEB020020,  # subs x0, x1, x2
            0x54000040,  # b.eq +8
            0xD65F03C0,  # ret x30
            0xD65F03C0,  # ret x30
        )
        assembly = translate_function(read_instruction, 0)
        self.assertIn("subq %r11, %r10", assembly)
        self.assertIn("cmc", assembly)
        self.assertIn("je .L_c", assembly)

    def test_reads_zero_register_as_zero(self):
        read_instruction = arm64_words(
            0x8B1F03E0,  # add x0, xzr, xzr
            0xD65F03C0,  # ret x30
        )
        assembly = translate_function(read_instruction, 0)
        self.assertIn("movq $0, %r10", assembly)
        self.assertNotIn("mov64", assembly)

    def test_translates_synthetic_macho_to_assembly_file(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "arm64-test"
            output_path = Path(directory) / "translated.s"
            write_synthetic_macho(input_path)
            image = load_macho(str(input_path))
            entry = translate_macho(input_path, output_path)
            assembly = output_path.read_text(encoding="utf-8")
        self.assertEqual(entry, 0x1000)
        self.assertEqual(image.sections[0].type, 6)
        self.assertEqual(image.sections[0].attributes, 0x80000006)
        self.assertIn("_champollion_aot_entry", assembly)
        self.assertIn("movabsq $7, %r10", assembly)

    def test_translates_arm64_slice_from_fat_macho(self):
        with tempfile.TemporaryDirectory() as directory:
            thin_path = Path(directory) / "thin"
            fat_path = Path(directory) / "fat"
            output_path = Path(directory) / "fat.s"
            write_synthetic_macho(thin_path)
            thin = thin_path.read_bytes()
            slice_offset = 28
            fat_header = struct.pack(">II", FAT_MAGIC, 1)
            fat_arch = struct.pack(">iiIII", CPU_TYPE_ARM64, 0, slice_offset, len(thin), 2)
            fat_path.write_bytes(fat_header + fat_arch + thin)
            entry = translate_macho(fat_path, output_path)
            assembly = output_path.read_text(encoding="utf-8")
        self.assertEqual(entry, 0x1000)
        self.assertIn("movabsq $7, %r10", assembly)

    def test_translates_arm64_slice_from_fat64_macho(self):
        with tempfile.TemporaryDirectory() as directory:
            thin_path = Path(directory) / "thin"
            fat_path = Path(directory) / "fat64"
            output_path = Path(directory) / "fat64.s"
            write_synthetic_macho(thin_path)
            thin = thin_path.read_bytes()
            slice_offset = 40
            fat_header = struct.pack(">II", FAT_MAGIC_64, 1)
            fat_arch = struct.pack(">iiQQII", CPU_TYPE_ARM64, 0, slice_offset, len(thin), 2, 0)
            fat_path.write_bytes(fat_header + fat_arch + thin)
            entry = translate_macho(fat_path, output_path)
            assembly = output_path.read_text(encoding="utf-8")
        self.assertEqual(entry, 0x1000)
        self.assertIn("movabsq $7, %r10", assembly)

    def test_rejects_unsupported_instruction_with_address(self):
        read_instruction = arm64_words(0xC85F7C20, 0xD65F03C0)   # ldxr x0, [x1] (exclusive)
        with self.assertRaisesRegex(TranslationError, "0x0: 0xc85f7c20"):
            translate_function(read_instruction, 0)

    def test_rejects_ret_through_other_register(self):
        read_instruction = arm64_words(0xD65F0020)               # ret x1
        with self.assertRaisesRegex(TranslationError, "x1"):
            translate_function(read_instruction, 0)

    def test_rejects_unpredictable_writeback_encoding(self):
        read_instruction = arm64_words(0xF8408420, 0xD65F03C0)   # ldr x0, [x1], #8   (valid)
        translate_function(read_instruction, 0)
        read_instruction = arm64_words(0xF8408421, 0xD65F03C0)   # ldr x1, [x1], #8   (unpredictable)
        with self.assertRaises(TranslationError):
            translate_function(read_instruction, 0)


if __name__ == "__main__":
    unittest.main()