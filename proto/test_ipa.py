import glob
import json
import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

try:
    from .ipa import IPAError, inspect_ipa, install_ipa, preflight_summary
except ImportError:
    from ipa import IPAError, inspect_ipa, install_ipa, preflight_summary

MH_MAGIC_64, CPU_ARM64, CPU_X86_64 = 0xFEEDFACF, 0x0100000C, 0x01000007
LC_SEGMENT_64, LC_MAIN, LC_ENCRYPTION_INFO_64 = 0x19, 0x80000028, 0x2C


def make_macho(words, encrypted=False, cputype=CPU_ARM64):
    code = struct.pack("<%dI" % len(words), *words)
    extra = struct.pack("<IIIIII", LC_ENCRYPTION_INFO_64, 24, 0, 0, 1, 0) if encrypted else b""
    code_offset = 32 + 152 + 24 + len(extra)
    header = struct.pack("<IIIIIIII", MH_MAGIC_64, cputype, 0, 2, 3 if encrypted else 2,
                         152 + 24 + len(extra), 0, 0)
    seg = struct.pack("<II16sQQQQIIII", LC_SEGMENT_64, 152 + 0, b"__TEXT\0".ljust(16, b"\0"),
                      0x1000, 0x1000, code_offset, len(code), 5, 5, 1, 0)
    sect = struct.pack("<16s16sQQIIIIIIII", b"__text\0".ljust(16, b"\0"), b"__TEXT\0".ljust(16, b"\0"),
                       0x1000, len(code), code_offset, 2, 0, 0, 0x80000400, 0, 0, 0)
    main = struct.pack("<IIQQ", LC_MAIN, 24, code_offset, 0)
    return header + seg + sect + main + extra + code


def make_ipa(path, macho, plist_extra=None, members=None):
    plist = {"CFBundleExecutable": "Test", "CFBundleIdentifier": "com.example.test",
             "CFBundleName": "Test", "CFBundleShortVersionString": "1.2", "MinimumOSVersion": "14.0"}
    plist.update(plist_extra or {})
    with zipfile.ZipFile(str(path), "w") as z:
        z.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist))
        z.writestr("Payload/Test.app/Test", macho)
        for name, data in (members or {}).items():
            z.writestr(name, data)


GOOD = [0xD28000E0, 0xD65F03C0]          # movz x0,#7 ; ret
UNSUPPORTED = [0xC85F7C20, 0xD65F03C0]   # ldxr x0,[x1] ; ret  (exclusive access: not supported)


class IPATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.before = set(glob.glob(tempfile.gettempdir() + "/champollion_ipa_*"))

    def tearDown(self):
        after = set(glob.glob(tempfile.gettempdir() + "/champollion_ipa_*"))
        self.assertEqual(after, self.before, "temp directories were leaked")
        self.tmp.cleanup()

    def test_translatable_ipa_writes_assembly_and_report_but_is_not_installed(self):
        ipa = self.dir / "a.ipa"
        make_ipa(ipa, make_macho(GOOD))
        result = install_ipa(str(ipa), str(self.dir / "out"))
        self.assertTrue(result["ok"])
        self.assertFalse(result["installed"])
        self.assertIn("_champollion_aot_entry", Path(result["artifact"]).read_text())
        report = json.loads(Path(result["report"]).read_text())
        self.assertEqual(report["bundle_id"], "com.example.test")
        self.assertEqual(report["min_macos_target"], "11.0")

    def test_unsupported_code_is_reported_not_installed(self):
        ipa = self.dir / "b.ipa"
        make_ipa(ipa, make_macho(UNSUPPORTED))
        result = install_ipa(str(ipa), str(self.dir / "out"))
        self.assertFalse(result["ok"])
        self.assertFalse(result["installed"])
        self.assertIsNone(result["artifact"])
        self.assertIn("not installed", result["message"])
        self.assertTrue(Path(result["report"]).is_file())

    def test_encrypted_app_is_refused(self):
        ipa = self.dir / "c.ipa"
        make_ipa(ipa, make_macho(GOOD, encrypted=True))
        with self.assertRaises(IPAError) as cm:
            install_ipa(str(ipa), str(self.dir / "out"))
        self.assertIn("encrypted", str(cm.exception))

    def test_non_arm64_is_refused(self):
        ipa = self.dir / "d.ipa"
        make_ipa(ipa, make_macho(GOOD, cputype=CPU_X86_64))
        with self.assertRaises(IPAError):
            inspect_ipa(str(ipa))

    def test_bad_archives_are_rejected(self):
        bad = self.dir / "e.ipa"
        bad.write_bytes(b"not a zip")
        with self.assertRaises(IPAError):
            inspect_ipa(str(bad))
        empty = self.dir / "f.ipa"
        with zipfile.ZipFile(str(empty), "w") as z:
            z.writestr("readme.txt", "hi")
        with self.assertRaises(IPAError):
            inspect_ipa(str(empty))

    def test_zip_slip_is_rejected(self):
        ipa = self.dir / "g.ipa"
        make_ipa(ipa, make_macho(GOOD), members={"../evil.txt": "x"})
        with self.assertRaises(IPAError) as cm:
            inspect_ipa(str(ipa))
        self.assertIn("Unsafe", str(cm.exception))
        self.assertFalse((self.dir.parent / "evil.txt").exists())

    def test_preflight_summary_lists_app_and_warnings(self):
        ipa = self.dir / "h.ipa"
        make_ipa(ipa, make_macho(GOOD))
        info = inspect_ipa(str(ipa))
        try:
            text = preflight_summary(info)
        finally:
            info.cleanup()
        self.assertIn("com.example.test", text)
        self.assertIn("Warning:", text)


if __name__ == "__main__":
    unittest.main()
