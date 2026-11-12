#!/usr/bin/env python3
"""Run the cross-platform Python reference and installer test suites."""
import subprocess
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
TEST_COMMANDS = (
    ("Import/constants", "proto/test_import.py"),
    ("ARM64 decoder", "proto/test_decoder.py"),
    ("Mach-O end-to-end", "proto/test_e2e.py"),
    ("AOT translator", "proto/test_aot.py"),
    ("AOT differential (x86-64 + gcc)", "proto/test_aot_diff.py"),
    ("AOT memory + calls differential", "proto/test_aot_mem_diff.py"),
    ("IPA support", "proto/test_ipa.py"),
    ("Installer pipeline", "test_installer_server.py"),
    ("Installer IPA + CLI", "test_installer_ipa.py"),
    ("C++ decoder vs Python (g++)", "tests/diff_decoder.py"),
    ("C++ JIT differential (g++)", "tests/diff_jit.py"),
    ("C++ JIT memory + calls differential (g++)", "tests/diff_jit_mem.py"),
)


def main() -> int:
    for label, script in TEST_COMMANDS:
        print(f"=== {label} ===", flush=True)
        result = subprocess.run([sys.executable, str(PROJECT_DIR / script)], cwd=PROJECT_DIR)
        if result.returncode:
            print(f"FAILED: {label}", file=sys.stderr)
            return result.returncode
    print("All test suites passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())