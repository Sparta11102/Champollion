Champollion
Run ARM64 macOS apps on Intel Macs.

Champollion is an experimental binary translator that aims to do what Rosetta 2 does — in reverse. Where Rosetta 2 brings Intel apps to Apple silicon, Champollion is being built to bring ARM64 apps back to the Intel Macs Apple left behind.

Named after Jean-François Champollion, the man who deciphered the Rosetta Stone.

Why
Apple silicon Macs can still run Intel apps through Rosetta 2. Intel Macs got no such courtesy — ARM64-only apps simply won't launch. Champollion exists to close that gap: translate ARM64 machine code to native x86-64, ahead-of-time or just-in-time, and keep older hardware useful.

What it can do today (Beta 2)
Champollion translates real ARM64 integer code to x86-64, both as assembly (AOT) and as live executable machine code (JIT), including:

Full integer arithmetic and logic, with flags and all condition codes

Every load/store width and addressing mode — byte to doubleword, sign extension, pre/post-index, register offsets, ldp/stp pairs, SP-relative stack access

Complete control flow — b, b.cond, cbz/cbnz, tbz/tbnz, bl, blr, br, tail calls, and ret

Real Mach-O parsing: thin and universal binaries, segments, symbols, dylibs, chained fixups

IPA inspection with FairPlay detection (encrypted apps are refused, never stripped)

And it proves itself: randomly generated ARM64 programs are translated, executed natively on x86-64, and checked register-by-register and byte-for-byte against a reference model. The C++ and Python decoders agree on 400,000+ instruction words. Every suite passes.

What's coming
Shifts, multiply/divide, conditional select, bitfield ops

SIMD / floating point and atomics

The big one: a runtime — dyld, libSystem, Objective-C and Swift bridging

Real app support, one instruction at a time

Try it
Requirements: macOS 11+ (Big Sur or later) and Python 3.8+ (included with Xcode Command Line Tools).

bash
git clone https://github.com/Sparta11102/champollion.git
cd champollion
python3 run_tests.py        # watch every suite pass
python3 installer_app.py    # launch the installer wizard
Or grab a release, unzip, and double-click Champollion.app.

Honest fine print
Champollion cannot run full iOS or macOS apps yet — SIMD, external calls, and the Objective-C runtime are still ahead. The installer tells you plainly when an app is out of reach, and it will never claim an app is "installed" unless it actually runs. No hype, no fake progress bars — just steady, tested progress toward reverse Rosetta.

Status
Phase	Status
Mach-O loader & mini-dyld	In progress
Integer ARM64 decoder	Done
AOT translator (integer)	Done
JIT backend (integer)	Done
Differential test harness	Done
SIMD / FP / atomics	Pending
Runtime (dyld, libSystem, Obj-C)	Pending
Contributing
Issues, bug reports, and instruction-coverage contributions are welcome. The Python reference implementation in proto/ mirrors the C++ core, so you can prototype a feature in Python, differential-test it, then port it to C++ with confidence.

License
See LICENSE for details.
