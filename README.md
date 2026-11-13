Champollion
Run ARM64 macOS apps on Intel Macs.

Champollion is an binary translator that aims to do what Rosetta 2 does — in reverse. Where Rosetta 2 brings Intel apps to Apple silicon, Champollion is being built to bring ARM64 apps back to the Intel Macs Apple left behind.

Named after Jean-François Champollion, the man who deciphered the Rosetta Stone.

Why
Apple silicon Macs can still run Intel apps through Rosetta 2. Intel Macs got no such courtesy — ARM64-only apps simply won't launch. Champollion exists to close that gap: translate ARM64 machine code to native x86-64, ahead-of-time or just-in-time, and keep older hardware useful.

What it can do today (Beta 2)
Champollion translates real ARM64 integer code to x86-64, both as assembly (AOT) and as live executable machine code (JIT), including:

Upcoming and in testing
Swift Ui Downgrader
Ipa app installer and launcher
AVX Emulation
Cloud service to enable faster traanslation
Swift unsupported mac upgrader
Wine embedded for win app or game installs

SIMD / floating point and atomics

The big one: a runtime — dyld, libSystem, Objective-C and Swift bridging

Real app support, one instruction at a time

Try it
Requirements: macOS 11+ (Big Sur or later) and Python 3.8+ (included with Xcode Command Line Tools).

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
