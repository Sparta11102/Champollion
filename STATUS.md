# Champollion status

Target: **macOS 11 (Big Sur) and later**. Last full test run: all suites passed (see "Tests").

## The honest summary

Champollion can currently translate **integer ARM64 programs made of several functions** to x86-64,
either as assembly text (AOT) or as live machine code (JIT, x86-64 hosts only):

* move-wide, add/sub (register and immediate), and/orr/eor, compares and flags, all condition codes;
* **loads and stores**: byte/half/word/doubleword, sign extension, every addressing mode
  (unsigned offset, unscaled, pre/post-index, register offset with `uxtw`/`lsl`/`sxtw`/`sxtx`), and
  `ldp`/`stp`/`ldpsw`, with SP as a base register (so prologues, epilogues and locals work);
* **calls**: `bl`, `blr`/`br` to known function entries, tail calls, and `ret`.

Guest memory is accessed **at the guest address** (identity mapping). Whoever runs the translated
code must map the image at its own virtual addresses; no loader does that yet. Guest `ret` is a host
`ret` (x30 is still set by `bl`/`blr`), so code must use balanced call/return.

It **cannot run real iOS or macOS apps**: still missing are shifts, multiply/divide, conditional
select and bitfield instructions, SIMD/FP, atomics, calls into libSystem, and the dyld /
Objective-C / UIKit runtime. The last item is the largest piece of the project and has not been
started.

The installer therefore *inspects* an IPA and tries to translate it, and tells you plainly when it
cannot. It never reports an app as "installed" unless it is a runnable app, which none are yet.

## What changed in this version

| Area | Before | Now |
|---|---|---|
| ARM64 decoder (Python) | Most real instructions decoded wrongly (`add` as a load, `sub`/`cmp`/`ldr`/`str` unallocated, `br`/`blr` encodings swapped) | Rewritten against the ARM encoding groups; known-answer tests + 200k-word fuzz |
| ARM64 decoder (C++) | `src/arm64_decoder.cpp` missing from the project | Written; checked field-by-field against the Python decoder on 400k words |
| AOT translator | `b.hi` / `b.ls` evaluated wrongly after compares; no add/sub immediate; no memory or calls | Fixed; add/sub immediate, loads/stores (all forms), stack and calls added; differential-tested by executing the output on x86-64 |
| JIT backend | `compile()` ignored its input and emitted a fixed stub; arena growth used an invalid `mmap` | Real JIT path (`compile_guest`) with the same memory/call support as the AOT; fixed arena; unsupported code is refused with an error |
| IPA support | none | `proto/ipa.py` + installer modes (see below) |
| Installer backend | `installer_app.py` / `installer_ui.html` missing | Recreated; existing 9 tests pass; adds IPA mode and `champollion_cli.py` |
| Swift app | UI mock-up with a fake progress timer; `Package.swift` target name did not match sources | Calls the real backend; macOS 11 deployment target; unit tests for the CLI protocol |

## IPA handling

`proto/ipa.py` unpacks the `.ipa` (with a zip-slip guard), reads `Info.plist`, finds the arm64 slice
(thin or universal), scans embedded frameworks, and checks `LC_ENCRYPTION_INFO(_64)`.

* **Encrypted (FairPlay) apps are refused** with a clear message. Champollion does not remove app
  protection; use an unencrypted build you have the right to use (for example your own).
* Non-arm64 apps are refused. arm64e apps get a warning.
* The main executable is passed to the AOT translator. If it uses anything unsupported (almost
  every real app: it will call libSystem, use SIMD, ...), the result is "not installed" plus a JSON
  report explaining why. If it translates, you get an assembly file, clearly labelled as not runnable.

## macOS 11 compatibility

* CMake: `CMAKE_OSX_DEPLOYMENT_TARGET 11.0`. Swift package: `platforms: [.macOS(.v11)]`, tools 5.4.
  App `Info.plist`: `LSMinimumSystemVersion 11.0`. Xcode template project: deployment target 11.0.
* Swift avoids syntax newer than 5.4 (no `if let x {` shorthand) and macOS 12+ APIs.
* Python code is checked for 3.8 syntax (the version in macOS 11's command line tools).
* JIT memory uses `MAP_JIT` on macOS; `pthread_jit_write_protect_np` is only called on Apple silicon.
  The JIT emits **x86-64**, so it runs on Intel Macs. On Apple silicon the installer and AOT
  assembly output work, but `compile_guest` returns "not supported".

## Tests

`python3 run_tests.py` runs everything:

* Decoder known answers + fuzz; C++ vs Python decoder agreement (needs g++).
* AOT differential: random ARM64 programs are executed by a Python reference model and, after
  translation, natively on x86-64 (needs an x86-64 host with gcc); every register must match.
  Re-introducing the old `hi`/`ls` bug fails 28 of 400 programs, so the test does detect it.
* AOT memory + calls differential: random multi-function programs (prologues, locals, `bl`, `blr`,
  `br`, tail calls, every load/store width and addressing mode, pairs, negative and high-bit index
  registers) plus two directed loops (array sum, byte copy). Every register and a CRC of the whole
  128 KiB memory window must match. Deliberately breaking sign extension, post-index writeback,
  the pair offset, the index scale, `sxtw`/`uxtw`, or the x30 update on `bl` is caught each time.
* JIT differentials: the same programs through the C++ JIT (same mutation checks).
* IPA, installer HTTP API and CLI tests.

What the tests do **not** prove: behaviour on real ARM64 hardware (the reference model was written
from the architecture manual, not validated against a device), anything involving memory, calls
or SIMD, or any real app.

## Not verified (no Mac available while this was written)

* The **Swift code has never been compiled.** Expect to fix a compiler error or two on first build.
* CMake was not run (not installed here); the same sources compile cleanly with
  `g++ -std=c++20 -Wall -Wextra -Werror -pedantic`, the flags in `CMakeLists.txt`.
* macOS-only paths: `MAP_JIT`, `osascript` file chooser, `codesign`, `open` for `.pkg`/`.dmg`.
* `.dmg` / `.pkg` contents are not inspected; AOT on a `.dmg` is not supported (mount it and pick the `.app`).

## Next steps, in order

1. Build on a Mac: `cd macos-installer-native && ./build_app.sh`, then `python3 run_tests.py`.
2. ~~Add loads/stores, the stack, and calls~~ (done, see above).
3. Map a Mach-O image at its own addresses (loader), then run a plain command-line ARM64 program.
4. Decide how libSystem is provided (host libSystem via thunks is the usual route), so `bl` to stubs works.
5. Add the remaining integer instructions (shifts, mul/div, csel, bitfield), then SIMD/FP and atomics.
6. Only then take on dyld/fixups, Objective-C, and UIKit.
