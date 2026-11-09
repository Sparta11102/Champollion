# champollion

An experimental ARM64 Mach-O loader/translator workbench targeting x86_64 macOS.
The current CLI loads Mach-O files and decodes a limited entry-instruction set;
full app translation is not implemented.

Based on the Champollion design (ProjectChampollion) — see `../ProjectChampollion-main/`
for the upstream AOT extractor, the Ghidra AArch64 spec, and the design docs.

## Status

| ToDo Phase | Scope | Status |
|---|---|---|
| 0 | Setup and research | **Done** — project scaffold, toolchain probe, design notes |
| 1 | Mach-O loader and mini-dyld | **In progress** — loader parses fat/thin arm64 Mach-O (segments, sections, symtab, dylibs, chained fixups) |
| 2 | Runtime skeleton | Pending |
| 3 | Full ARM64 decoder | **In progress** — control-flow + MOV/ADD/SUBS decoded; broader ISA pending |
| 4 | IR and context | **Started** — SSA IR data model, `GuestContext`, verifier skeleton |
| 5 | Testing infrastructure | Pending (differential vs. arm64 host required) |
| 6 | x64 backend and first run | **Started** — exec-memory arena, x64 emit helpers, codegen stub |
| 7 | Memory management and atomics | Pending |
| 8 | Floating point and SIMD | Pending |
| 9 | Thunking and calling conventions | Pending |
| 10 | Objective-C / Swift / frameworks | Pending |
| 11 | Performance optimization | Pending |
| 12 | Testing and validation | Pending |
| 13 | Documentation | In progress |

## Layout

```
champollion-jit/
├── CMakeLists.txt              # C++20 / CMake build (primary implementation)
├── include/champollion/
│   ├── macho_loader.h          # Phase 1 — Mach-O parser (fat/thin, arm64 slice)
│   ├── arm64_decoder.h         # Phase 3 — ARM64 instruction decoder
│   ├── ir.h                    # Phase 4 — SSA IR, GuestContext, verifier
│   └── x64_backend.h           # Phase 6 — x64 codegen, exec arena
├── src/
│   ├── macho_loader.cpp
│   ├── arm64_decoder.cpp
│   ├── ir.cpp
│   ├── x64_backend.cpp
│   └── main.cpp
├── installer_app.py           # Cross-platform localhost installer server
├── installer_ui.html          # Browser-based installer wizard
├── test_installer_server.py    # Installer endpoint tests
├── run_tests.py                # Cross-platform test runner
└── proto/                      # Pure-stdlib Python reference implementation
│   ├── macho.py                #   Mach-O loader (mirrors the C++ module)
│   ├── arm64_decode.py         #   ARM64 decoder (mirrors the C++ module)
│   ├── aot_translator.py       #   Limited ARM64-to-x86-64 assembly translator
│   ├── demo.py                 #   Load a Mach-O and disassemble its entry point
│   ├── test_decoder.py         #   Decoder unit tests
│   ├── test_aot.py             #   AOT tests, including FAT Mach-O inputs
│   └── test_import.py          #   Module import / constant checks
```

The `proto/` package is a **line-by-line reference implementation** in Python
that runs anywhere (no toolchain required). It exists to (a) validate the
Mach-O layout and ARM64 encoding assumptions on real binaries, and (b) serve as
the specification to port into the C++ core.

## Building (C++)

Requires CMake ≥ 3.21 and a C++20 compiler (AppleClang/Xcode on macOS).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/bin/champollion-jit /path/to/arm64-binary
```

On Intel macOS the JIT will additionally need `MAP_JIT` (or
`pthread_jit_write_protect_np`) for the executable-memory arena, which
`x64_backend.cpp` currently stubs with a heap buffer.

On Windows, a user-scoped CMake, Ninja, and Zig toolchain can be installed with
`python -m pip install --user cmake ninja ziglang`. The installer discovers
these tools from the selected Python environment and uses them to configure,
build, and install the command-line target.

## Running the Python tools

```sh
python proto/demo.py /path/to/arm64-macho
```

### AOT Translation

The current AOT backend accepts little-endian ARM64 Mach-O executables,
including FAT32/FAT64 universal files, and emits x86-64 assembly for the
reachable function at its `LC_MAIN` entry:

```sh
python proto/aot_translator.py /path/to/arm64-executable /path/to/output.s
```

It supports a limited integer and local-branch subset. Calls, memory accesses,
SIMD, external branches, relocations, dyld, and framework integration are not
implemented. The output is one assembly function using a guest-register context
pointer, not a runnable translated app.

### Test suite

```sh
python3 run_tests.py
```

The runner executes five suites:
- `test_import.py` — verifies Mach-O constants import correctly
- `test_decoder.py` — 12 ARM64 decoder unit tests (control-flow instructions)
- `test_e2e.py` — builds a synthetic arm64 Mach-O, loads it, and decodes its entry point
- `test_aot.py` — translates supported ARM64 instructions and a synthetic Mach-O to x86-64 assembly
- `test_installer_server.py` — verifies installer selection, architecture detection, and AOT tasks


## Current limitations

- The ARM64 decoder currently recognizes the control-flow instructions needed
  to build a basic-block CFG (`b`, `b.cond`, `cbz`/`cbnz`, `tbz`/`tbnz`,
  `bl`, `br`, `blr`, `ret`) plus `movz`/`movk`/`movn` and `add`/`adds`/`subs`
  data processing. Load/store and SIMD&FP are recognised but not yet decoded
  into IR.
- `arm64e` PAC instructions are decoded as no-ops (per ToDo Phase 1); real
  pointer-authentication support is a later phase.
- The x64 backend allocates a heap arena rather than `MAP_JIT` memory and
  emits a stub `ret` — real codegen lands in Phase 6.

## Cross-platform installer

The installer UI uses HTML/CSS/JavaScript with a Python standard-library server,
and the native file chooser uses Tk. Start it with Python 3.10+ and Tk available:

```sh
python installer_app.py
```

Introduction accepts `.app`, `.pkg`, and `.dmg` installers and one destination
folder, defaulting to the user's `Applications/Champollion` directory. The
Computer Type step checks installer architectures: native `.app` bundles are
copied into the destination, native `.pkg`/`.dmg` files open with the system
installer, and non-native inputs continue to the AOT/JIT choice. AOT emits x86-64
assembly for a supported entry function; it is not a complete translated app.
The JIT option builds and installs the current C++ prototype; it does not yet
execute translated ARM64 apps. The server binds to `127.0.0.1` only.
