# Champollion Installer (native macOS app)

SwiftUI installer wizard for **macOS 11 (Big Sur) and later**. It does no translation itself:
it runs the Python backend (`../champollion_cli.py`) and shows its progress and result.

## Build

    ./build_app.sh                 # build/ChampollionInstaller.app (current architecture)
    UNIVERSAL=1 ./build_app.sh     # arm64 + x86_64 (Xcode 13+)
    swift test                     # unit tests for the CLI protocol (ChampollionCore)

Needs the Xcode Command Line Tools (`xcode-select --install`), which also provide Python 3.8+
at `/usr/bin/python3`. For the JIT option, also install CMake.

During development you can run the wizard straight from the source tree with `swift run`;
the app finds `../champollion_cli.py` automatically, or set `CHAMPOLLION_BACKEND=/path/to/champollion`.

## Targets

| Target | Purpose |
|---|---|
| `ChampollionCore` | CLI event parsing, backend lookup and process runner (unit-tested) |
| `ChampollionInstaller` | SwiftUI wizard |

## Notes

* Output is written to `~/Applications/Champollion` (no admin rights needed).
* IPA files skip the translation-mode step and use the IPA pipeline.
* The Swift code was written without access to a Mac here, so it has **not been compiled or run**.
  Build it first and report any compiler errors.
