"""
IPA support for the Champollion installer.

Pipeline: unpack -> inspect (Info.plist, Mach-O slices, encryption, frameworks)
-> preflight report -> attempt AOT translation of the main executable.

What this does NOT do: decrypt FairPlay-protected apps (they are refused), or
produce a launchable Mac app. The translator emits assembly for one supported
function today; it cannot yet build a complete app (no libSystem/dyld/Objective-C
runtime). install_ipa() therefore reports exactly what happened and never claims
an app was installed.

Python 3.8 compatible (macOS 11 command line tools ship 3.8).
"""
from __future__ import annotations

import json
import os
import plistlib
import shutil
import struct
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

try:
    from .aot_translator import TranslationError, translate_macho
except ImportError:  # run as a script from proto/
    from aot_translator import TranslationError, translate_macho

MIN_MACOS = "11.0"

FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
MH_MAGIC, MH_MAGIC_64 = 0xFEEDFACE, 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64E = 2
LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64 = 0x21, 0x2C
DYLIB_CMDS = {0xC, 0x80000018, 0x8000001F, 0x80000023}

# Frameworks the translator/runtime cannot provide; extend as support grows.
RISKY_FRAMEWORKS = {"ARKit", "HealthKit", "HomeKit", "CarPlay", "RealityKit",
                    "CallKit", "PassKit", "NetworkExtension", "UIKit", "SpriteKit"}


class IPAError(Exception):
    """The IPA cannot be processed (bad archive, encrypted, wrong architecture...)."""


@dataclass
class BinaryInfo:
    path: Path
    arm64: bool = False
    arm64e: bool = False
    encrypted: bool = False
    frameworks: set = field(default_factory=set)


@dataclass
class IPAInfo:
    app_dir: Path
    work_dir: Path
    bundle_id: str
    name: str
    version: str
    min_ios: str
    executable: str
    main: BinaryInfo
    embedded: List[BinaryInfo] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def cleanup(self) -> None:
        shutil.rmtree(self.work_dir, ignore_errors=True)


# ---- Mach-O inspection ------------------------------------------------------
def _slices(data: bytes):
    """Yield (cputype, cpusubtype, offset) for each architecture slice."""
    if len(data) < 8:
        return
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        count = struct.unpack(">I", data[4:8])[0]
        pos = 8
        for _ in range(min(count, 64)):
            if magic == FAT_MAGIC:
                if pos + 20 > len(data):
                    return
                ct, st, off, _sz, _al = struct.unpack(">iiIII", data[pos:pos + 20])
                pos += 20
            else:
                if pos + 32 > len(data):
                    return
                ct, st, off, _sz, _al, _r = struct.unpack(">iiQQII", data[pos:pos + 32])
                pos += 32
            yield ct & 0xFFFFFFFF, st & 0xFFFFFF, off
    elif struct.unpack("<I", data[:4])[0] in (MH_MAGIC, MH_MAGIC_64):
        ct, st = struct.unpack("<ii", data[4:12])
        yield ct & 0xFFFFFFFF, st & 0xFFFFFF, 0


def is_macho(path: Path) -> bool:
    try:
        with open(str(path), "rb") as f:
            return f.read(4) in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf",
                                 b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
    except OSError:
        return False


def inspect_macho(path: Path) -> BinaryInfo:
    info = BinaryInfo(path=path)
    data = path.read_bytes()
    for cputype, subtype, base in _slices(data):
        if cputype != CPU_TYPE_ARM64 or base + 32 > len(data):
            continue
        info.arm64 = True
        info.arm64e = info.arm64e or subtype == CPU_SUBTYPE_ARM64E
        magic = struct.unpack("<I", data[base:base + 4])[0]
        hdr = 32 if magic == MH_MAGIC_64 else 28
        ncmds = struct.unpack("<I", data[base + 16:base + 20])[0]
        pos = base + hdr
        for _ in range(ncmds):
            if pos + 8 > len(data):
                break
            cmd, size = struct.unpack("<II", data[pos:pos + 8])
            if size < 8 or pos + size > len(data):
                break
            if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64) and size >= 20:
                if struct.unpack("<I", data[pos + 16:pos + 20])[0] != 0:
                    info.encrypted = True
            elif cmd in DYLIB_CMDS and size >= 12:
                name_off = struct.unpack("<I", data[pos + 8:pos + 12])[0]
                raw = data[pos + name_off:pos + size].split(b"\0", 1)[0].decode(errors="replace")
                if "/System/Library/Frameworks/" in raw:
                    info.frameworks.add(raw.split("/Frameworks/")[1].split(".framework")[0])
            pos += size
    return info


# ---- unpack + inspect -------------------------------------------------------
def unpack_ipa(ipa_path: str, work: Path) -> Path:
    try:
        with zipfile.ZipFile(ipa_path) as z:
            root = os.path.realpath(str(work))
            for member in z.namelist():              # zip-slip guard
                target = os.path.realpath(os.path.join(root, member))
                if os.path.commonpath([root, target]) != root:
                    raise IPAError("Unsafe path in archive: %s" % member)
            z.extractall(str(work))
    except zipfile.BadZipFile:
        raise IPAError("Not a valid .ipa (zip) file.")
    apps = sorted((work / "Payload").glob("*.app")) if (work / "Payload").is_dir() else []
    if not apps:
        raise IPAError("No .app bundle found inside Payload/.")
    return apps[0]


def inspect_ipa(ipa_path: str) -> IPAInfo:
    """Unpack and inspect. The caller owns the temp dir and must call info.cleanup()."""
    work = Path(tempfile.mkdtemp(prefix="champollion_ipa_"))
    try:
        app = unpack_ipa(ipa_path, work)
        try:
            plist = plistlib.loads((app / "Info.plist").read_bytes())
        except (OSError, plistlib.InvalidFileException, ValueError):
            raise IPAError("Info.plist is missing or unreadable.")
        exe = plist.get("CFBundleExecutable")
        if not exe or not (app / exe).is_file():
            raise IPAError("The app's main executable was not found.")

        main = inspect_macho(app / exe)
        info = IPAInfo(
            app_dir=app, work_dir=work,
            bundle_id=plist.get("CFBundleIdentifier", "unknown"),
            name=plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or app.stem,
            version=str(plist.get("CFBundleShortVersionString", "?")),
            min_ios=str(plist.get("MinimumOSVersion", "?")),
            executable=exe, main=main)
        fw_dir = app / "Frameworks"
        if fw_dir.is_dir():
            for p in sorted(fw_dir.rglob("*")):
                if p.is_file() and not p.is_symlink() and is_macho(p):
                    info.embedded.append(inspect_macho(p))
        everything = [info.main] + info.embedded

        if not main.arm64:
            raise IPAError("No arm64 slice found; only arm64 apps can be translated.")
        if any(b.encrypted for b in everything):
            raise IPAError("This app is encrypted (FairPlay) and can only be installed from a "
                           "source that provides a decrypted build. Champollion does not "
                           "remove app protection.")
        if any(b.arm64e for b in everything):
            info.warnings.append("Uses arm64e (pointer authentication); translation may be unreliable.")
        risky = set()
        for b in everything:
            risky |= (b.frameworks & RISKY_FRAMEWORKS)
        if risky:
            info.warnings.append("Links frameworks that are not available on macOS translation yet: "
                                 + ", ".join(sorted(risky)))
        info.warnings.append("iOS apps need UIKit and the iOS runtime, which Champollion does not "
                             "provide yet; a translated app will not launch as a Mac app.")
        return info
    except Exception:
        shutil.rmtree(str(work), ignore_errors=True)
        raise


def preflight_summary(info: IPAInfo) -> str:
    lines = ["%s (%s) v%s" % (info.name, info.bundle_id, info.version),
             "Minimum iOS: %s" % info.min_ios,
             "Architecture: arm64%s" % (" (arm64e)" if info.main.arm64e else ""),
             "Embedded binaries: %d" % len(info.embedded)]
    lines += ["Warning: " + w for w in info.warnings]
    return "\n".join(lines)


# ---- install ----------------------------------------------------------------
def _safe_name(name: str) -> str:
    cleaned = "".join(c if (c.isalnum() or c in "-_. ") else "_" for c in name).strip(" .")
    return cleaned or "app"


def install_ipa(ipa_path: str, destination: str,
                progress: Optional[Callable[[float, str], None]] = None) -> dict:
    """
    Inspect the IPA and try to translate its main executable.

    Returns {"ok": bool, "installed": False, "artifact": path-or-None, "report": path,
             "message": str, "warnings": [...]}.
    Raises IPAError for archives that cannot be processed at all.
    """
    def tick(fraction: float, text: str) -> None:
        if progress:
            progress(fraction, text)

    tick(0.05, "Unpacking IPA")
    info = inspect_ipa(ipa_path)
    try:
        tick(0.3, "Inspecting app")
        out_dir = Path(destination)
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = _safe_name(info.name)
        report_path = out_dir / ("%s_ipa_report.json" % stem)
        artifact = out_dir / ("%s_x86_64.s" % stem)

        report = {
            "name": info.name, "bundle_id": info.bundle_id, "version": info.version,
            "min_ios": info.min_ios, "min_macos_target": MIN_MACOS,
            "executable": info.executable, "arm64e": info.main.arm64e,
            "frameworks": sorted(info.main.frameworks),
            "embedded_binaries": len(info.embedded), "warnings": info.warnings,
        }

        tick(0.5, "Translating main executable")
        try:
            translate_macho(info.main.path, artifact)
            ok, installed = True, False
            message = ("Translated the app's entry code to x86-64 assembly at %s. It assumes the "
                       "app's memory is mapped at its original addresses and needs a loader and "
                       "runtime that do not exist yet, so this is not a runnable Mac app." % artifact)
            report["translation"] = {"status": "assembly_only", "artifact": str(artifact)}
        except (TranslationError, ValueError, OSError, struct.error) as exc:
            ok, installed, artifact = False, False, None
            message = ("The app was not installed: its code uses features the translator does "
                       "not support yet (%s)." % exc)
            report["translation"] = {"status": "unsupported", "reason": str(exc)}

        report["installed"] = installed
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        tick(1.0, "Done")
        return {"ok": ok, "installed": installed,
                "artifact": str(artifact) if artifact else None,
                "report": str(report_path), "message": message, "warnings": info.warnings}
    finally:
        info.cleanup()
