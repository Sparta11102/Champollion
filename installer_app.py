#!/usr/bin/env python3
"""
Champollion installer backend.

* A local HTTP server bound to 127.0.0.1 (used by the browser UI and tests), and
* run_install(), the shared install routine that the native Swift app also calls
  through champollion_cli.py.

Modes: native (copy .app / open .pkg,.dmg), aot (emit x86-64 assembly), jit (build the
champollion-jit tool with CMake), ipa (inspect an .ipa and try to translate it).

Python 3.8 compatible (macOS 11 command line tools ship 3.8).
"""
from __future__ import annotations

import argparse
import json
import platform
import plistlib
import shutil
import subprocess
import sys
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, List, Optional

PROJECT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_DIR))

from proto.aot_translator import TranslationError, translate_macho  # noqa: E402
from proto.ipa import IPAError, inspect_ipa, install_ipa  # noqa: E402
from proto.macho import CPU_TYPE_ARM64, load_macho  # noqa: E402

CPU_TYPE_X86_64 = 0x01000007
MIN_MACOS = "11.0"
MODES = ("native", "aot", "jit", "ipa")
ARCH_NAMES = {CPU_TYPE_ARM64: "arm64", CPU_TYPE_X86_64: "x86_64"}

Progress = Callable[[float, str], None]


class InstallError(Exception):
    pass


# ---------------------------------------------------------------- host / detect
def host_architecture() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    return machine


def _macho_architectures(path: Path) -> List[str]:
    """Architecture names in a Mach-O file (thin or universal); [] if it is not one."""
    try:
        image = load_macho(str(path))
    except Exception:  # noqa: BLE001 - any parse failure means "not Mach-O"
        return []
    name = ARCH_NAMES.get(image.cputype)
    return [name] if name else []


def find_app_executable(bundle: Path) -> Optional[Path]:
    macos_dir = bundle / "Contents" / "MacOS"
    if not macos_dir.is_dir():
        return None
    try:
        info = plistlib.loads((bundle / "Contents" / "Info.plist").read_bytes())
        named = macos_dir / info.get("CFBundleExecutable", "")
        if named.is_file():
            return named
    except (OSError, ValueError, plistlib.InvalidFileException):
        pass
    files = sorted(p for p in macos_dir.iterdir() if p.is_file())
    return files[0] if files else None


def _is_native(host: str, archs: List[str]) -> bool:
    if not archs:
        return False
    return host in archs or (host == "arm64" and "x86_64" in archs)  # Rosetta 2 covers x86_64


def detect_installer(path) -> dict:
    p = Path(path)
    suffix = p.suffix.lower()
    host = host_architecture()
    result = {"path": str(p), "host_architecture": host, "architectures": [], "native": False}
    if suffix == ".app" or p.is_dir():
        result["format"] = "APP"
        exe = find_app_executable(p)
        if exe is not None:
            result["architectures"] = _macho_architectures(exe)
            result["executable"] = str(exe)
        result["native"] = _is_native(host, result["architectures"])
    elif suffix in (".pkg", ".dmg"):
        result["format"] = suffix[1:].upper()
        # The system installer opens these on macOS; contents are not inspected here.
        result["native"] = platform.system() == "Darwin"
    elif suffix == ".ipa":
        result["format"] = "IPA"
        try:
            info = inspect_ipa(str(p))
            try:
                result["architectures"] = ["arm64"] if info.main.arm64 else []
                result["bundle_id"] = info.bundle_id
                result["name"] = info.name
                result["warnings"] = list(info.warnings)
            finally:
                info.cleanup()
        except IPAError as exc:
            result["error"] = str(exc)
    else:
        result["format"] = "MACHO" if _macho_architectures(p) else "UNKNOWN"
        result["architectures"] = _macho_architectures(p)
        result["native"] = _is_native(host, result["architectures"])
    return result


def browse_for_installer() -> str:
    """Native file chooser. Returns '' when cancelled or unavailable."""
    if platform.system() == "Darwin":
        script = ('POSIX path of (choose file with prompt "Choose an app, installer or IPA" '
                  'of type {"app", "pkg", "dmg", "ipa", "public.item"})')
        try:
            out = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=300)
            return out.stdout.strip() if out.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""
    try:
        import tkinter
        from tkinter import filedialog
        root = tkinter.Tk()
        root.withdraw()
        chosen = filedialog.askopenfilename(title="Choose an app, installer or IPA")
        root.destroy()
        return chosen or ""
    except Exception:  # noqa: BLE001 - no display / no Tk
        return ""


def status() -> dict:
    return {"host": {"system": platform.system(), "machine": platform.machine(),
                     "architecture": host_architecture(), "python": platform.python_version()},
            "min_macos": MIN_MACOS,
            "home": str(Path.home()),
            "aot_available": True,
            "ipa_available": True,
            "jit_available": bool(shutil.which("cmake")) and bool(shutil.which("c++") or shutil.which("clang++")),
            "tools": {"cmake": shutil.which("cmake"), "compiler": shutil.which("c++") or shutil.which("clang++")}}


# ---------------------------------------------------------------- request validation
def validate_request(body: dict) -> dict:
    mode = body.get("mode")
    if mode not in MODES:
        raise ValueError("mode must be one of: %s." % ", ".join(MODES))
    destination = str(body.get("destination", ""))
    if not destination or not Path(destination).is_absolute():
        raise ValueError("destination must be an absolute path.")
    source = str(body.get("input", ""))
    if mode == "aot":
        if not source or not Path(source).exists():
            raise ValueError("AOT mode needs an existing .app bundle or ARM64 Mach-O file.")
    elif mode == "native":
        if not source or not Path(source).exists():
            raise ValueError("Native install needs an existing .app, .pkg or .dmg.")
    elif mode == "ipa":
        if not source.lower().endswith(".ipa") or not Path(source).is_file():
            raise ValueError("IPA mode needs an existing .ipa file.")
    return {"mode": mode, "input": source, "destination": destination}


# ---------------------------------------------------------------- install routines
def _resolve_macho(source: Path) -> Path:
    if source.is_dir():
        exe = find_app_executable(source)
        if exe is None:
            raise InstallError("No executable found in %s/Contents/MacOS." % source.name)
        return exe
    return source


def _install_native(source: Path, destination: Path, progress: Progress) -> dict:
    detected = detect_installer(source)
    if not detected.get("native"):
        raise InstallError("This installer is not native to this Mac; choose AOT or JIT instead.")
    if source.suffix.lower() == ".app" or source.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        target = destination / source.name
        progress(0.3, "Copying %s" % source.name)
        if target.exists():
            shutil.rmtree(str(target))
        shutil.copytree(str(source), str(target), symlinks=True)
        return {"message": "Copied %s to %s." % (source.name, destination), "artifact": str(target)}
    if platform.system() == "Darwin":
        subprocess.run(["open", str(source)], check=True)
        return {"message": "Opened %s with the system installer." % source.name, "artifact": str(source)}
    raise InstallError(".pkg and .dmg files can only be opened on macOS.")


def _install_aot(source: Path, destination: Path, progress: Progress) -> dict:
    macho = _resolve_macho(source)
    stem = source.stem if source.suffix else source.name
    artifact = destination / ("%s_x86_64.s" % stem)
    progress(0.4, "Translating %s" % macho.name)
    try:
        translate_macho(macho, artifact)
    except (TranslationError, ValueError, OSError) as exc:
        raise InstallError("Translation failed: %s" % exc)
    return {"message": "Wrote x86-64 assembly for the code reachable from the entry point. It "
                       "assumes the app's memory is mapped at its original addresses and needs a "
                       "loader and runtime that do not exist yet; it is not a runnable app.",
            "artifact": str(artifact)}


def _install_jit(destination: Path, progress: Progress) -> dict:
    cmake = shutil.which("cmake")
    if not cmake:
        raise InstallError("CMake is required to build the JIT tool (install it, then retry).")
    build = Path.home() / ".champollion" / "build"   # never inside the (possibly signed) app bundle
    if not (PROJECT_DIR / "CMakeLists.txt").is_file():
        raise InstallError("The JIT sources are not part of this installation.")
    build.mkdir(parents=True, exist_ok=True)
    steps = [("Configuring", [cmake, "-S", str(PROJECT_DIR), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release"]),
             ("Building", [cmake, "--build", str(build), "--parallel"])]
    for index, (label, command) in enumerate(steps):
        progress(0.1 + 0.4 * index, label)
        out = subprocess.run(command, capture_output=True, text=True)
        if out.returncode != 0:
            tail = (out.stdout + out.stderr).strip().splitlines()[-12:]
            raise InstallError("%s failed:\n%s" % (label, "\n".join(tail)))
    tool = build / "bin" / "champollion-jit"
    if not tool.is_file():
        raise InstallError("Build finished but champollion-jit was not produced.")
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / "champollion-jit"
    shutil.copy2(str(tool), str(target))
    return {"message": "Built champollion-jit. It compiles simple integer functions only; "
                       "it cannot run full apps yet.", "artifact": str(target)}


def run_install(request: dict, progress: Progress = lambda fraction, text: None) -> dict:
    """Run one validated install request. Returns a result dict or raises InstallError."""
    mode, destination = request["mode"], Path(request["destination"])
    source = Path(request["input"]) if request.get("input") else None
    if mode == "native":
        return _install_native(source, destination, progress)
    if mode == "aot":
        return _install_aot(source, destination, progress)
    if mode == "jit":
        return _install_jit(destination, progress)
    if mode == "ipa":
        try:
            result = install_ipa(str(source), str(destination), progress)
        except IPAError as exc:
            raise InstallError(str(exc))
        if not result["ok"]:
            raise InstallError(result["message"])
        return {"message": result["message"], "artifact": result["artifact"], "report": result["report"],
                "warnings": result["warnings"]}
    raise InstallError("Unknown mode.")


# ---------------------------------------------------------------- tasks + HTTP
_tasks: Dict[str, dict] = {}
_tasks_lock = threading.Lock()


def _update_task(task_id: str, **fields) -> None:
    with _tasks_lock:
        _tasks[task_id].update(fields)


def start_task(request: dict) -> str:
    task_id = uuid.uuid4().hex[:12]
    with _tasks_lock:
        _tasks[task_id] = {"state": "running", "progress": 0.0, "message": "Starting", "artifact": None}

    def work() -> None:
        def progress(fraction: float, text: str) -> None:
            _update_task(task_id, progress=fraction, message=text)
        try:
            result = run_install(request, progress)
            _update_task(task_id, state="complete", progress=1.0, **result)
        except InstallError as exc:
            _update_task(task_id, state="error", message=str(exc))
        except Exception as exc:  # noqa: BLE001 - never leave a task stuck in "running"
            _update_task(task_id, state="error", message="Unexpected error: %s" % exc)

    threading.Thread(target=work, daemon=True).start()
    return task_id


class InstallerHandler(BaseHTTPRequestHandler):
    server_version = "ChampollionInstaller/0.2"

    def log_message(self, fmt, *args):  # quiet
        pass

    def _send(self, code: int, payload, content_type="application/json") -> None:
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ValueError("Request body must be JSON.")
        if not isinstance(body, dict):
            raise ValueError("Request body must be a JSON object.")
        return body

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            page = PROJECT_DIR / "installer_ui.html"
            if page.is_file():
                return self._send(200, page.read_bytes(), "text/html; charset=utf-8")
            return self._send(404, {"error": "installer_ui.html is missing."})
        if self.path == "/api/status":
            return self._send(200, status())
        if self.path.startswith("/api/tasks/"):
            with _tasks_lock:
                task = dict(_tasks.get(self.path.rsplit("/", 1)[1], {}))
            if not task:
                return self._send(404, {"error": "Unknown task."})
            return self._send(200, task)
        self._send(404, {"error": "Not found."})

    def do_POST(self):
        try:
            body = self._body()
            if self.path == "/api/select-installer":
                return self._send(200, {"path": browse_for_installer()})
            if self.path == "/api/detect":
                path = str(body.get("path", ""))
                if not path or not Path(path).exists():
                    raise ValueError("path must point to an existing file or bundle.")
                return self._send(200, detect_installer(path))
            if self.path == "/api/install":
                return self._send(200, {"task_id": start_task(validate_request(body))})
            self._send(404, {"error": "Not found."})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Champollion installer (local web UI)")
    parser.add_argument("--port", type=int, default=0, help="port (default: any free port)")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), InstallerHandler)
    url = "http://127.0.0.1:%d/" % server.server_port
    print("Champollion installer listening on %s (Ctrl+C to stop)" % url, flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
