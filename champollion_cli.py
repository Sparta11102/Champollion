#!/usr/bin/env python3
"""
Command-line front end used by the native Swift installer.

  champollion_cli.py status
  champollion_cli.py detect <path>
  champollion_cli.py install --mode {native,aot,jit,ipa} --input <path> --destination <abs dir>

Every output line is one JSON object. install emits {"event":"progress",...} lines and
ends with exactly one {"event":"result",...} (exit 0) or {"event":"error",...} (exit 1).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_app  # noqa: E402


def emit(**fields) -> None:
    print(json.dumps(fields), flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    detect = sub.add_parser("detect")
    detect.add_argument("path")
    install = sub.add_parser("install")
    install.add_argument("--mode", required=True)
    install.add_argument("--input", default="")
    install.add_argument("--destination", required=True)
    args = parser.parse_args(argv)

    if args.command == "status":
        emit(event="result", **installer_app.status())
        return 0
    if args.command == "detect":
        if not Path(args.path).exists():
            emit(event="error", message="Path does not exist: %s" % args.path)
            return 1
        emit(event="result", **installer_app.detect_installer(args.path))
        return 0

    try:
        request = installer_app.validate_request(
            {"mode": args.mode, "input": args.input, "destination": args.destination})
        result = installer_app.run_install(
            request, lambda fraction, text: emit(event="progress", fraction=fraction, text=text))
    except ValueError as exc:
        emit(event="error", message=str(exc))
        return 1
    except installer_app.InstallError as exc:
        emit(event="error", message=str(exc))
        return 1
    emit(event="result", **result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
