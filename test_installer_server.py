import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from installer_app import InstallerHandler, detect_installer
from proto.test_aot import write_synthetic_macho


class InstallerServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), InstallerHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_status_marks_limited_aot_available(self):
        with urlopen(f"{self.base_url}/api/status") as response:
            status = json.load(response)
        self.assertTrue(status["aot_available"])
        self.assertIn("host", status)

    def test_aot_requires_existing_macho_input(self):
        request = Request(
            f"{self.base_url}/api/install",
            data=json.dumps({
                "mode": "aot",
                "input": "missing-arm64-binary",
                "destination": "/tmp/champollion.s",
            }).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request)
        self.assertEqual(raised.exception.code, 400)
        with raised.exception as error_response:
            response = json.load(error_response)
        self.assertIn("existing .app bundle or ARM64 Mach-O file", response["error"])

    def test_relative_destination_is_rejected(self):
        request = Request(
            f"{self.base_url}/api/install",
            data=json.dumps({"mode": "jit", "destination": "relative/path"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request)
        self.assertEqual(raised.exception.code, 400)
        with raised.exception as error_response:
            response = json.load(error_response)
        self.assertIn("absolute path", response["error"])

    def test_select_installer_returns_picked_bundle(self):
        request = Request(f"{self.base_url}/api/select-installer", data=b"", method="POST")
        with patch("installer_app.browse_for_installer", return_value="C:/Apps/Test.app") as picker:
            with urlopen(request) as response:
                result = json.load(response)
        self.assertEqual(result["path"], "C:/Apps/Test.app")
        picker.assert_called_once_with()

    def test_detect_reports_architecture_from_app_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Test.app"
            executable_dir = bundle / "Contents" / "MacOS"
            executable_dir.mkdir(parents=True)
            write_synthetic_macho(executable_dir / "Test")
            result = detect_installer(bundle)
        self.assertEqual(result["format"], "APP")
        self.assertEqual(result["architectures"], ["arm64"])
        self.assertIn("host_architecture", result)

    def test_pkg_and_dmg_are_supported_detection_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            for suffix in (".pkg", ".dmg"):
                path = Path(directory) / f"Installer{suffix}"
                path.write_bytes(b"container")
                with patch("installer_app.platform.system", return_value="Windows"):
                    result = detect_installer(path)
                self.assertEqual(result["format"], suffix[1:].upper())
                self.assertFalse(result["native"])

    def test_native_app_install_copies_to_the_one_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "Native.app"
            contents = app / "Contents" / "MacOS"
            contents.mkdir(parents=True)
            (contents / "Native").write_text("app binary", encoding="utf-8")
            destination = Path(directory) / "Applications"
            request = Request(
                f"{self.base_url}/api/install",
                data=json.dumps({
                    "mode": "native",
                    "input": str(app),
                    "destination": str(destination),
                }).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with patch("installer_app.detect_installer", return_value={"native": True}):
                with urlopen(request) as response:
                    task_id = json.load(response)["task_id"]

            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with urlopen(f"{self.base_url}/api/tasks/{task_id}") as response:
                    task = json.load(response)
                if task["state"] in ("complete", "error"):
                    break
                time.sleep(0.02)

            copied_binary = destination / "Native.app" / "Contents" / "MacOS" / "Native"
            self.assertEqual(task["state"], "complete", task.get("message"))
            self.assertTrue(copied_binary.is_file())

    def test_aot_request_writes_assembly_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "arm64-test"
            destination = Path(directory) / "output"
            artifact = destination / "arm64-test_x86_64.s"
            write_synthetic_macho(source)
            request = Request(
                f"{self.base_url}/api/install",
                data=json.dumps({
                    "mode": "aot",
                    "input": str(source),
                    "destination": str(destination),
                }).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request) as response:
                task_id = json.load(response)["task_id"]

            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with urlopen(f"{self.base_url}/api/tasks/{task_id}") as response:
                    task = json.load(response)
                if task["state"] in ("complete", "error"):
                    break
                time.sleep(0.02)

            self.assertEqual(task["state"], "complete", task.get("message"))
            self.assertEqual(task["artifact"], str(artifact))
            self.assertIn("_champollion_aot_entry", artifact.read_text(encoding="utf-8"))

    def test_aot_request_accepts_app_bundle_and_uses_chosen_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "SmokeApp.app"
            executable = app / "Contents" / "MacOS" / "SmokeApp"
            executable.parent.mkdir(parents=True)
            write_synthetic_macho(executable)
            destination = Path(directory) / "Applications"
            artifact = destination / "SmokeApp_x86_64.s"
            request = Request(
                f"{self.base_url}/api/install",
                data=json.dumps({
                    "mode": "aot",
                    "input": str(app),
                    "destination": str(destination),
                }).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request) as response:
                task_id = json.load(response)["task_id"]

            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with urlopen(f"{self.base_url}/api/tasks/{task_id}") as response:
                    task = json.load(response)
                if task["state"] in ("complete", "error"):
                    break
                time.sleep(0.02)

            self.assertEqual(task["state"], "complete", task.get("message"))
            self.assertEqual(task["artifact"], str(artifact))
            self.assertTrue(artifact.is_file())


if __name__ == "__main__":
    unittest.main()