"""IPA mode through the HTTP API and the CLI used by the Swift app."""
import io
import json
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import champollion_cli
from installer_app import InstallerHandler
from proto.test_ipa import GOOD, make_ipa, make_macho


def post(base, path, body):
    req = Request(base + path, data=json.dumps(body).encode(),
                  headers={"Content-Type": "application/json"}, method="POST")
    return json.load(urlopen(req))


def wait(base, task_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        task = json.load(urlopen("%s/api/tasks/%s" % (base, task_id)))
        if task["state"] in ("complete", "error"):
            return task
        time.sleep(0.02)
    raise AssertionError("task did not finish")


class IPAInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), InstallerHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_ipa_mode_requires_an_ipa_file(self):
        with self.assertRaises(HTTPError) as cm:
            post(self.base, "/api/install", {"mode": "ipa", "input": "/nope.txt", "destination": "/tmp/x"})
        self.assertEqual(cm.exception.code, 400)
        self.assertIn(".ipa", json.load(cm.exception)["error"])

    def test_ipa_api_translates_and_reports_not_installed(self):
        with tempfile.TemporaryDirectory() as d:
            ipa = Path(d) / "t.ipa"
            make_ipa(ipa, make_macho(GOOD))
            tid = post(self.base, "/api/install", {"mode": "ipa", "input": str(ipa),
                                                  "destination": str(Path(d) / "out")})["task_id"]
            task = wait(self.base, tid)
            self.assertEqual(task["state"], "complete", task.get("message"))
            self.assertTrue(Path(task["artifact"]).is_file())
            self.assertTrue(Path(task["report"]).is_file())

    def test_encrypted_ipa_ends_in_error_state(self):
        with tempfile.TemporaryDirectory() as d:
            ipa = Path(d) / "enc.ipa"
            make_ipa(ipa, make_macho(GOOD, encrypted=True))
            tid = post(self.base, "/api/install", {"mode": "ipa", "input": str(ipa),
                                                  "destination": str(Path(d) / "out")})["task_id"]
            task = wait(self.base, tid)
            self.assertEqual(task["state"], "error")
            self.assertIn("encrypted", task["message"])

    def test_detect_reports_ipa_details(self):
        with tempfile.TemporaryDirectory() as d:
            ipa = Path(d) / "t.ipa"
            make_ipa(ipa, make_macho(GOOD))
            info = post(self.base, "/api/detect", {"path": str(ipa)})
            self.assertEqual(info["format"], "IPA")
            self.assertEqual(info["architectures"], ["arm64"])
            self.assertEqual(info["bundle_id"], "com.example.test")
            self.assertFalse(info["native"])


class CLITests(unittest.TestCase):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = champollion_cli.main(list(argv))
        return code, [json.loads(line) for line in buf.getvalue().splitlines()]

    def test_install_emits_progress_then_one_result(self):
        with tempfile.TemporaryDirectory() as d:
            ipa = Path(d) / "t.ipa"
            make_ipa(ipa, make_macho(GOOD))
            code, events = self.run_cli("install", "--mode", "ipa", "--input", str(ipa),
                                        "--destination", str(Path(d) / "out"))
        self.assertEqual(code, 0)
        self.assertEqual(events[-1]["event"], "result")
        self.assertTrue(any(e["event"] == "progress" for e in events[:-1]))

    def test_errors_exit_nonzero_with_error_event(self):
        code, events = self.run_cli("install", "--mode", "ipa", "--input", "/missing.ipa",
                                    "--destination", "/tmp/out")
        self.assertEqual(code, 1)
        self.assertEqual(events[-1]["event"], "error")

    def test_detect_unknown_path(self):
        code, events = self.run_cli("detect", "/definitely/missing")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
