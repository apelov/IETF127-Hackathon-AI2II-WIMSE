"""Tests for the configurable inbound driver. Run: python -m unittest discover -s tests -v

Nothing here talks to Maurice or port 5050: the end-to-end test starts tests/stub_server.py on a
free port and runs the driver against it with --wire-only.
"""
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "peers"), str(ROOT / "tests")]
import driver  # noqa: E402
import stub_server  # noqa: E402

DEFAULT_URL = "http://maurice.ietf127.example:5050/api/v2/agents/dbsccjan18nkaiapu9v0/workflows/text-stats/executions"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_target(d, obj):
    p = pathlib.Path(d) / "t.json"
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj))
    return p


class LoaderTests(unittest.TestCase):
    def test_defaults_unchanged(self):
        t = driver.load_target()
        self.assertEqual(t["url"], DEFAULT_URL)
        self.assertEqual(t["audience"], "http://maurice.ietf127.example:5050")
        self.assertTrue(t["journal"])
        self.assertEqual((driver.URL, driver.AUD), (DEFAULT_URL, t["audience"]))

    def test_legacy_three_field_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = write_target(d, {"agent": "a", "workflow": "w", "base": "http://h:1"})
            t = driver.load_target(p)
        self.assertEqual(t["url"], "http://h:1/api/v2/agents/a/workflows/w/executions")
        self.assertEqual(t["audience"], "http://h:1")
        self.assertTrue(t["journal"])

    def test_custom_route_audience_journal(self):
        with tempfile.TemporaryDirectory() as d:
            p = write_target(d, {"base": "http://h:1", "route": "/v1/run", "audience": "https://svc.example", "journal": False})
            t = driver.load_target(p)
        self.assertEqual((t["url"], t["audience"], t["journal"]), ("http://h:1/v1/run", "https://svc.example", False))

    def test_cli_overrides_win(self):
        t = driver.load_target(base="http://x:2", route="/r/{agent}", agent="ag", journal=False)
        self.assertEqual((t["url"], t["journal"], t["audience"]), ("http://x:2/r/ag", False, "http://x:2"))

    def test_errors_are_clear(self):
        cases = {
            "{not json": "not valid JSON",
            "[]": "must be a JSON object",
            json.dumps({"agent": "a"}): "missing required field 'base'",
            json.dumps({"base": "https://h"}): "only http://",
            json.dumps({"base": "http://h/"}): "no path, trailing slash",
            json.dumps({"base": "http://h:1", "colour": 1}): "unknown field",
            json.dumps({"base": "http://h:1", "route": "v1"}): "must start with /",
            json.dumps({"base": "http://h:1"}): "uses {agent}",
            json.dumps({"base": "http://h:1", "route": "/x", "journal": "no"}): "true or false",
        }
        for text, want in cases.items():
            with self.subTest(want=want), tempfile.TemporaryDirectory() as d:
                p = write_target(d, text)
                with self.assertRaises(driver.TargetError) as cm:
                    driver.load_target(p)
                self.assertIn(want, str(cm.exception))

    def test_missing_file(self):
        with self.assertRaises(driver.TargetError):
            driver.load_target("/nonexistent/target.json")

    def test_comment_keys_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            p = write_target(d, {"_doc": "hi", "base": "http://h:1", "route": "/x"})
            self.assertEqual(driver.load_target(p)["url"], "http://h:1/x")

    def test_classification(self):
        for cid in ("IN6", "C12", "C12b", "A13i", "A13j", "IN15"):
            self.assertEqual(driver.classify(cid), "policy")
        self.assertEqual(driver.classify("A2"), "draft")
        self.assertTrue(set(driver.APPLICABILITY["policy"]) <= set(driver.CASES))


class StubEndToEnd(unittest.TestCase):
    def test_wire_only_run(self):
        port = free_port()
        srv = stub_server.make_server(port, f"http://127.0.0.1:{port}")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as d:
                t = write_target(d, {"base": f"http://127.0.0.1:{port}", "route": "/api/v2/agents/x/workflows/y/executions", "journal": False})
                proc = subprocess.run([sys.executable, str(ROOT / "peers/driver.py"), "--target", str(t)],
                                      capture_output=True, text=True, timeout=300)
        finally:
            srv.shutdown()
        out = proc.stdout
        passed = {line.split()[1] for line in out.splitlines() if line.startswith("CASE ") and " PASS " in line}
        for cid in ("A2", "A4", "A5", "A3", "A6a", "A13a", "IN10", "C2", "C3", "IN4"):
            self.assertIn(cid, passed, out)
        # no issuer allowlist in the stub: these must fail and be labelled as policy cases
        policy_line = next(x for x in out.splitlines() if x.startswith("BREAKDOWN"))
        self.assertIn("'C12'", policy_line.split("failed_needs_policy=")[1])
        self.assertIn("'IN6'", policy_line.split("failed_needs_policy=")[1])
        self.assertNotIn("CASE IN6 [IN-6] PASS", out)
        self.assertIn("SKIPPED decision-journal", out)
        self.assertEqual(proc.returncode, 1)


    def test_alternative_400_accepted_in_wire_only(self):
        port = free_port()
        srv = stub_server.make_server(port, f"http://127.0.0.1:{port}", status_400_only=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            proc = subprocess.run([sys.executable, str(ROOT / "peers/driver.py"), "--base", f"http://127.0.0.1:{port}",
                                   "--wire-only", "--cases", "A5"], capture_output=True, text=True, timeout=60)
        finally:
            srv.shutdown()
        self.assertIn("matched=alternative(400 wimse-signature-invalid, http-signature-08) ok", proc.stdout)
        self.assertEqual(proc.returncode, 0)

    def test_primary_401_reported(self):
        port = free_port()
        srv = stub_server.make_server(port, f"http://127.0.0.1:{port}")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            proc = subprocess.run([sys.executable, str(ROOT / "peers/driver.py"), "--base", f"http://127.0.0.1:{port}",
                                   "--wire-only", "--cases", "A5"], capture_output=True, text=True, timeout=60)
        finally:
            srv.shutdown()
        self.assertIn("matched=primary(401, wpt-02) ok", proc.stdout)
        self.assertIn("CLASS A5 draft (wpt-02 SHOULD 401; conflicts with http-signature-08", proc.stdout)

    def test_only_draft_skips_policy_cases(self):
        port = free_port()
        srv = stub_server.make_server(port, f"http://127.0.0.1:{port}")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            proc = subprocess.run([sys.executable, str(ROOT / "peers/driver.py"), "--base", f"http://127.0.0.1:{port}",
                                   "--wire-only", "--only", "draft", "--cases", "A2,IN6,IN15,A5"], capture_output=True, text=True, timeout=60)
        finally:
            srv.shutdown()
        self.assertIn("SUMMARY total=2 failed=0", proc.stdout)
        self.assertNotIn("CASE IN6", proc.stdout)


if __name__ == "__main__":
    unittest.main()
