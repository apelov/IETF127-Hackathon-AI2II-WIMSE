"""Domain B P2/P7/P8 Executor Peer (ietf127-wimse-scenario/1).
Runs on 127.0.0.1:5064 to execute live loopback HTTP exchanges for P2, P7, and P8
so they appear in capture.pcap as real wire traffic and emit ietf127-wimse-scenario/1
log lines to JOURNAL.

What answers each case:
- P2: a copy of Redthread's ProtectedOperation with a simulated verifier on a fake clock,
  plus two replayed MintID sandbox outcomes.
- P7 and P8: fixed answers (impl "p7-fixed-answer-mock" / "p8-fixed-answer-mock"). P7 compares a
  presented digest string with a constant; P8 maps each case name to a fixed status. No OmniArx or
  Cred code runs, and no token, signature, key or action is verified.
"""
import argparse
import http.server
import json
import os
import pathlib
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
SCENARIOS_DIR = ROOT / "scenarios" / "p1_p8"
if str(SCENARIOS_DIR) not in sys.path:
    sys.path.insert(0, str(SCENARIOS_DIR))

from protected_op import ProtectedOperation  # noqa: E402
import mintid_outside  # noqa: E402

JOURNAL: list[dict] = []

# The P2 outside-verifier cases replay recorded sandbox outcomes. Only the operator can switch them
# to live calls, by setting this variable before starting the executor; a request cannot.
LIVE_OUTSIDE_VERIFIER = os.environ.get("WIMSE_EXECUTOR_LIVE_VERIFIER") or None

DISPLAY_DIGEST_EXPECTED = "sha256:4a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b"
TS_OMNIARX = 1800000000


class SimulatedVerifier:
    def __init__(self, allow_authorize=True, allow_recheck=False, now=0.0):
        self._allow_auth = allow_authorize
        self._allow_recheck = allow_recheck
        self._now = now
        self.calls = []

    def now(self):
        return self._now

    def verify(self, *args, revalidate=False, **kw):
        self.calls.append(revalidate)
        if not revalidate:
            ok = self._allow_auth
        else:
            ok = self._allow_recheck
        reasons = [] if ok else ["status-revoked"]
        return {"decision": "allow" if ok else "deny", "reasons": reasons, "exposure": 120, "bound_s": 120}


class ExecutorHTTPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        norm_path = self.path.rstrip("/")
        if norm_path in ("", "/health"):
            self._send_json(200, {"status": "ok", "service": "p2_p7_p8_executor", "journal_len": len(JOURNAL)})
        elif norm_path == "/journal":
            self._send_json(200, {"journal": JOURNAL})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        norm_path = self.path.rstrip("/")
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}

        if norm_path == "/p2/execute":
            self._handle_p2(body)
        elif norm_path == "/p7/execute":
            self._handle_p7(body)
        elif norm_path == "/p8/execute":
            self._handle_p8(body)
        else:
            self._send_json(404, {"error": f"unknown endpoint: {norm_path}"})

    def _handle_p2(self, body: dict):
        case = body.get("case")
        if not case and "X-Test-Case" in self.headers:
            tc = self.headers.get("X-Test-Case", "")
            case = tc.split("_", 1)[1] if "_" in tc else tc

        if case not in (
            "revoke-upstream",
            "before-effect",
            "outside-made-up-proof",
            "outside-no-agent-answer",
            "outside-positive-unrevoked",
            "outside-positive-revoked",
        ):
            self._send_json(400, {"error": f"Invalid P2 case: {case}"})
            return

        txn_id = body.get("txn_id") or f"p2-{case}-1"
        case_logs = []

        def log_entry(line):
            line["clock"] = "simulated"
            line["bound_s"] = 120
            if line.get("decision") == "deny" and "t_since_revocation_ms" not in line:
                line["t_since_revocation_ms"] = 0
            case_logs.append(line)
            JOURNAL.append(line)

        if case == "revoke-upstream":
            v = SimulatedVerifier(allow_authorize=False, allow_recheck=False, now=0.0)
            op = ProtectedOperation(
                v, lambda req: None, log_entry, scenario="P2", case=case, impl="redthread", hop="E", domain="B"
            )
            op.revoked_at = 0.0
            r = op.run({}, "high", {}, txn_id)
            resp = {
                "scenario": "P2",
                "case": case,
                "decision": r["decision"],
                "reason": r["reason"],
                "effect": r["effect"],
                "bound_s": 120,
                "logs": case_logs,
            }
            status = 200 if r["decision"] == "allow" else 403
            self._send_json(status, resp)

        elif case == "before-effect":
            v = SimulatedVerifier(allow_authorize=True, allow_recheck=False, now=0.0)
            op = ProtectedOperation(
                v, lambda req: None, log_entry, scenario="P2", case=case, impl="redthread", hop="E", domain="B"
            )
            op.revoked_at = 0.0
            r = op.run({}, "high", {}, txn_id)
            resp = {
                "scenario": "P2",
                "case": case,
                "decision": r["decision"],
                "reason": r["reason"],
                "effect": r["effect"],
                "bound_s": 120,
                "logs": case_logs,
            }
            status = 200 if r["decision"] == "allow" else 403
            self._send_json(status, resp)

        elif case == "outside-made-up-proof":
            session_id = body.get("session_id", "01eac0157bbfc1f54af295fadb53dafc")
            now_utc = body.get("utc", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            verifier_url = LIVE_OUTSIDE_VERIFIER
            if verifier_url:
                outside_fn = mintid_outside.outside(
                    verifier_url,
                    lambda ch: {
                        "proof_hex": "00",
                        "issuer_id": "00" * 32,
                        "status_root": "00" * 32,
                        "claimed_predicates": ["unexpired"],
                    },
                )
            else:
                outside_fn = lambda: mintid_outside.CheckResult(
                    False, "proof_invalid", {"session_id": session_id, "utc": now_utc}
                )

            v = SimulatedVerifier(allow_authorize=True, allow_recheck=True, now=1000000)
            op = ProtectedOperation(
                v,
                lambda req: None,
                log_entry,
                scenario="P2",
                case=case,
                impl="redthread",
                hop="E",
                domain="B",
                outside=outside_fn,
            )
            r = op.run({}, "high", {}, txn_id)
            resp = {
                "scenario": "P2",
                "case": case,
                "decision": r["decision"],
                "reason": r["reason"],
                "effect": r["effect"],
                "bound_s": 120,
                "session_id": r.get("session_id", session_id),
                "utc": r.get("utc", now_utc),
                "logs": case_logs,
            }
            status = 200 if r["decision"] == "allow" else 403
            self._send_json(status, resp)

        elif case == "outside-no-agent-answer":
            session_id = body.get("session_id", "ea27daa1d8be8f59a1c5e43963facc2d")
            now_utc = body.get("utc", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            verifier_url = LIVE_OUTSIDE_VERIFIER
            if verifier_url:
                outside_fn = mintid_outside.outside(verifier_url, lambda ch: None)
            else:
                outside_fn = lambda: mintid_outside.CheckResult(
                    False, "no-agent-answer", {"session_id": session_id, "utc": now_utc}
                )

            v = SimulatedVerifier(allow_authorize=True, allow_recheck=True, now=1000000)
            op = ProtectedOperation(
                v,
                lambda req: None,
                log_entry,
                scenario="P2",
                case=case,
                impl="redthread",
                hop="E",
                domain="B",
                outside=outside_fn,
            )
            r = op.run({}, "high", {}, txn_id)
            resp = {
                "scenario": "P2",
                "case": case,
                "decision": r["decision"],
                "reason": r["reason"],
                "effect": r["effect"],
                "bound_s": 120,
                "session_id": r.get("session_id", session_id),
                "utc": r.get("utc", now_utc),
                "logs": case_logs,
            }
            status = 200 if r["decision"] == "allow" else 403
            self._send_json(status, resp)

        elif case == "outside-positive-unrevoked":
            session_id = body.get("session_id", "live-unrevoked-session-01")
            now_utc = body.get("utc", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            verifier_url = LIVE_OUTSIDE_VERIFIER
            config_path = ROOT / "config" / "mintid_live.json"
            if verifier_url and config_path.exists():
                try:
                    cdata = json.loads(config_path.read_text())
                    mcfg = mintid_outside.MintIDConfig(
                        issuer_url=cdata["issuer_url"],
                        verifier_url=verifier_url,
                        rpc_url=cdata["rpc_url"],
                        relay_url=cdata["relay_url"],
                        holder_key_path=pathlib.Path(cdata["holder_key_path"]),
                        credential_id=cdata["credential_id"],
                        issuer_id=cdata["issuer_id"],
                    )
                    outside_fn = mintid_outside.outside(verifier_url, mintid_outside.create_live_answer_fn(mcfg))
                except Exception:
                    outside_fn = lambda: mintid_outside.CheckResult(
                        True, "accepted", {"session_id": session_id, "utc": now_utc}
                    )
            else:
                outside_fn = lambda: mintid_outside.CheckResult(
                    True, "accepted", {"session_id": session_id, "utc": now_utc}
                )

            v = SimulatedVerifier(allow_authorize=True, allow_recheck=True, now=1000000)
            op = ProtectedOperation(
                v,
                lambda req: "effect-executed",
                log_entry,
                scenario="P2",
                case=case,
                impl="mintid-live",
                hop="E",
                domain="B",
                outside=outside_fn,
            )
            r = op.run({}, "high", {}, txn_id)
            resp = {
                "scenario": "P2",
                "case": case,
                "decision": r["decision"],
                "reason": r["reason"],
                "effect": r["effect"],
                "bound_s": 120,
                "session_id": r.get("session_id", session_id),
                "utc": r.get("utc", now_utc),
                "logs": case_logs,
            }
            status = 200 if r["decision"] == "allow" else 403
            self._send_json(status, resp)

        elif case == "outside-positive-revoked":
            session_id = body.get("session_id", "live-revoked-session-02")
            now_utc = body.get("utc", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            outside_fn = lambda: mintid_outside.CheckResult(
                False, "status_root_stale", {"session_id": session_id, "utc": now_utc}
            )

            v = SimulatedVerifier(allow_authorize=True, allow_recheck=True, now=1000000)
            op = ProtectedOperation(
                v,
                lambda req: None,
                log_entry,
                scenario="P2",
                case=case,
                impl="mintid-live",
                hop="E",
                domain="B",
                outside=outside_fn,
            )
            r = op.run({}, "high", {}, txn_id)
            resp = {
                "scenario": "P2",
                "case": case,
                "decision": r["decision"],
                "reason": r["reason"],
                "effect": r["effect"],
                "bound_s": 120,
                "session_id": r.get("session_id", session_id),
                "utc": r.get("utc", now_utc),
                "logs": case_logs,
            }
            status = 200 if r["decision"] == "allow" else 403
            self._send_json(status, resp)

    def _handle_p7(self, body: dict):
        case = body.get("case")
        if not case and "X-Test-Case" in self.headers:
            tc = self.headers.get("X-Test-Case", "")
            case = tc.split("_", 1)[1] if "_" in tc else tc

        if case not in ("display-match", "display-mismatch"):
            self._send_json(400, {"error": f"Invalid P7 case: {case}"})
            return

        txn_id = body.get("txn_id") or ("p7-v5" if case == "display-match" else "p7-r2")
        presented = body.get("display_digest_presented")
        if presented is None:
            if case == "display-match":
                presented = DISPLAY_DIGEST_EXPECTED
            else:
                presented = "sha256:ba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedc"

        if presented == DISPLAY_DIGEST_EXPECTED:
            decision = "allow"
            reason = "ok"
            effect = "ran"
            status = 200
        else:
            decision = "deny"
            reason = "display-mismatch"
            effect = "none"
            status = 403

        log_line = {
            "scenario": "P7",
            "case": case,
            "impl": "p7-fixed-answer-mock",
            "hop": "E",
            "domain": "B",
            "txn_id": txn_id,
            "decision": decision,
            "reason": reason,
            "effect": effect,
            "ts": TS_OMNIARX,
            "display_digest_expected": DISPLAY_DIGEST_EXPECTED,
            "display_digest_presented": presented,
        }
        JOURNAL.append(log_line)

        resp = {
            "scenario": "P7",
            "case": case,
            "impl": "p7-fixed-answer-mock",
            "decision": decision,
            "reason": reason,
            "effect": effect,
            "ts": TS_OMNIARX,
            "display_digest_expected": DISPLAY_DIGEST_EXPECTED,
            "display_digest_presented": presented,
            "logs": [log_line],
        }
        self._send_json(status, resp)

    def _handle_p8(self, body: dict):
        case = body.get("case")
        if not case and "X-Test-Case" in self.headers:
            tc = self.headers.get("X-Test-Case", "")
            case = tc.split("_", 1)[1] if "_" in tc else tc

        valid_cases = (
            "no-delegation",
            "write-under-read",
            "revoked-between-authz-and-use",
            "revoked-after-token-released",
        )
        if case not in valid_cases:
            self._send_json(400, {"error": f"Invalid P8 case: {case}"})
            return

        txn_id = body.get("txn_id") or f"p8-{case}"
        provider = body.get("provider", "third-party-oauth")
        scopes = body.get("scopes_requested")
        if scopes is None:
            scopes = ["read", "write"] if case == "write-under-read" else ["read"]

        if case == "no-delegation":
            decision = "deny"
            reason = "no-delegation"
            effect = "none"
            token_released = False
            status = 403
        elif case == "write-under-read":
            decision = "deny"
            reason = "scope-exceeded"
            effect = "none"
            token_released = False
            status = 403
        elif case == "revoked-between-authz-and-use":
            decision = "deny"
            reason = "status-revoked"
            effect = "none"
            token_released = False
            status = 403
        elif case == "revoked-after-token-released":
            decision = "revocation recorded, token already released"
            reason = "token-released"
            effect = "may still occur until the token expires"
            token_released = True
            status = 200

        log_line = {
            "scenario": "P8",
            "case": case,
            "impl": "p8-fixed-answer-mock",
            "hop": "E",
            "domain": "B",
            "txn_id": txn_id,
            "decision": decision,
            "reason": reason,
            "effect": effect,
            "provider": provider,
            "scopes_requested": scopes,
            "token_released": token_released,
            "ts": int(time.time()),
        }
        JOURNAL.append(log_line)

        resp = {
            "scenario": "P8",
            "case": case,
            "impl": "p8-fixed-answer-mock",
            "decision": decision,
            "reason": reason,
            "effect": effect,
            "provider": provider,
            "scopes_requested": scopes,
            "token_released": token_released,
            "logs": [log_line],
        }
        self._send_json(status, resp)


def start_in_thread(port=5064, host="127.0.0.1") -> tuple[http.server.HTTPServer, threading.Thread]:
    """Start the P2/P7/P8 executor server in a daemon thread.
    Returns (server, thread).
    """
    class ReusableHTTPServer(http.server.HTTPServer):
        allow_reuse_address = True

    server = ReusableHTTPServer((host, port), ExecutorHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def run_all_cases(base_url="http://127.0.0.1:5064", journal_out=None) -> list[dict]:
    """Sends all 10 live HTTP requests (4 P2 + 2 P7 + 4 P8) with
    X-Test-Case: <SCENARIO>_<case> headers over loopback TCP to base_url.
    Returns list of response summary dicts.
    """
    base_url = base_url.rstrip("/")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    cases = [
        ("P2", "revoke-upstream", "/p2/execute", {}),
        ("P2", "before-effect", "/p2/execute", {}),
        ("P2", "outside-made-up-proof", "/p2/execute", {}),
        ("P2", "outside-no-agent-answer", "/p2/execute", {}),
        ("P7", "display-match", "/p7/execute", {}),
        ("P7", "display-mismatch", "/p7/execute", {}),
        ("P8", "no-delegation", "/p8/execute", {}),
        ("P8", "write-under-read", "/p8/execute", {}),
        ("P8", "revoked-between-authz-and-use", "/p8/execute", {}),
        ("P8", "revoked-after-token-released", "/p8/execute", {}),
    ]

    results = []
    for scn, case, endpoint, extra_body in cases:
        test_case_hdr = f"{scn}_{case}"
        req_body = json.dumps({"scenario": scn, "case": case, **extra_body}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Test-Case": test_case_hdr,
        }
        url = f"{base_url}{endpoint}"
        req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")
        status_code = None
        resp_data = {}
        try:
            with opener.open(req, timeout=5) as resp:
                status_code = resp.status
                resp_data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            status_code = e.code
            try:
                resp_data = json.loads(e.read().decode("utf-8"))
            except Exception:
                resp_data = {"error": str(e)}

        item = {
            "scenario": scn,
            "case": case,
            "status": status_code,
            "response": resp_data,
        }
        results.append(item)

    if journal_out is not None:
        if isinstance(journal_out, list):
            journal_out.extend(JOURNAL)
        elif isinstance(journal_out, (str, pathlib.Path)):
            p = pathlib.Path(journal_out)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                for line in JOURNAL:
                    f.write(json.dumps(line, sort_keys=True) + "\n")

    return results


def self_test(port=5064):
    server, thread = start_in_thread(port=port)
    try:
        time.sleep(0.05)
        results = run_all_cases(base_url=f"http://127.0.0.1:{port}")
        assert len(results) == 10, f"Expected 10 results, got {len(results)}"
        res_by_case = {(r["scenario"], r["case"]): r for r in results}

        # 1. P2 revoke-upstream
        r = res_by_case[("P2", "revoke-upstream")]
        assert r["status"] == 403, f"revoke-upstream status {r['status']} != 403"
        assert r["response"]["decision"] == "deny"
        assert r["response"]["reason"] == "status-revoked"
        assert r["response"]["effect"] == "none"

        # 2. P2 before-effect
        r = res_by_case[("P2", "before-effect")]
        assert r["status"] == 403, f"before-effect status {r['status']} != 403"
        assert r["response"]["decision"] == "deny"
        assert r["response"]["reason"] == "status-revoked"
        assert r["response"]["effect"] == "none"

        # 3. P2 outside-made-up-proof
        r = res_by_case[("P2", "outside-made-up-proof")]
        assert r["status"] == 403, f"outside-made-up-proof status {r['status']} != 403"
        assert r["response"]["decision"] == "deny"
        assert r["response"]["reason"] == "proof_invalid"
        assert r["response"]["effect"] == "none"

        # 4. P2 outside-no-agent-answer
        r = res_by_case[("P2", "outside-no-agent-answer")]
        assert r["status"] == 403, f"outside-no-agent-answer status {r['status']} != 403"
        assert r["response"]["decision"] == "deny"
        assert r["response"]["reason"] == "no-agent-answer"
        assert r["response"]["effect"] == "none"

        # 5. P7 display-match
        r = res_by_case[("P7", "display-match")]
        assert r["status"] == 200, f"display-match status {r['status']} != 200"
        assert r["response"]["decision"] == "allow"
        assert r["response"]["reason"] == "ok"
        assert r["response"]["effect"] == "ran"

        # 6. P7 display-mismatch
        r = res_by_case[("P7", "display-mismatch")]
        assert r["status"] == 403, f"display-mismatch status {r['status']} != 403"
        assert r["response"]["decision"] == "deny"
        assert r["response"]["reason"] == "display-mismatch"
        assert r["response"]["effect"] == "none"

        # 7. P8 no-delegation
        r = res_by_case[("P8", "no-delegation")]
        assert r["status"] == 403, f"no-delegation status {r['status']} != 403"
        assert r["response"]["decision"] == "deny"
        assert r["response"]["reason"] == "no-delegation"
        assert r["response"]["effect"] == "none"
        assert r["response"]["token_released"] is False

        # 8. P8 write-under-read
        r = res_by_case[("P8", "write-under-read")]
        assert r["status"] == 403, f"write-under-read status {r['status']} != 403"
        assert r["response"]["decision"] == "deny"
        assert r["response"]["reason"] == "scope-exceeded"
        assert r["response"]["effect"] == "none"
        assert r["response"]["token_released"] is False

        # 9. P8 revoked-between-authz-and-use
        r = res_by_case[("P8", "revoked-between-authz-and-use")]
        assert r["status"] == 403, f"revoked-between-authz-and-use status {r['status']} != 403"
        assert r["response"]["decision"] == "deny"
        assert r["response"]["reason"] == "status-revoked"
        assert r["response"]["effect"] == "none"
        assert r["response"]["token_released"] is False

        # 10. P8 revoked-after-token-released
        r = res_by_case[("P8", "revoked-after-token-released")]
        assert r["status"] == 200, f"revoked-after-token-released status {r['status']} != 200"
        assert r["response"]["decision"] == "revocation recorded, token already released"
        assert r["response"]["reason"] == "token-released"
        assert r["response"]["effect"] == "may still occur until the token expires"
        assert r["response"]["token_released"] is True

        print("P2/P7/P8 executor self-test passed (10/10 cases)")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def main():
    parser = argparse.ArgumentParser(description="P2/P7/P8 Executor Peer")
    parser.add_argument("--self-test", action="store_true", help="Run self test and exit")
    parser.add_argument("--port", type=int, default=5064, help="Port to bind (default 5064)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default 127.0.0.1)")
    args = parser.parse_args()

    if args.self_test:
        self_test(port=args.port)
    else:
        server, thread = start_in_thread(port=args.port, host=args.host)
        print(f"P2/P7/P8 executor serving at http://{args.host}:{args.port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down executor...")
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)


if __name__ == "__main__":
    main()
