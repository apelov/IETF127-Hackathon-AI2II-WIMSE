"""Outside verifier hook for MintID testnet sandbox verifier.
Connects Redthread's ProtectedOperation executor with MintID's testnet verifier
(https://verifier.testnet.mintid.net) or local mock server.
"""
import http.server
import json
import threading
import time
import urllib.error
import urllib.request


class CheckResult(tuple):
    """3-tuple of (ok: bool, reason: str, extra: dict).
    Also supports dict-like operations for backward compatibility with wrappers
    like stamp() that treat the result as a mutable dict.
    """

    def __new__(cls, ok: bool, reason: str, extra: dict):
        return super().__new__(cls, (ok, reason, extra))

    def __init__(self, ok: bool, reason: str, extra: dict):
        super().__init__()
        self._ok = ok
        self._reason = reason
        self._extra = dict(extra) if extra else {}
        self._dict = {
            "ok": ok,
            "decision": "allow" if ok else "deny",
            "reason": reason,
            **self._extra,
        }

    def __getitem__(self, item):
        if isinstance(item, (int, slice)):
            return super().__getitem__(item)
        return self._dict[item]

    def __setitem__(self, key, value):
        self._dict[key] = value
        self[2][key] = value

    def get(self, key, default=None):
        return self._dict.get(key, default)

    def items(self):
        return self._dict.items()

    def keys(self):
        return self._dict.keys()

    def values(self):
        return self._dict.values()

    def __contains__(self, key):
        return key in self._dict


def _urlopen(req, timeout=10):
    url = req.full_url if hasattr(req, "full_url") else str(req)
    if "127.0.0.1" in url or "localhost" in url:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        return opener.open(req, timeout=timeout)
    return urllib.request.urlopen(req, timeout=timeout)


def outside(base_url, answer_fn, policy="iot_Command"):
    """Returns a zero-arg callable `_check() -> tuple[bool, str, dict]` (or `_check(*args, **kwargs)`).
    When called:
    - Sends POST {base_url}/v1/challenges with JSON {"policy": policy}.
    - Extracts session_id = ch.get("session_id", "") and utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()).
    - Calls ans = answer_fn(ch). If ans is None, returns (False, "no-agent-answer", extra).
    - Sends POST {base_url}/v1/presentations with JSON {"session_id": session_id, **ans}.
    - If HTTP 200 and resp.get("accepted") is True, returns (True, "ok", extra).
    - Otherwise extracts reason = resp.get("error") or resp.get("reason_code") or "proof_invalid"
      and returns (False, reason, extra).
    """
    base = base_url.rstrip("/")

    def _check(*args, **kwargs) -> CheckResult:
        now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        headers = {"Content-Type": "application/json"}
        ch_url = f"{base}/v1/challenges"
        ch_payload = json.dumps({"policy": policy}).encode("utf-8")
        ch_req = urllib.request.Request(ch_url, data=ch_payload, headers=headers, method="POST")

        try:
            with _urlopen(ch_req, timeout=10) as resp:
                ch = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read().decode("utf-8"))
            except Exception:
                err = {}
            reason = err.get("error") or err.get("reason_code") or f"http_{e.code}"
            return CheckResult(False, reason, {"session_id": "", "utc": now_utc})
        except urllib.error.URLError:
            return CheckResult(False, "status-unavailable", {"session_id": "", "utc": now_utc})

        session_id = ch.get("session_id", "")
        extra = {"session_id": session_id, "utc": now_utc}

        ans = answer_fn(ch)
        if ans is None:
            return CheckResult(False, "no-agent-answer", extra)

        pres_url = f"{base}/v1/presentations"
        pres_payload = json.dumps({"session_id": session_id, **ans}).encode("utf-8")
        pres_req = urllib.request.Request(pres_url, data=pres_payload, headers=headers, method="POST")

        try:
            with _urlopen(pres_req, timeout=10) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                if resp_data.get("accepted") is True:
                    return CheckResult(True, "ok", extra)
                reason = resp_data.get("error") or resp_data.get("reason_code") or "proof_invalid"
                return CheckResult(False, reason, extra)
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read().decode("utf-8"))
            except Exception:
                err = {}
            reason = err.get("error") or err.get("reason_code") or "proof_invalid"
            return CheckResult(False, reason, extra)
        except urllib.error.URLError:
            return CheckResult(False, "status-unavailable", extra)

    return _check


def demo():
    class MockHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
            if self.path == "/v1/challenges":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"session_id": "test-session-123", "policy": body.get("policy")}).encode("utf-8"))
            elif self.path == "/v1/presentations":
                if body.get("proof_hex") == "valid":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"accepted": True}).encode("utf-8"))
                else:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"accepted": False, "error": "proof_invalid"}).encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        base_url = f"http://127.0.0.1:{port}"
        # 1. No agent answer
        fn_none = outside(base_url, lambda ch: None)
        ok, reason, extra = fn_none()
        assert not ok and reason == "no-agent-answer" and extra["session_id"] == "test-session-123"

        # 2. Made up proof (invalid)
        fn_bad = outside(base_url, lambda ch: {"proof_hex": "00"})
        ok, reason, extra = fn_bad()
        assert not ok and reason == "proof_invalid" and extra["session_id"] == "test-session-123"

        # 3. Valid proof
        fn_good = outside(base_url, lambda ch: {"proof_hex": "valid"})
        ok, reason, extra = fn_good()
        assert ok and reason == "ok" and extra["session_id"] == "test-session-123"

        # 4. Check CheckResult dict behavior
        res = fn_bad()
        assert isinstance(res, tuple)
        assert res["decision"] == "deny"
        res["utc"] = "2026-11-15T00:00:00Z"
        assert res["utc"] == "2026-11-15T00:00:00Z"

        print("mintid_outside self-check ok")
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=1.0)


if __name__ == "__main__":
    demo()
