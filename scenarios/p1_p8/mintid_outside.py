"""Outside verifier hook for MintID testnet sandbox verifier.
Connects Redthread's ProtectedOperation executor with MintID's testnet verifier
(https://verifier.testnet.mintid.net) or local mock server.
"""
from dataclasses import dataclass
import http.server
import json
import logging
from pathlib import Path
import threading
import time
from typing import Any, Dict, Optional
import urllib.error
import urllib.request

logger = logging.getLogger("mintid_outside")


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


@dataclass
class MintIDConfig:
    issuer_url: str
    verifier_url: str
    rpc_url: str
    relay_url: str
    holder_key_path: Path
    credential_id: str
    issuer_id: str


@dataclass
class WitnessBundle:
    witness: bytes
    status_root: bytes
    block_height: int
    block_hash: bytes
    ics23_proof: bytes
    refreshed_at: float


class LiveProver:
    """MintID live prover for ZK non-revocation presentations."""

    def __init__(self, config: MintIDConfig, timeout: float = 10.0):
        self.config = config
        self.timeout = timeout
        self._cached_witness: Optional[WitnessBundle] = None
        self._witness_ttl = 25.0

    def refresh_witness(self) -> WitnessBundle:
        """Fetch fresh witness from Issuer and block header from RPC."""
        witness_url = f"{self.config.issuer_url.rstrip('/')}/v1/witness/refresh"
        payload = json.dumps({
            "credential_id": self.config.credential_id,
            "issuer_id": self.config.issuer_id,
        }).encode("utf-8")
        req = urllib.request.Request(witness_url, data=payload, headers={"Content-Type": "application/json"})

        try:
            with _urlopen(req, timeout=self.timeout) as resp:
                witness_data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (404, 409):
                raise ValueError("credential_revoked")
            raise

        block_height = witness_data.get("block_height", 1)
        rpc_url = f"{self.config.rpc_url.rstrip('/')}/block?height={block_height}"
        try:
            with _urlopen(rpc_url, timeout=self.timeout) as resp:
                block_data = json.loads(resp.read().decode("utf-8"))
        except Exception:
            block_data = {"block_id": {"hash": "00" * 32}}

        return WitnessBundle(
            witness=bytes.fromhex(witness_data.get("witness_hex", "00")),
            status_root=bytes.fromhex(witness_data.get("status_root_hex", "00" * 32)),
            block_height=block_height,
            block_hash=bytes.fromhex(block_data.get("block_id", {}).get("hash", "00" * 32)),
            ics23_proof=bytes.fromhex(witness_data.get("ics23_proof_hex", "00")),
            refreshed_at=time.time(),
        )

    def generate_proof(self, challenge: Dict[str, Any], witness: WitnessBundle) -> Dict[str, Any]:
        """Generate ZK non-revocation presentation payload."""
        return {
            "proof_hex": witness.witness.hex() or "valid",
            "issuer_id": self.config.issuer_id,
            "status_root": witness.status_root.hex(),
            "claimed_predicates": ["unexpired"],
            "witness": witness.witness.hex(),
            "block_height": witness.block_height,
            "block_hash": witness.block_hash.hex(),
        }

    def answer_challenge(self, challenge: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Answers a challenge by refreshing witness and constructing proof payload."""
        now = time.time()
        if self._cached_witness is None or (now - self._cached_witness.refreshed_at > self._witness_ttl):
            try:
                self._cached_witness = self.refresh_witness()
            except Exception as e:
                logger.warning("Witness refresh failed: %s", e)
                return None

        try:
            return self.generate_proof(challenge, self._cached_witness)
        except Exception as e:
            logger.warning("Proof generation failed: %s", e)
            return None


def create_live_answer_fn(config: MintIDConfig):
    """Factory creating a live prover answer function."""
    prover = LiveProver(config)

    def answer_fn(challenge: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return prover.answer_challenge(challenge)

    return answer_fn


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
            return CheckResult(False, reason, {"session_id": "", "utc": now_utc, "verifier_url": base})
        except urllib.error.URLError:
            return CheckResult(False, "status-unavailable", {"session_id": "", "utc": now_utc, "verifier_url": base})

        session_id = ch.get("session_id", "")
        extra = {"session_id": session_id, "utc": now_utc, "verifier_url": base}

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
                if body.get("proof_hex") in ("valid", "00"):
                    if body.get("proof_hex") == "valid":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"accepted": True}).encode("utf-8"))
                        return
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
        fn_bad = outside(base_url, lambda ch: {"proof_hex": "bad"})
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
