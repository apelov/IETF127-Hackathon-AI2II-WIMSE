"""Trust Domain A Services: TTS-A, AS-A, and Maurice fallback responder.

Implements Domain A services for WIMSE multi-agent identity chaining and negative tests.
Endpoints on 127.0.0.1:5051:
  - GET  /.well-known/wimse/jwks.json: Domain A JWKS (TTS-A public key)
  - GET  /health: Service health check
  - POST /tts/token: Issues/narrows txntoken+jwt for Domain A
  - POST /oauth/token: RFC 8693 token exchange from Txn-Token to cross-domain JWT grant
"""
import http.server
import json
import os
import pathlib
import socketserver
import sys
import threading
import time
import urllib.parse
import uuid
from cryptography.hazmat.primitives import serialization

# Import wimse primitives
try:
    from . import wimse as w
except (ImportError, ValueError):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import wimse as w

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEYS_DIR = ROOT / "keys"


def _load_private_key(name: str):
    p = KEYS_DIR / f"{name}.pem"
    return serialization.load_pem_private_key(p.read_bytes(), None)


def _load_jwks(name: str) -> dict:
    p = KEYS_DIR / f"{name}.jwks.json"
    return json.loads(p.read_text(encoding="utf-8"))


TTS_A_KEY = _load_private_key("tts_a")
TTS_A_JWKS = _load_jwks("tts_a")
AS_A_KEY = _load_private_key("as_a")
AS_A_JWKS = _load_jwks("as_a")
PEER_JWKS = _load_jwks("peer")

JOURNAL: list[dict] = []


def _log_journal(entry: dict):
    JOURNAL.append(entry)
    jpath = os.environ.get("WIMSE_JOURNAL_FILE")
    if jpath:
        try:
            with open(jpath, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass


class DomainAServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class DomainAHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json_response(self, status: int, data: dict, headers: dict | None = None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path in ("/.well-known/wimse/jwks.json", "/jwks.json", "/health"):
            self.send_json_response(200, TTS_A_JWKS)
        else:
            self.send_json_response(404, {"error": "not-found"})

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len) if content_len > 0 else b""

        if u.path == "/tts/token":
            self.handle_tts_token(raw_body)
        elif u.path == "/oauth/token":
            self.handle_oauth_token(raw_body)
        else:
            self.send_json_response(404, {"error": "not-found"})

    def handle_tts_token(self, raw_body: bytes):
        case_id = self.headers.get("X-Test-Case", "")
        try:
            req = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            req = {}

        sub = req.get("sub", "")
        scope = req.get("scope", "")
        tctx = req.get("tctx") or {}
        req_wl = req.get("req_wl", "")
        test_mode = req.get("test_mode")
        parent_tok = req.get("parent_txn_token")

        if parent_tok:
            try:
                parent = w.verify_jwt(
                    parent_tok,
                    TTS_A_JWKS,
                    expected_typ="txntoken+jwt",
                    expected_aud="maurice.ietf127.example",
                )
            except Exception:
                _log_journal({
                    "service": "tts-a",
                    "direction": "issue",
                    "decision": "reject",
                    "reason": "parent-token-invalid",
                    "status": 403,
                    "case": case_id,
                })
                self.send_json_response(403, {"error": "parent-token-invalid"})
                return

            txn = parent.get("txn", "")
            sub = parent.get("sub", sub)
            tctx = parent.get("tctx", tctx)
            if not req_wl:
                req_wl = parent.get("req_wl", "")

            parent_scope_set = set((parent.get("scope") or "").split())
            req_scope_set = set(scope.split())
            if not (req_scope_set <= parent_scope_set) and not test_mode:
                _log_journal({
                    "service": "tts-a",
                    "direction": "issue",
                    "decision": "reject",
                    "reason": "scope-widened",
                    "status": 403,
                    "case": case_id,
                })
                self.send_json_response(403, {"error": "scope-widened"})
                return
        else:
            txn = req.get("txn") or str(uuid.uuid4())

        if test_mode == "widen_scope":
            scope = f"{scope} files:write".strip()
        elif test_mode == "change_txn":
            txn = f"mutated-{uuid.uuid4().hex[:8]}"

        tok = w.issue_txn_token(
            TTS_A_KEY,
            kid="tts_a-1",
            iss="http://maurice.ietf127.example:5051",
            aud="maurice.ietf127.example",
            txn=txn,
            sub=sub,
            scope=scope,
            req_wl=req_wl,
            tctx=tctx,
        )

        _log_journal({
            "service": "tts-a",
            "direction": "issue",
            "txn": txn,
            "sub": sub,
            "scope": scope,
            "req_wl": req_wl,
            "decision": "accept",
            "status": 200,
            "case": case_id,
        })
        self.send_json_response(200, {"txn_token": tok, "txn": txn})

    def handle_oauth_token(self, raw_body: bytes):
        case_id = self.headers.get("X-Test-Case", "")
        trust_jwks = {
            "peer.ietf127.example": PEER_JWKS,
            "maurice.ietf127.example": TTS_A_JWKS,
        }
        ok, status, reason, ctx = w.verify_wimse_proof(
            self.command,
            self.path,
            dict(self.headers),
            raw_body,
            trust_jwks,
            expected_aud="http://maurice.ietf127.example:5051",
        )
        if not ok:
            _log_journal({
                "service": "as-a",
                "direction": "exchange",
                "decision": "reject",
                "reason": reason,
                "status": status,
                "case": case_id,
            })
            hdrs = {"WWW-Authenticate": 'WPT realm="wimse"'} if status == 401 else None
            self.send_json_response(status, {"error": reason}, headers=hdrs)
            return

        content_type = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            req = dict(urllib.parse.parse_qsl(raw_body.decode("utf-8")))
        else:
            try:
                req = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            except Exception:
                req = {}

        subject_token = req.get("subject_token")
        if not subject_token:
            _log_journal({
                "service": "as-a",
                "direction": "exchange",
                "decision": "reject",
                "reason": "txn-token-invalid",
                "status": 403,
                "case": case_id,
            })
            self.send_json_response(403, {"error": "txn-token-invalid"})
            return

        try:
            subj_claims = w.verify_jwt(
                subject_token,
                TTS_A_JWKS,
                expected_typ="txntoken+jwt",
                expected_aud="maurice.ietf127.example",
            )
        except Exception:
            _log_journal({
                "service": "as-a",
                "direction": "exchange",
                "decision": "reject",
                "reason": "txn-token-invalid",
                "status": 403,
                "case": case_id,
            })
            self.send_json_response(403, {"error": "txn-token-invalid"})
            return

        scope = req.get("scope") or subj_claims.get("scope", "")
        req_scopes = set(scope.split())
        subj_scopes = set((subj_claims.get("scope") or "").split())
        if not (req_scopes <= subj_scopes):
            _log_journal({
                "service": "as-a",
                "direction": "exchange",
                "decision": "reject",
                "reason": "not-authorized",
                "status": 403,
                "case": case_id,
            })
            self.send_json_response(403, {"error": "not-authorized"})
            return

        test_mode = req.get("test_mode")
        if test_mode == "wrong_aud":
            aud = "http://wrong.example/oauth/token"
        else:
            aud = req.get("audience") or "http://rich.ietf127.example:5061/oauth/token"

        grant = w.issue_chain_grant(
            AS_A_KEY,
            kid="as_a-1",
            iss="http://maurice.ietf127.example:5051",
            aud=aud,
            sub=subj_claims["sub"],
            scope=scope,
            txn=subj_claims["txn"],
            tctx=subj_claims.get("tctx"),
        )

        _log_journal({
            "service": "as-a",
            "direction": "exchange",
            "txn": subj_claims["txn"],
            "sub": subj_claims["sub"],
            "scope": scope,
            "decision": "accept",
            "status": 200,
            "case": case_id,
        })
        self.send_json_response(200, {"assertion": grant, "txn": subj_claims["txn"]})


class MauriceFallbackHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path in ("/.well-known/wimse/jwks.json", "/jwks.json", "/health"):
            body = json.dumps(TTS_A_JWKS).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len) if content_len > 0 else b""
        case_id = self.headers.get("X-Test-Case", "")

        txn_headers = self.headers.get_all("Txn-Token", [])
        if len(txn_headers) > 1:
            _log_journal({
                "service": "maurice",
                "direction": "inbound",
                "decision": "reject",
                "reason": "txn-token-invalid",
                "status": 403,
                "case": case_id,
            })
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "txn-token-invalid"}).encode("utf-8"))
            return

        trust_jwks = {
            "peer.ietf127.example": PEER_JWKS,
            "maurice.ietf127.example": TTS_A_JWKS,
        }
        ok, status, reason, ctx = w.verify_wimse_proof(
            self.command,
            self.path,
            dict(self.headers),
            raw_body,
            trust_jwks,
            expected_aud="http://maurice.ietf127.example:5050",
        )
        if not ok:
            _log_journal({
                "service": "maurice",
                "direction": "inbound",
                "decision": "reject",
                "reason": reason,
                "status": status,
                "case": case_id,
            })
            self.send_response(status)
            if status == 401:
                self.send_header("WWW-Authenticate", 'WPT realm="wimse"')
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": reason}).encode("utf-8"))
            return

        txn_token = self.headers.get("Txn-Token")
        txn_id = ""
        sub = ""
        if txn_token:
            try:
                claims = w.verify_jwt(
                    txn_token,
                    TTS_A_JWKS,
                    expected_typ="txntoken+jwt",
                    expected_aud="maurice.ietf127.example",
                )
                txn_id = claims.get("txn", "")
                sub = claims.get("sub", "")
            except Exception:
                _log_journal({
                    "service": "maurice",
                    "direction": "inbound",
                    "decision": "reject",
                    "reason": "txn-token-invalid",
                    "status": 403,
                    "case": case_id,
                })
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "txn-token-invalid"}).encode("utf-8"))
                return

        _log_journal({
            "service": "maurice",
            "direction": "inbound",
            "txn": txn_id,
            "sub": sub,
            "decision": "accept",
            "status": 200,
            "case": case_id,
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))


def start_in_thread(port: int = 5051) -> http.server.ThreadingHTTPServer:
    srv = DomainAServer(("127.0.0.1", port), DomainAHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def start_maurice_fallback_on_5050(port: int = 5050) -> http.server.ThreadingHTTPServer:
    srv = DomainAServer(("127.0.0.1", port), MauriceFallbackHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def validate_narrowed_replacement(
    original_txn_token: str, replacement_txn_token: str, tts_a_jwks: dict
) -> tuple[bool, str]:
    """Client-side helper for D-6 (TXO-4, TXO-5): verifies replacement_txn_token,

    checks rep["txn"] == orig["txn"] (else (False, "txn-mutated")), and checks
    set(rep["scope"].split()) <= set(orig["scope"].split()) (else (False, "scope-widened")).
    """
    try:
        rep = w.verify_jwt(replacement_txn_token, tts_a_jwks, expected_typ="txntoken+jwt")
    except Exception as exc:
        return False, str(exc)

    try:
        orig = w.verify_jwt(original_txn_token, tts_a_jwks, expected_typ="txntoken+jwt")
    except Exception:
        try:
            _, orig, _, _ = w.parse_jwt(original_txn_token)
        except Exception:
            return False, "original-jwt-malformed"

    if rep.get("txn") != orig.get("txn"):
        return False, "txn-mutated"

    rep_scopes = set((rep.get("scope") or "").split())
    orig_scopes = set((orig.get("scope") or "").split())
    if not (rep_scopes <= orig_scopes):
        return False, "scope-widened"

    return True, "ok"


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Domain A Services (TTS-A & AS-A)")
    parser.add_argument("--port", type=int, default=5051, help="Port for Domain A services (default 5051)")
    parser.add_argument("--with-maurice", action="store_true", help="Also start Maurice fallback on 5050")
    args = parser.parse_args()

    srv = DomainAServer(("127.0.0.1", args.port), DomainAHandler)
    print(f"Domain A listening on 127.0.0.1:{args.port}")
    if args.with_maurice:
        m_srv = start_maurice_fallback_on_5050()
        print("Maurice fallback listening on 127.0.0.1:5050")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
