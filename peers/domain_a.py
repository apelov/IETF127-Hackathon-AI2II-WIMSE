"""Trust Domain A Services: TTS-A, AS-A, and Maurice fallback responder.

Implements Domain A services for WIMSE multi-agent identity chaining and negative tests.
Endpoints on 127.0.0.1:5051:
  - GET  /.well-known/wimse/jwks.json: Domain A JWKS (TTS-A public key)
  - GET  /health: Service health check
  - POST /tts/token: Txn-Token request (txn-tokens-11 s11): form body, WIT + HTTP signature required, replacements narrow
  - POST /oauth/token: RFC 8693 token exchange from Txn-Token to cross-domain JWT authorization grant
"""
import http.server
import json
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
    from . import journal
    from . import wimse as w
except (ImportError, ValueError):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import journal
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

TRUST_DOMAIN = "maurice.ietf127.example"  # the aud of every Domain A Txn-Token, and the `audience` of a request
PROOF_AUD = "http://maurice.ietf127.example:5051"  # wimse-aud of requests signed for TTS-A / AS-A
TRUST_JWKS = {"peer.ietf127.example": PEER_JWKS, "maurice.ietf127.example": TTS_A_JWKS}
# who may ask TTS-A for a Txn-Token (txn-tokens-11 s11.3: the TTS decides whether the workload is authorized)
TTS_A_REQUESTERS = {"wimse://peer.ietf127.example/client"}
# the AS in trust domain B, by resource URI or logical name (identity-chaining-17 s2.3.1) -> aud of the grant
AS_B_TARGETS = {
    "http://rich.ietf127.example:5061": "http://rich.ietf127.example:5061/oauth/token",
    "http://rich.ietf127.example:5061/oauth/token": "http://rich.ietf127.example:5061/oauth/token",
    "rich.ietf127.example": "http://rich.ietf127.example:5061/oauth/token",
}
GRANT_TTL = 60

NONCES = {n: w.NonceCache() for n in ("tts-a", "as-a", "maurice")}  # replay caches, one per service
JOURNAL: list[dict] = []


def _log_journal(entry: dict):
    JOURNAL.append(entry)
    journal.append(entry)


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
        """TTS-A: Txn-Token request per txn-tokens-11 s11 (form body, WIT + HTTP signature client authentication).

        The requesting workload is the verified WIT subject (s11.3, s11.5); nothing in the body names it. A Txn-Token
        is never accepted as the credential of the request (s13.12): it is only a subject_token.
        """
        case_id = self.headers.get("X-Test-Case", "")
        ok, status, reason, ctx = w.verify_wimse_proof(
            self.command, self.path, dict(self.headers), raw_body, TRUST_JWKS, expected_aud=PROOF_AUD, seen_nonces=NONCES["tts-a"])
        if not ok:
            _log_journal({"service": "tts-a", "direction": "issue", "decision": "reject", "reason": reason,
                          "status": status, "case": case_id})
            # one body for every authentication failure (RFC 6749 s5.2 invalid_client); the cause is only journaled
            hdrs = {"WWW-Authenticate": 'WPT realm="wimse"'} if status == 401 else None
            self.send_json_response(status, {"error": "invalid_client"}, headers=hdrs)
            return
        req_wl = ctx["peer_id"]
        try:
            if req_wl not in TTS_A_REQUESTERS:
                raise w.OAuthError("unauthorized_client")
            tok, txn, sub, scope = self._issue_txn_token(raw_body, req_wl)
        except w.OAuthError as exc:
            _log_journal({"service": "tts-a", "direction": "issue", "decision": "reject", "reason": exc.cause,
                          "status": exc.status, "req_wl": req_wl, "case": case_id})
            self.send_json_response(exc.status, {"error": exc.error})
            return
        _log_journal({"service": "tts-a", "direction": "issue", "txn": txn, "sub": sub, "scope": scope,
                      "req_wl": req_wl, "decision": "accept", "status": 200, "case": case_id})
        self.send_json_response(200, w.txn_token_response(tok), headers={"Cache-Control": "no-store"})

    def _issue_txn_token(self, raw_body: bytes, req_wl: str) -> tuple[str, str, str, str]:
        f = w.parse_txn_token_request(raw_body, self.headers.get("Content-Type", ""), TRUST_DOMAIN)
        subject_token, stype = f["subject_token"], f["subject_token_type"]
        req_scopes = f.get("scope", "").split()
        rctx = None
        if stype == w.TT_UNSIGNED_JSON:  # a new transaction (s11.2.2)
            try:
                subj = json.loads(subject_token)
            except ValueError:
                raise w.OAuthError("invalid_grant") from None
            if not isinstance(subj, dict) or not isinstance(subj.get("sub"), str) or not subj["sub"]:
                raise w.OAuthError("invalid_grant")
            if not req_scopes:
                raise w.OAuthError("invalid_scope")
            txn, sub, tctx, rctx = str(uuid.uuid4()), subj["sub"], f["request_details"] or {}, f["request_context"]
        elif stype == w.TT_TXN:  # a replacement (s13.15)
            try:
                parent = w.verify_jwt(subject_token, TTS_A_JWKS, expected_typ="txntoken+jwt", expected_aud=TRUST_DOMAIN)
            except ValueError as exc:  # includes an expired token
                raise w.OAuthError("invalid_grant", cause=str(exc)) from None
            if not req_scopes:
                req_scopes = parent.get("scope", "").split()
            if not set(req_scopes) <= set(parent.get("scope", "").split()):
                raise w.OAuthError("invalid_scope", cause="scope-widened")
            txn, sub, tctx, rctx = parent["txn"], parent["sub"], parent.get("tctx", {}), parent.get("rctx")
        else:
            raise w.OAuthError("invalid_request")
        scope = " ".join(req_scopes)
        tok = w.issue_txn_token(TTS_A_KEY, kid="tts_a-1", iss="http://maurice.ietf127.example:5051", aud=TRUST_DOMAIN,
                                txn=txn, sub=sub, scope=scope, req_wl=req_wl, tctx=tctx, rctx=rctx)
        return tok, txn, sub, scope

    def handle_oauth_token(self, raw_body: bytes):
        """AS-A: RFC 8693 token exchange that returns a JWT authorization grant (identity-chaining-17 s2.3)."""
        case_id = self.headers.get("X-Test-Case", "")
        ok, status, reason, ctx = w.verify_wimse_proof(
            self.command, self.path, dict(self.headers), raw_body, TRUST_JWKS, expected_aud=PROOF_AUD, seen_nonces=NONCES["as-a"])
        if not ok:
            _log_journal({"service": "as-a", "direction": "exchange", "decision": "reject", "reason": reason,
                          "status": status, "case": case_id})
            hdrs = {"WWW-Authenticate": 'WPT realm="wimse"'} if status == 401 else None
            self.send_json_response(status, {"error": "invalid_client"}, headers=hdrs)
            return

        def refuse(status: int, error: str, cause: str | None = None):
            # RFC 8693 s2.2.2 / RFC 6749 s5.2: 400 and an error code; the precise cause is only journaled
            _log_journal({"service": "as-a", "direction": "exchange", "decision": "reject", "reason": cause or error,
                          "status": status, "case": case_id})
            self.send_json_response(status, {"error": error})

        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        req = w.form_decode(raw_body) if ctype == w.FORM_CT else None
        if req is None or req.get("grant_type") != w.GRANT_TOKEN_EXCHANGE or not req.get("subject_token"):
            refuse(400, "invalid_request")
            return
        if req.get("subject_token_type") != w.TT_TXN:
            refuse(400, "invalid_request")
            return
        # one of resource / audience names the AS in trust domain B; unknown ones are denied (s2.3.2)
        target = req.get("resource") or req.get("audience")
        aud = AS_B_TARGETS.get(target or "")
        if not aud:
            refuse(400, "invalid_target", "unknown-target")
            return

        try:
            subj_claims = w.verify_jwt(req["subject_token"], TTS_A_JWKS, expected_typ="txntoken+jwt",
                                       expected_aud=TRUST_DOMAIN)
        except Exception as exc:
            refuse(400, "invalid_grant", str(exc) if isinstance(exc, ValueError) else "txn-token-invalid")
            return

        scope = req.get("scope") or subj_claims.get("scope", "")
        if not set(scope.split()) <= set((subj_claims.get("scope") or "").split()):
            refuse(400, "invalid_scope", "scope-widened")
            return

        grant = w.issue_chain_grant(
            AS_A_KEY,
            kid="as_a-1",
            iss="http://maurice.ietf127.example:5051",
            aud=aud,
            sub=subj_claims["sub"],
            scope=scope,
            txn=subj_claims["txn"],
            tctx=subj_claims.get("tctx"),
            client_id=ctx["peer_id"],
        )
        _log_journal({"service": "as-a", "direction": "exchange", "txn": subj_claims["txn"],
                      "sub": subj_claims["sub"], "scope": scope, "decision": "accept", "status": 200, "case": case_id})
        self.send_json_response(200, {"access_token": grant, "issued_token_type": w.TT_JWT, "token_type": "N_A",
                                      "expires_in": GRANT_TTL}, headers={"Cache-Control": "no-store"})


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
            expected_aud="http://maurice.ietf127.example:5050", seen_nonces=NONCES["maurice"])
        if not ok:
            _log_journal({
                "service": "maurice",
                "direction": "inbound",
                "decision": "reject",
                "reason": reason,
                "status": status,
                "case": case_id,
            })
            ctype, problem = w.auth_failure_body(status)  # http-signature-08 s3.6: no per-check reason in the body
            self.send_response(status)
            if status == 401:
                self.send_header("WWW-Authenticate", 'WPT realm="wimse"')
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(json.dumps(problem).encode("utf-8"))
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

    checks rep["txn"], rep["sub"] and rep["aud"] equal the original's (txn-tokens-11 s13.15; else
    (False, "txn-mutated" / "sub-mutated" / "aud-mutated")), and checks
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
    if rep.get("sub") != orig.get("sub"):
        return False, "sub-mutated"
    if rep.get("aud") != orig.get("aud"):
        return False, "aud-mutated"

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
