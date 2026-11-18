"""A deliberately incomplete WIMSE-verifying HTTP server, for testing the inbound driver.

It reuses `verify_wimse_proof` from peers/wimse.py (the repository's own verifier) and adds only
what the draft-based cases need around it: the route, RFC 9457 problem responses, a grant table,
rejection of wimse-sign-response (501) and of mixed credentials. It does NOT implement an issuer
allowlist, so the cases that depend on one (IN6, C12, C12b) are expected to fail against it. It is
test scaffolding, not a reference implementation, and says nothing about Maurice.

    python tests/stub_server.py --port 18080 [--audience http://127.0.0.1:18080]
"""
import argparse
import json
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "peers"))
import wimse as w  # noqa: E402

PTYPE = "https://iana.org/assignments/http-problem-types#"
GRANTS = {f"wimse://peer.ietf127.example{p}" for p in ("/client", "/a~b", "/a/b")}
ROUTE_PREFIX = "/api/v2/agents/"


def make_server(port, audience, keys_dir=ROOT / "keys", status_400_only=False):
    trust = {"peer.ietf127.example": json.loads((keys_dir / "peer.jwks.json").read_text())}
    seen = set()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, status, ptype=None, www=None):
            body = json.dumps({"type": PTYPE + ptype, "status": status} if ptype else {"ok": True}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/problem+json" if ptype else "application/json")
            self.send_header("Content-Length", str(len(body)))
            if www:
                self.send_header("WWW-Authenticate", www)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if not (self.path.startswith(ROUTE_PREFIX) and self.path.endswith("/executions")):
                return self.reply(404)
            auth = self.headers.get_all("Authorization") or []
            sig_in = self.headers.get("Signature-Input", "")
            if self.headers.get("X-API-Key") or any(a.lower().startswith("bearer ") for a in auth):
                return self.reply(400, "wimse-signature-invalid")  # mixed credentials
            if ";wimse-sign-response" in sig_in:
                return self.reply(501, "wimse-signed-response-unsupported")
            headers = {k: v for k, v in self.headers.items()}
            ok, status, reason, ctx = w.verify_wimse_proof(
                "POST", self.path, headers, body, trust, expected_aud=audience, seen_nonces=seen)
            if not ok:
                if status == 401 and not status_400_only:
                    return self.reply(401, "wimse-proof-required", www="WPT")
                return self.reply(400, "wimse-signature-invalid")
            if ctx["peer_id"] not in GRANTS:
                return self.reply(403, "not-authorized")
            self.reply(200)

    return ThreadingHTTPServer(("127.0.0.1", port), H)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--audience", help="default: http://127.0.0.1:<port>")
    ap.add_argument("--status-400-only", action="store_true",
                    help="answer every proof failure with 400 (http-signature-08 style) instead of 401 + WWW-Authenticate: WPT")
    a = ap.parse_args()
    srv = make_server(a.port, a.audience or f"http://127.0.0.1:{a.port}", status_400_only=a.status_400_only)
    print(f"stub listening on 127.0.0.1:{a.port}", flush=True)
    srv.serve_forever()
