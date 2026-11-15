"""Northbank Financial Institution - WIMSE Settlement API.

Endpoints:
- POST /api/transfer: Cross-domain supplier payment settlement
- GET /health: Health readiness check
- GET /.well-known/jwks.json: Northbank public keys
"""
from __future__ import annotations

import json
import pathlib
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives import serialization

# Ensure peers directory is on path
PEERS_DIR = pathlib.Path(__file__).resolve().parent
if str(PEERS_DIR) not in sys.path:
    sys.path.insert(0, str(PEERS_DIR))

import wimse as w

ROOT = PEERS_DIR.parent
KEYS_DIR = ROOT / "keys"

# Load keys
harbor_jwks = json.loads((KEYS_DIR / "harbor.jwks.json").read_text())
northbank_jwks = json.loads((KEYS_DIR / "northbank.jwks.json").read_text())
northbank_key = serialization.load_pem_private_key((KEYS_DIR / "northbank.pem").read_bytes(), None)

# Trust bundle for Northbank
TRUST_JWKS = {
    "harbor.example": harbor_jwks,
    "northbank.example": northbank_jwks,
}

JOURNAL: list[dict[str, Any]] = []
JOURNAL_LOCK = threading.Lock()
JOURNAL_FILE: pathlib.Path | None = None
SEEN_NONCES: set[str] = set()


def record_journal(entry: dict[str, Any]) -> None:
    with JOURNAL_LOCK:
        JOURNAL.append(entry)
        if JOURNAL_FILE:
            JOURNAL_FILE.parent.mkdir(parents=True, exist_ok=True)
            with JOURNAL_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")


def process_transfer(method: str, path: str, headers: dict[str, str], body: bytes, test_case: str = "scenario_1_payment") -> tuple[int, dict[str, str], bytes]:
    """Execute Northbank transfer logic directly or via HTTP server."""
    u = urllib.parse.urlsplit(path)
    if u.path != "/api/transfer":
        return 404, {"Content-Type": "application/json"}, b'{"error": "not found"}'

    expected_aud = "wimse://northbank.example/api/transfer"
    ok, code, reason, claims = w.verify_wimse_proof(
        method,
        path,
        headers,
        body,
        TRUST_JWKS,
        expected_aud=expected_aud,
        seen_nonces=SEEN_NONCES,
    )

    if not ok:
        record_journal({
            "case": test_case,
            "service": "northbank-transfer",
            "status": code,
            "decision": "reject",
            "reason": reason,
        })
        err_body = json.dumps({"type": f"https://wimse.ietf127.example/errors#{reason}", "status": code, "detail": reason}).encode()
        return code, {"Content-Type": "application/problem+json"}, err_body

    # Proof accepted
    try:
        req_data = json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        req_data = {}

    txn_token = headers.get("Txn-Token", "")
    txn_ref = req_data.get("ref", "7f3a21")
    invoice = req_data.get("invoice", "4471")
    amount = req_data.get("amount", 4200)
    supplier = req_data.get("to", "supplier_acme_iban_xxx")
    peer_id = (claims or {}).get("peer_id", "wimse://harbor.example/agent/payments")

    settled_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    receipt_id = f"nb-rcpt-{txn_ref}-{invoice}"

    record_journal({
        "case": test_case,
        "service": "northbank-transfer",
        "status": 200,
        "decision": "settled",
        "txn": txn_ref,
        "invoice": invoice,
        "amount": amount,
        "supplier": supplier,
        "peer_id": peer_id,
        "settled_at": settled_at,
        "receipt": receipt_id,
    })

    resp_payload = {
        "status": "paid",
        "txn": txn_ref,
        "invoice": invoice,
        "amount": amount,
        "currency": "USD",
        "supplier": supplier,
        "settled_at": settled_at,
        "receipt": receipt_id,
        "payer": peer_id,
    }
    resp_bytes = json.dumps(resp_payload, indent=2).encode("utf-8")
    return 200, {"Content-Type": "application/json"}, resp_bytes


class NorthbankHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = b'{"status": "ok", "service": "northbank-transfer"}'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if u.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps(northbank_jwks).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        u = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        test_case = self.headers.get("X-Test-Case", "scenario_1_payment")

        code, resp_hdrs, resp_body = process_transfer(
            self.command,
            self.path,
            dict(self.headers),
            body,
            test_case,
        )

        self.send_response(code)
        for k, v in resp_hdrs.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def start_server(port: int = 5070, journal_file: pathlib.Path | None = None) -> ThreadingHTTPServer:
    global JOURNAL_FILE
    if journal_file:
        JOURNAL_FILE = journal_file
    srv = ThreadingHTTPServer(("127.0.0.1", port), NorthbankHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Northbank Transfer Service")
    parser.add_argument("--port", type=int, default=5070, help="Port to listen on (default: 5070)")
    parser.add_argument("--journal-out", type=pathlib.Path, default=None, help="Journal output file")
    args = parser.parse_args()

    srv = start_server(args.port, args.journal_out)
    print(f"Northbank Transfer Service running on http://127.0.0.1:{args.port}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
