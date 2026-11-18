#!/usr/bin/env python3
"""Multi-Agent Chain & Attack Driver for WIMSE interoperability testing.

Executes and verifies:
- Normal Path (B_CHAIN): 3-agent 2-domain call chain with unified txn correlation
- Negative / Attack Cases (C5, C6, C7, C8, C9, C9b, C10, D1, D2, D3_exp, D3_sig,
  D3_typ, D3_reqwl, D3_dup, D4, D5, D6, D7, T1-T5)
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import socket
import sys
import time
import urllib.parse
import uuid
from typing import Any

from cryptography.hazmat.primitives import serialization

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import journal as peer_journal
import wimse as w
from domain_a import validate_narrowed_replacement

KEYS_DIR = ROOT / "keys"

CLIENT_ID = "wimse://peer.ietf127.example/client"
COORDINATOR_ID = "wimse://rich.ietf127.example/agent/coordinator"
RESEARCH_ID = "wimse://rich.ietf127.example/agent/research"
OPERATOR_ID = "wimse://rich.ietf127.example/operator"
TTS_A_URL = "http://127.0.0.1:5051/tts/token"
TTS_B_URL = "http://127.0.0.1:5061/tts/token"
TTS_A_PROOF_AUD = "http://maurice.ietf127.example:5051"
FILE_AUD = "http://rich.ietf127.example:5063"


def _load_private_key(name: str):
    p = KEYS_DIR / f"{name}.pem"
    return serialization.load_pem_private_key(p.read_bytes(), None)


def _load_jwks(name: str) -> dict:
    p = KEYS_DIR / f"{name}.jwks.json"
    return json.loads(p.read_text(encoding="utf-8"))


PEER_KEY = _load_private_key("peer")
ROGUE_KEY = _load_private_key("rogue")
RICH_KEY = _load_private_key("rich")  # Domain B WIT issuer
COORD_KEY = _load_private_key("coordinator")  # workload keys: one per workload
RESEARCH_KEY = _load_private_key("research")
OPERATOR_KEY = _load_private_key("operator")
TTS_A_KEY = _load_private_key("tts_a")
TTS_B_KEY = _load_private_key("tts_b")
AS_A_KEY = _load_private_key("as_a")
AS_B_KEY = _load_private_key("as_b")

TTS_A_JWKS = _load_jwks("tts_a")
TTS_B_JWKS = _load_jwks("tts_b")
PEER_JWKS = _load_jwks("peer")
RICH_JWKS = _load_jwks("rich")
AS_A_JWKS = _load_jwks("as_a")
AS_B_JWKS = _load_jwks("as_b")

CASES_FILE = ROOT / "chain_cases.json"
CASES = {c["id"]: c for c in json.loads(CASES_FILE.read_text(encoding="utf-8"))}

JOURNAL_RECORDS: list[dict[str, Any]] = []


def is_port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def safe_send(req: w.Req, case: str, timeout: int = 15) -> w.Resp:
    """Send an HTTP request while enforcing the outbound cross-domain guard

    and ensuring X-Test-Case is present.
    """
    req.headers["X-Test-Case"] = case

    # Outbound cross-domain guard check (WP04 / DESIGN §24.20)
    u = urllib.parse.urlsplit(req.url)
    port = u.port or (443 if u.scheme == "https" else 80)
    if port in (5060, 5061, 5062, 5063) or "rich.ietf127.example" in (u.hostname or ""):
        all_headers = list(req.headers.items()) + list(req.extra_headers)
        for k, v in all_headers:
            if k.lower() == "txn-token":
                try:
                    _, claims, _, _ = w.parse_jwt(v)
                    if claims.get("aud") == "maurice.ietf127.example":
                        raise PermissionError("txn-cross-domain")
                except PermissionError:
                    raise
                except Exception:
                    pass

    return w.send(req, case=case, timeout=timeout)


wimse_fetch = safe_send


def peer_wit(wkey, sub: str = CLIENT_ID) -> str:
    """WIT of a Domain A / peer workload, issued by the peer issuer and bound to wkey."""
    return w.issue_wit(PEER_KEY, kid="peer-1", iss="http://peer.ietf127.example", sub=sub,
                       workload_pub_jwk=w.jwk_from_public(wkey.public_key()))


def rich_wit(wkey, sub: str) -> str:
    """WIT of a Domain B workload, issued by the Domain B issuer and bound to the workload's own key."""
    return w.issue_wit(RICH_KEY, kid="rich-1", iss="http://rich.ietf127.example", sub=sub,
                       workload_pub_jwk=w.jwk_from_public(wkey.public_key()))


def signed_form(url: str, form: bytes, wit: str, wkey, aud: str) -> w.Req:
    """A form POST authenticated with a WIT and an HTTP message signature."""
    return w.http_sig("POST", url, form, wit, wkey, aud=aud, content_type=w.FORM_CT)


def new_txn_form(scope: str, *, tctx: dict | None = None, rctx: dict | None = None, sub: str = "user:alice") -> bytes:
    """Txn-Token request that starts a transaction at TTS-A (txn-tokens-11 s11.1, s11.2.2)."""
    return w.txn_token_request(
        audience="maurice.ietf127.example", scope=scope, subject_token=json.dumps({"sub": sub}),
        subject_token_type=w.TT_UNSIGNED_JSON, request_context=rctx, request_details=tctx)


def replace_form(txn_token: str, scope: str, audience: str = "maurice.ietf127.example") -> bytes:
    """Txn-Token request that replaces (narrows) an existing Txn-Token (s13.15)."""
    return w.txn_token_request(audience=audience, scope=scope, subject_token=txn_token, subject_token_type=w.TT_TXN)


def reason_of(r: w.Resp) -> str | None:
    try:
        return json.loads(r.body.decode()).get("reason")
    except Exception:
        return None


def error_of(r: w.Resp) -> str | None:
    """What the response body says: an OAuth error code, a reason, or the problem type (after '#'); None if nothing."""
    try:
        d = json.loads(r.body.decode())
    except Exception:
        return None
    if d.get("error") or d.get("reason"):
        return d.get("error") or d.get("reason")
    t = d.get("type", "")
    return t.rsplit("#", 1)[-1] if t and t != "about:blank" else None


def claims_of(token: str) -> dict:
    return w.parse_jwt(token)[1]


# ---------------------------------------------------------------------------
# Case Implementations
# ---------------------------------------------------------------------------


def run_b_chain(with_maurice: bool) -> tuple[bool, list[str], list[dict]]:
    notes = []
    journal = []
    wkey = w.new_workload_key("ES256")  # the client workload's key; its WIT names it in cnf
    wit = peer_wit(wkey)

    def step(n, service, status, txn):
        journal.append({"case": "B_CHAIN", "step": n, "service": service, "status": status, "txn": txn,
                        "decision": "accept"})

    # 1. TTS-A: Txn-Token request authenticated with the client's WIT + HTTP signature
    r1 = safe_send(
        signed_form(TTS_A_URL, new_txn_form("files:read files:list", tctx={"file": "Q3.pdf"},
                                            rctx={"req_ip": "127.0.0.1", "authn": "wimse-http-sig"}),
                    wit, wkey, TTS_A_PROOF_AUD),
        case="B_CHAIN",
    )
    if r1.status != 200:
        return False, [f"Step 1 TTS-A failed ({r1.status}): {r1.body.decode()}"], journal
    d1 = json.loads(r1.body.decode("utf-8"))
    if d1.get("issued_token_type") != w.TT_TXN or d1.get("token_type") != "N_A" or "refresh_token" in d1:
        return False, [f"Step 1 TTS-A response is not a Txn-Token response: {sorted(d1)}"], journal
    txn_token_a = d1["access_token"]
    c1 = claims_of(txn_token_a)
    txn_a = c1["txn"]
    if c1["req_wl"] != CLIENT_ID:
        return False, [f"Step 1 req_wl {c1['req_wl']} is not the WIT subject"], journal
    notes.append(f"step1=tts-a status={r1.status} txn={txn_a}")
    step(1, "tts-a", r1.status, txn_a)

    # 2. If with_maurice or port 5050 is open:
    if with_maurice:
        wkey_m = w.new_workload_key("ES256")
        req_m = w.http_sig(
            "POST",
            "http://127.0.0.1:5050/api/v2/agents/dbsccjan18nkaiapu9v0/workflows/text-stats/executions",
            b'{"inputs": {"text": "hello wimse"}}',
            peer_wit(wkey_m),
            wkey_m,
            aud="http://maurice.ietf127.example:5050",
            headers={"Txn-Token": txn_token_a},
        )
        r_m = safe_send(req_m, case="B_CHAIN")
        if r_m.status != 200:
            return False, notes + [f"Step 2 Maurice failed ({r_m.status}): {r_m.body.decode()}"], journal
        notes.append(f"step2=maurice status={r_m.status}")
        step(2, "maurice", r_m.status, txn_a)

    # 3. AS-A: RFC 8693 token exchange for a JWT authorization grant (identity-chaining-17 s2.3)
    r3 = safe_send(
        signed_form(
            "http://127.0.0.1:5051/oauth/token",
            w.chain_exchange_request(subject_token=txn_token_a, resource="http://rich.ietf127.example:5061"),
            wit, wkey, TTS_A_PROOF_AUD),
        case="B_CHAIN",
    )
    if r3.status != 200:
        return False, notes + [f"Step 3 AS-A failed ({r3.status}): {r3.body.decode()}"], journal
    d3 = json.loads(r3.body.decode("utf-8"))
    if d3.get("issued_token_type") != w.TT_JWT or d3.get("token_type") != "N_A" or not d3.get("expires_in"):
        return False, notes + [f"Step 3 AS-A response is not an RFC 8693 response: {sorted(d3)}"], journal
    assertion = d3["access_token"]
    c3 = claims_of(assertion)
    if c3["txn"] != txn_a or c3.get("client_id") != CLIENT_ID:
        return False, notes + [f"Step 3 AS-A grant claims mismatch: txn={c3['txn']} client_id={c3.get('client_id')}"], journal
    notes.append(f"step3=as-a status={r3.status} txn={c3['txn']}")
    step(3, "as-a", r3.status, txn_a)

    # 4. AS-B: RFC 7523 JWT bearer grant -> access token
    r4 = safe_send(
        w.Req("POST", "http://127.0.0.1:5061/oauth/token", {"Content-Type": w.FORM_CT}, w.jwt_bearer_request(assertion)),
        case="B_CHAIN",
    )
    if r4.status != 200:
        return False, notes + [f"Step 4 AS-B failed ({r4.status}): {r4.body.decode()}"], journal
    d4 = json.loads(r4.body.decode("utf-8"))
    if d4.get("token_type") != "Bearer" or not d4.get("expires_in"):
        return False, notes + [f"Step 4 AS-B response is not an RFC 6749 s5.1 response: {sorted(d4)}"], journal
    access_token = d4["access_token"]
    c4 = claims_of(access_token)
    if c4["txn"] != txn_a or c4.get("client_id") != CLIENT_ID:
        return False, notes + [f"Step 4 AS-B access token claims mismatch: txn={c4['txn']} client_id={c4.get('client_id')}"], journal
    notes.append(f"step4=as-b status={r4.status} txn={c4['txn']}")
    step(4, "as-b", r4.status, txn_a)

    # 5. POST http://127.0.0.1:5060/coordinate
    req_coord = w.http_sig(
        "POST",
        "http://127.0.0.1:5060/coordinate",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5060",
        headers={"Authorization": "Bearer " + access_token},
    )
    r5 = safe_send(req_coord, case="B_CHAIN")
    if r5.status != 200:
        return False, notes + [f"Step 5 Coordinator failed ({r5.status}): {r5.body.decode()}"], journal
    d5 = json.loads(r5.body.decode("utf-8"))
    if d5.get("summary") != "$4.2M":
        return False, notes + [f"Step 5 summary mismatch: {d5.get('summary')}"], journal
    if d5.get("txn") != txn_a:
        return False, notes + [f"Step 5 coord txn mismatch: {d5.get('txn')} != {txn_a}"], journal
    expected_hops = ["agent1:maurice", "agent2:coordinator", "agent3:research", "tool:files"]
    if d5.get("hops") != expected_hops:
        return False, notes + [f"Step 5 hops mismatch: {d5.get('hops')}"], journal

    notes.append(f"step5=coord status={r5.status} summary={d5.get('summary')} hops={d5.get('hops')}")
    step(5, "agent2-coordinator", r5.status, txn_a)
    return True, notes, journal


def run_c5() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok1 = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    tok2 = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:bob",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok1},
    )
    # Swap Txn-Token after signing
    req.headers["Txn-Token"] = tok2
    r = safe_send(req, case="C5")
    reason = error_of(r)
    ok = (r.status == 400 and reason == "wimse-signature-invalid")
    notes = [f"status={r.status} want=400 body={reason} want_body=wimse-signature-invalid (cause is in the peer journal)"]
    journal = [{"case": "C5", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_c6() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    # Use aud="foreign.ietf127.example" so aud="maurice.ietf127.example" NEVER crosses to Domain B on wire
    tok_foreign = w.issue_txn_token(
        TTS_A_KEY,
        kid="tts_a-1",
        iss="http://maurice.ietf127.example:5051",
        aud="foreign.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok_foreign},
    )
    r = safe_send(req, case="C6")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 403 and reason == "txn-token-invalid")
    notes = [f"status={r.status} want=403 reason={reason} want_reason=txn-token-invalid"]
    journal = [{"case": "C6", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_c7() -> tuple[bool, list[str], list[dict]]:
    wkey = COORD_KEY
    wit = rich_wit(wkey, COORDINATOR_ID)
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read files:list",
        req_wl="wimse://rich.ietf127.example/agent/coordinator",
        tctx={"file": "Q3.pdf"},
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5062/research",
        json.dumps({"file": "Q3.pdf", "follow_injection": True}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5062",
        headers={"Txn-Token": tok},
    )
    r = safe_send(req, case="C7")
    data = {}
    try:
        data = json.loads(r.body.decode())
    except Exception:
        pass
    file_status = data.get("file_status")
    inj_status = data.get("injection_read_status")
    ok = (r.status == 200 and file_status == 200 and inj_status == 403)
    notes = [f"status={r.status} file_status={file_status} inj_status={inj_status}"]
    journal = [
        {"case": "C7", "service": "agent3-research", "status": r.status, "decision": "accept"},
        {"case": "C7", "service": "file-tool", "status": inj_status, "decision": "reject", "reason": "not-authorized"},
    ]
    return ok, notes, journal


def run_c8() -> tuple[bool, list[str], list[dict]]:
    wkey = COORD_KEY
    wit = rich_wit(wkey, COORDINATOR_ID)
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read files:list",
        req_wl="wimse://rich.ietf127.example/agent/coordinator",
        tctx={"file": "Q3.pdf"},
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5062/research",
        json.dumps({"file": "Q3.pdf", "follow_injection": True}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5062",
        headers={"Txn-Token": tok},
    )
    r = safe_send(req, case="C8")
    data = {}
    try:
        data = json.loads(r.body.decode())
    except Exception:
        pass
    leaked = data.get("leaked_credentials")
    ctx_str = json.dumps(data.get("caller_context", {}))
    has_raw_jwt = "eyJ" in ctx_str
    ok = (r.status == 200 and leaked is False and not has_raw_jwt)
    notes = [f"status={r.status} leaked={leaked} raw_jwt_in_ctx={has_raw_jwt}"]
    journal = [{"case": "C8", "service": "agent3-research", "status": r.status, "decision": "accept"}]
    return ok, notes, journal


def run_c9() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
    )
    r = safe_send(req, case="C9")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 403 and reason == "not-authorized")
    notes = [f"status={r.status} want=403 reason={reason} want_reason=not-authorized"]
    journal = [{"case": "C9", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_c9b() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/index",
        b"{}",
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok},
    )
    r = safe_send(req, case="C9b")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 403 and reason == "not-authorized")
    notes = [f"status={r.status} want=403 reason={reason} want_reason=not-authorized"]
    journal = [{"case": "C9b", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def admin_revoke(body: dict) -> w.Req:
    """A /admin/revoke call authenticated as the operator workload (WIT + HTTP signature)."""
    return w.http_sig(
        "POST", "http://127.0.0.1:5063/admin/revoke", json.dumps(body).encode("utf-8"),
        rich_wit(OPERATOR_KEY, OPERATOR_ID), OPERATOR_KEY, aud=FILE_AUD,
    )


def run_c10() -> tuple[bool, list[str], list[dict]]:
    wkey = RESEARCH_KEY
    wit = rich_wit(wkey, RESEARCH_ID)
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl=RESEARCH_ID,
        tctx={"file": "Q3.pdf"},
    )

    def read_file() -> w.Resp:
        return safe_send(w.http_sig(
            "POST", "http://127.0.0.1:5063/files/read", json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
            wit, wkey, aud=FILE_AUD, headers={"Txn-Token": tok},
        ), case="C10")

    # Step 1: Valid call -> 200
    r1 = read_file()
    # Step 2: The operator revokes the workload
    r_rev = safe_send(admin_revoke({"workload": RESEARCH_ID}), case="C10")
    # Step 3: Call /files/read again -> 403 revoked
    r3 = read_file()
    reason3 = reason_of(r3)
    # Step 4: The operator clears the revocation
    r_clr = safe_send(admin_revoke({"clear": True}), case="C10")

    ok = (
        r1.status == 200
        and r_rev.status == 200
        and r3.status == 403
        and reason3 == "revoked"
        and r_clr.status == 200
    )
    notes = [
        f"step1={r1.status} step2_rev={r_rev.status} step3_revoked={r3.status} reason={reason3} step4_clr={r_clr.status}"
    ]
    journal = [
        {"case": "C10", "step": 1, "service": "file-tool", "status": r1.status, "decision": "accept"},
        {"case": "C10", "step": 3, "service": "file-tool", "status": r3.status, "decision": "reject", "reason": reason3},
    ]
    return ok, notes, journal


def run_d1() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok},
        drop_components=("txn-token",),
    )
    r = safe_send(req, case="D1")
    reason = error_of(r)
    ok = (r.status == 400 and reason == "wimse-signature-invalid")
    notes = [f"status={r.status} want=400 body={reason} want_body=wimse-signature-invalid (cause is in the peer journal)"]
    journal = [{"case": "D1", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_d2(with_maurice: bool) -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    req = w.wpt_request(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        alg="ES256",
        headers={"Txn-Token": tok},
        txn_token=tok,
        claims_extra={"tth": "wrong_hash"},
    )
    r = safe_send(req, case="D2")
    auth_hdr = r.headers.get("www-authenticate", "")
    reason = error_of(r)
    ok = (r.status == 401 and auth_hdr.startswith("WPT") and reason is None)
    notes = [f"file_tool status={r.status} www_auth={auth_hdr} reason={reason}"]
    journal = [{"case": "D2", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]

    if with_maurice:
        tok_m = w.issue_txn_token(
            TTS_A_KEY,
            kid="tts_a-1",
            iss="http://maurice.ietf127.example:5051",
            aud="maurice.ietf127.example",
            txn=str(uuid.uuid4()),
            sub="user:alice",
            scope="files:read",
            req_wl="wimse://peer.ietf127.example/client",
        )
        req_m = w.wpt_request(
            "POST",
            "http://127.0.0.1:5050/api/v2/agents/dbsccjan18nkaiapu9v0/workflows/text-stats/executions",
            b'{"inputs": {"text": "hello wimse"}}',
            wit,
            wkey,
            aud="http://maurice.ietf127.example:5050",
            alg="ES256",
            headers={"Txn-Token": tok_m},
            txn_token=tok_m,
            claims_extra={"tth": "wrong_hash"},
        )
        rm = safe_send(req_m, case="D2")
        auth_hdr_m = rm.headers.get("www-authenticate", "")
        reason_m = error_of(rm)
        ok_m = (rm.status == 401 and auth_hdr_m.startswith("WPT"))
        ok = ok and ok_m
        notes.append(f"maurice status={rm.status} www_auth={auth_hdr_m} reason={reason_m}")
        journal.append({"case": "D2", "service": "maurice", "status": rm.status, "decision": "reject", "reason": reason_m})

    return ok, notes, journal


def run_d3_exp() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
        ttl=-10,
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok},
    )
    r = safe_send(req, case="D3_exp")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 403 and reason == "txn-token-invalid")
    notes = [f"status={r.status} want=403 reason={reason} want_reason=txn-token-invalid"]
    journal = [{"case": "D3_exp", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_d3_sig() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok = w.issue_txn_token(
        ROGUE_KEY,
        kid="rogue-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok},
    )
    r = safe_send(req, case="D3_sig")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 403 and reason == "txn-token-invalid")
    notes = [f"status={r.status} want=403 reason={reason} want_reason=txn-token-invalid"]
    journal = [{"case": "D3_sig", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_d3_typ() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
        typ="jwt",
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok},
    )
    r = safe_send(req, case="D3_typ")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 403 and reason == "txn-token-invalid")
    notes = [f"status={r.status} want=403 reason={reason} want_reason=txn-token-invalid"]
    journal = [{"case": "D3_typ", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_d3_reqwl() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
        drop=("req_wl",),
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok},
    )
    r = safe_send(req, case="D3_reqwl")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 403 and reason == "txn-token-invalid")
    notes = [f"status={r.status} want=403 reason={reason} want_reason=txn-token-invalid"]
    journal = [{"case": "D3_reqwl", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_d3_dup() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok1 = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    tok2 = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:bob",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok1},
    )
    req.extra_headers.append(("Txn-Token", tok2))
    r = safe_send(req, case="D3_dup")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 403 and reason == "txn-token-invalid")
    notes = [f"status={r.status} want=403 reason={reason} want_reason=txn-token-invalid"]
    journal = [{"case": "D3_dup", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_d4() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    tok = w.issue_txn_token(
        TTS_B_KEY,
        kid="tts_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="rich.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="profile:view",
        req_wl="wimse://peer.ietf127.example/client",
        tctx={"file": "Q3.pdf"},
    )
    req = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok},
    )
    r = safe_send(req, case="D4")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 403 and reason == "not-authorized")
    notes = [f"status={r.status} want=403 reason={reason} want_reason=not-authorized"]
    journal = [{"case": "D4", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]
    return ok, notes, journal


def run_d5() -> tuple[bool, list[str], list[dict]]:
    notes = []
    journal = []

    # 1. Outbound guard verification
    tok_a = w.issue_txn_token(
        TTS_A_KEY,
        kid="tts_a-1",
        iss="http://maurice.ietf127.example:5051",
        aud="maurice.ietf127.example",
        txn=str(uuid.uuid4()),
        sub="user:alice",
        scope="files:read",
        req_wl="wimse://peer.ietf127.example/client",
    )
    guard_blocked = False
    try:
        dummy_req = w.Req("POST", "http://127.0.0.1:5063/files/read", {"Txn-Token": tok_a}, b"{}")
        safe_send(dummy_req, case="D5")
    except PermissionError as pe:
        if "txn-cross-domain" in str(pe):
            guard_blocked = True
    notes.append(f"outbound_guard_blocked={guard_blocked}")
    journal.append({"case": "D5", "service": "driver-guard", "decision": "reject", "reason": "txn-cross-domain"})

    # 2. Sending non-grant JWT (typ="at+jwt") to POST http://127.0.0.1:5061/oauth/token
    non_grant = w.issue_access_token(
        AS_B_KEY,
        kid="as_b-1",
        iss="http://rich.ietf127.example:5061",
        aud="http://rich.ietf127.example:5060",
        sub="user:alice",
        scope="files:read",
        txn=str(uuid.uuid4()),
    )
    req = w.Req("POST", "http://127.0.0.1:5061/oauth/token", {"Content-Type": w.FORM_CT},
                w.jwt_bearer_request(non_grant))
    r = safe_send(req, case="D5")
    reason = error_of(r)
    ok = guard_blocked and (r.status == 400 and reason == "invalid_grant")
    notes.append(f"as-b status={r.status} want=400 error={reason} want_error=invalid_grant")
    journal.append({"case": "D5", "service": "as-b", "status": r.status, "decision": "reject", "reason": reason})
    return ok, notes, journal


def run_d6() -> tuple[bool, list[str], list[dict]]:
    """Replacement Txn-Tokens at TTS-A (txn-tokens-11 s13.15).

    On the wire: the original token, a narrowed replacement (200), a widening request (refused, invalid_scope) and a
    replacement request from an expired token (refused, invalid_grant). Offline: the client-side validator rejects
    widened, txn-, sub- and aud-mutated tokens that this driver forges, because a conformant TTS never issues them.
    """
    wkey = w.new_workload_key("ES256")
    wit = peer_wit(wkey)

    def ask(form: bytes) -> w.Resp:
        return safe_send(signed_form(TTS_A_URL, form, wit, wkey, TTS_A_PROOF_AUD), case="D6")

    r1 = ask(new_txn_form("files:read files:list"))
    if r1.status != 200:
        return False, [f"Orig token failed: {r1.status}"], []
    orig_tok = json.loads(r1.body.decode())["access_token"]

    r2 = ask(replace_form(orig_tok, "files:read"))
    if r2.status != 200:
        return False, [f"Narrowed token failed: {r2.status}"], []
    nar_tok = json.loads(r2.body.decode())["access_token"]
    ok_nar, msg_nar = validate_narrowed_replacement(orig_tok, nar_tok, TTS_A_JWKS)

    r3 = ask(replace_form(orig_tok, "files:read files:write"))
    err3 = error_of(r3)

    oc = claims_of(orig_tok)
    expired = w.issue_txn_token(
        TTS_A_KEY, kid="tts_a-1", iss=oc["iss"], aud=oc["aud"], txn=oc["txn"], sub=oc["sub"], scope=oc["scope"],
        req_wl=oc["req_wl"], tctx=oc["tctx"], ttl=-10)
    r4 = ask(replace_form(expired, "files:read"))
    err4 = error_of(r4)

    def forged(**over):
        kw = dict(kid="tts_a-1", iss=oc["iss"], aud=oc["aud"], txn=oc["txn"], sub=oc["sub"], scope="files:read",
                  req_wl=oc["req_wl"], tctx=oc["tctx"]) | over
        return w.issue_txn_token(TTS_A_KEY, **kw)

    ok_widen, msg_widen = validate_narrowed_replacement(orig_tok, forged(scope="files:read files:write"), TTS_A_JWKS)
    ok_mut, msg_mut = validate_narrowed_replacement(orig_tok, forged(txn="mutated-" + uuid.uuid4().hex[:8]), TTS_A_JWKS)
    ok_sub, msg_sub = validate_narrowed_replacement(orig_tok, forged(sub="user:mallory"), TTS_A_JWKS)
    ok_aud, msg_aud = validate_narrowed_replacement(orig_tok, forged(aud="foreign.ietf127.example"), TTS_A_JWKS)

    ok = (
        ok_nar is True and msg_nar == "ok"
        and r3.status == 400 and err3 == "invalid_scope"
        and r4.status == 400 and err4 == "invalid_grant"
        and (ok_widen, msg_widen) == (False, "scope-widened")
        and (ok_mut, msg_mut) == (False, "txn-mutated")
        and (ok_sub, msg_sub) == (False, "sub-mutated")
        and (ok_aud, msg_aud) == (False, "aud-mutated")
    )
    notes = [
        f"nar=({ok_nar},{msg_nar}) widen_request={r3.status} {err3} expired_parent={r4.status} {err4} "
        f"forged: widen=({ok_widen},{msg_widen}) mut=({ok_mut},{msg_mut}) sub=({ok_sub},{msg_sub}) aud=({ok_aud},{msg_aud})"
    ]
    journal = [{"case": "D6", "service": "tts-a", "status": 200, "decision": "accept", "reason": "accept"}]
    return ok, notes, journal


def run_d7() -> tuple[bool, list[str], list[dict]]:
    """A grant for the wrong audience never gets accepted: AS-A will not mint it for an unknown target, and AS-B
    refuses one that is minted anyway (forged here with AS-A's key)."""
    wkey = w.new_workload_key("ES256")
    wit = peer_wit(wkey)

    # 1. Get Txn-Token from TTS-A
    r1 = safe_send(signed_form(TTS_A_URL, new_txn_form("files:read"), wit, wkey, TTS_A_PROOF_AUD), case="D7")
    if r1.status != 200:
        return False, [f"TTS-A failed: {r1.status}"], []
    tok_a = json.loads(r1.body.decode())["access_token"]
    ca = claims_of(tok_a)

    # 2. AS-A refuses an exchange that names an unknown authorization server
    r2 = safe_send(signed_form(
        "http://127.0.0.1:5051/oauth/token",
        w.chain_exchange_request(subject_token=tok_a, resource="http://wrong.example/oauth/token"),
        wit, wkey, TTS_A_PROOF_AUD), case="D7")
    err2 = error_of(r2)

    # 3. A grant with the wrong aud, signed with AS-A's key, is refused by AS-B
    wrong_grant = w.issue_chain_grant(
        AS_A_KEY, kid="as_a-1", iss="http://maurice.ietf127.example:5051", aud="http://wrong.example/oauth/token",
        sub=ca["sub"], scope=ca["scope"], txn=ca["txn"], tctx=ca.get("tctx"), client_id=CLIENT_ID)
    r3 = safe_send(
        w.Req("POST", "http://127.0.0.1:5061/oauth/token", {"Content-Type": w.FORM_CT}, w.jwt_bearer_request(wrong_grant)),
        case="D7")
    reason = error_of(r3)
    ok = (r2.status == 400 and err2 == "invalid_target" and r3.status == 400 and reason == "invalid_grant")
    notes = [f"as_a_status={r2.status} {err2} as_b_status={r3.status} want=400 error={reason} want_error=invalid_grant"]
    journal = [
        {"case": "D7", "service": "as-a", "status": r2.status, "decision": "reject", "reason": err2},
        {"case": "D7", "service": "as-b", "status": r3.status, "decision": "reject", "reason": reason},
    ]
    return ok, notes, journal


def run_t1() -> tuple[bool, list[str], list[dict]]:
    """TTS-A request with no WIT and no signature: the TTS authenticates the workload (txn-tokens-11 s11.3, s11.5)."""
    body = w.form_encode({"req_wl": CLIENT_ID}) + b"&" + new_txn_form("files:read")
    r = safe_send(w.Req("POST", TTS_A_URL, {"Content-Type": w.FORM_CT}, body), case="T1")
    err = error_of(r)
    ok = r.status == 401 and err == "invalid_client" and r.headers.get("www-authenticate", "").startswith("WPT")
    return ok, [f"status={r.status} want=401 error={err} want_error=invalid_client"], [
        {"case": "T1", "service": "tts-a", "status": r.status, "decision": "reject", "reason": err}]


def run_t2() -> tuple[bool, list[str], list[dict]]:
    """TTS-B request that carries a valid Txn-Token but no WIT proof: a Txn-Token does not authenticate a workload
    (s13.12), it can only be a subject_token."""
    tok = w.issue_txn_token(
        TTS_B_KEY, kid="tts_b-1", iss="http://rich.ietf127.example:5061", aud="rich.ietf127.example",
        txn=str(uuid.uuid4()), sub="user:alice", scope="files:read files:list", req_wl=COORDINATOR_ID,
        tctx={"file": "Q3.pdf"})
    form = w.txn_token_request(audience="rich.ietf127.example", scope="files:read", subject_token=tok,
                               subject_token_type=w.TT_TXN)
    r = safe_send(w.Req("POST", TTS_B_URL, {"Content-Type": w.FORM_CT, "Txn-Token": tok}, form), case="T2")
    err = error_of(r)
    ok = r.status == 401 and err == "invalid_client" and r.headers.get("www-authenticate", "").startswith("WPT")
    return ok, [f"status={r.status} want=401 error={err} want_error=invalid_client"], [
        {"case": "T2", "service": "tts-b", "status": r.status, "decision": "reject", "reason": err}]


def run_t3() -> tuple[bool, list[str], list[dict]]:
    """Research's WIT presented with the Coordinator's key: the proof must come from the key the WIT names."""
    wit = rich_wit(RESEARCH_KEY, RESEARCH_ID)
    tok = w.issue_txn_token(
        TTS_B_KEY, kid="tts_b-1", iss="http://rich.ietf127.example:5061", aud="rich.ietf127.example",
        txn=str(uuid.uuid4()), sub="user:alice", scope="files:read", req_wl=RESEARCH_ID, tctx={"file": "Q3.pdf"})
    req = w.http_sig(
        "POST", "http://127.0.0.1:5063/files/read", json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit, COORD_KEY, aud=FILE_AUD, headers={"Txn-Token": tok})
    r = safe_send(req, case="T3")
    reason = error_of(r)
    ok = r.status == 400 and reason == "wimse-signature-invalid"
    return ok, [f"status={r.status} want=400 body={reason} want_body=wimse-signature-invalid"], [
        {"case": "T3", "service": "file-tool", "status": r.status, "decision": "reject", "reason": reason}]


def run_t4() -> tuple[bool, list[str], list[dict]]:
    """/admin/revoke needs an operator: no proof -> 401, a workload that is not an operator -> 403; and the
    attempt changed nothing (Research can still read)."""
    body = json.dumps({"workload": RESEARCH_ID}).encode("utf-8")
    r1 = safe_send(w.Req("POST", "http://127.0.0.1:5063/admin/revoke", {"Content-Type": "application/json"}, body), case="T4")
    reason1 = error_of(r1)
    r2 = safe_send(w.http_sig(
        "POST", "http://127.0.0.1:5063/admin/revoke", body, rich_wit(RESEARCH_KEY, RESEARCH_ID), RESEARCH_KEY,
        aud=FILE_AUD), case="T4")
    reason2 = reason_of(r2)
    tok = w.issue_txn_token(
        TTS_B_KEY, kid="tts_b-1", iss="http://rich.ietf127.example:5061", aud="rich.ietf127.example",
        txn=str(uuid.uuid4()), sub="user:alice", scope="files:read", req_wl=RESEARCH_ID, tctx={"file": "Q3.pdf"})
    r3 = safe_send(w.http_sig(
        "POST", "http://127.0.0.1:5063/files/read", json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        rich_wit(RESEARCH_KEY, RESEARCH_ID), RESEARCH_KEY, aud=FILE_AUD, headers={"Txn-Token": tok}), case="T4")
    ok = r1.status == 401 and reason1 is None and r2.status == 403 and reason2 == "not-authorized" and r3.status == 200
    notes = [f"unauthenticated={r1.status} {reason1} non_operator={r2.status} {reason2} read_after={r3.status}"]
    journal = [
        {"case": "T4", "step": 1, "service": "file-tool", "status": r1.status, "decision": "reject", "reason": reason1},
        {"case": "T4", "step": 2, "service": "file-tool", "status": r2.status, "decision": "reject", "reason": reason2},
        {"case": "T4", "step": 3, "service": "file-tool", "status": r3.status, "decision": "accept"},
    ]
    return ok, notes, journal


def run_t5() -> tuple[bool, list[str], list[dict]]:
    """A requester named in the request body is ignored: req_wl is the verified WIT subject."""
    wkey = w.new_workload_key("ES256")
    form = new_txn_form("files:read") + b"&" + w.form_encode({"req_wl": OPERATOR_ID})
    r = safe_send(signed_form(TTS_A_URL, form, peer_wit(wkey), wkey, TTS_A_PROOF_AUD), case="T5")
    req_wl = None
    if r.status == 200:
        req_wl = claims_of(json.loads(r.body.decode())["access_token"]).get("req_wl")
    ok = r.status == 200 and req_wl == CLIENT_ID
    return ok, [f"status={r.status} req_wl={req_wl} want={CLIENT_ID}"], [
        {"case": "T5", "service": "tts-a", "status": r.status, "decision": "accept"}]


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


RUNNERS = {
    "B_CHAIN": lambda with_m: run_b_chain(with_m),
    "C5": lambda with_m: run_c5(),
    "C6": lambda with_m: run_c6(),
    "C7": lambda with_m: run_c7(),
    "C8": lambda with_m: run_c8(),
    "C9": lambda with_m: run_c9(),
    "C9b": lambda with_m: run_c9b(),
    "C10": lambda with_m: run_c10(),
    "D1": lambda with_m: run_d1(),
    "D2": lambda with_m: run_d2(with_m),
    "D3_exp": lambda with_m: run_d3_exp(),
    "D3_sig": lambda with_m: run_d3_sig(),
    "D3_typ": lambda with_m: run_d3_typ(),
    "D3_reqwl": lambda with_m: run_d3_reqwl(),
    "D3_dup": lambda with_m: run_d3_dup(),
    "D4": lambda with_m: run_d4(),
    "D5": lambda with_m: run_d5(),
    "D6": lambda with_m: run_d6(),
    "D7": lambda with_m: run_d7(),
    "T1": lambda with_m: run_t1(),
    "T2": lambda with_m: run_t2(),
    "T3": lambda with_m: run_t3(),
    "T4": lambda with_m: run_t4(),
    "T5": lambda with_m: run_t5(),
}


def with_journal_check(cid, fn):
    """Run a case, then compare the causes the peers journaled with chain_cases.json "journal".

    Response bodies of refused authentications are the same whatever failed (http-signature-08 s3.6), so the precise
    reason is read from the peers' decision journal, like peers/driver.py reads Maurice's.
    """
    def run(with_m):
        offset = peer_journal.size()
        ok, notes, entries = fn(with_m)
        want = CASES.get(cid, {}).get("journal")
        if want is not None:
            got = [f"{e['service']} {e['reason']}" for e in peer_journal.read_since(offset)
                   if e.get("case") == cid and e.get("decision") == "reject"]
            if got != want:
                ok = False
                notes = notes + [f"peer journal {got} differs from chain_cases.json journal {want} ({peer_journal.path()})"]
            else:
                notes = notes + [f"journal={got}"]
        return ok, notes, entries
    return run


RUNNERS = {cid: with_journal_check(cid, fn) for cid, fn in RUNNERS.items()}


def main():
    parser = argparse.ArgumentParser(description="Multi-Agent Chain & Attack Driver")
    parser.add_argument("--cases", default="all", help="Comma-separated case IDs or 'all'")
    parser.add_argument("--journal-out", type=pathlib.Path, help="Optional JSONL output path for journal records")
    parser.add_argument("--with-maurice", action="store_true", help="Include live Maurice on 127.0.0.1:5050")
    parser.add_argument("--no-maurice", action="store_true",
                        help="Never contact :5050, even if something listens there (skips hop 2 and the Maurice half of D2)")
    parser.add_argument("--with-p1-p8", action="store_true", help="Include P1-P8 executor on 127.0.0.1:5064")
    args = parser.parse_args()

    with_maurice = (args.with_maurice or is_port_open(5050)) and not args.no_maurice
    with_p1_p8 = args.with_p1_p8 or is_port_open(5064)

    if args.cases == "all":
        case_ids = list(RUNNERS.keys())
    else:
        case_ids = [c.strip() for c in args.cases.split(",") if c.strip()]

    # If P1-P8 executor requested or open on 5064, execute it first
    if with_p1_p8:
        try:
            import p2_p7_p8_executor

            p_res = p2_p7_p8_executor.run_all_cases("http://127.0.0.1:5064")
            print(f"P2/P7/P8 executor: ran {len(p_res)} cases successfully.", flush=True)
            for r in p_res:
                JOURNAL_RECORDS.append({
                    "case": f"{r['scenario']}_{r['case']}",
                    "status": r["status"],
                    "decision": r.get("response", {}).get("decision"),
                    "reason": r.get("response", {}).get("reason"),
                    "service": "p2_p7_p8_executor",
                })
        except Exception as exc:
            print(f"Warning: p2_p7_p8_executor error: {exc}", flush=True)

    failed = []
    for cid in case_ids:
        runner = RUNNERS.get(cid)
        if not runner:
            print(f"CASE {cid} [UNKNOWN] FAIL :: Unknown case ID", flush=True)
            failed.append(cid)
            continue

        c_meta = CASES.get(cid, {})
        ref = c_meta.get("ref", "-")
        title = c_meta.get("title", "")

        try:
            ok, notes, j_entries = runner(with_maurice)
            JOURNAL_RECORDS.extend(j_entries)
        except Exception as exc:
            ok = False
            notes = [f"exception {type(exc).__name__}: {exc}"]

        status_str = "PASS" if ok else "FAIL"
        print(f"CASE {cid} [{ref}] {status_str} :: {title} :: " + "; ".join(notes), flush=True)
        if not ok:
            failed.append(cid)

    if args.journal_out:
        args.journal_out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.journal_out, "w", encoding="utf-8") as f:
            for rec in JOURNAL_RECORDS:
                f.write(json.dumps(rec) + "\n")

    print(f"SUMMARY total={len(case_ids)} failed={len(failed)} {failed}", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
