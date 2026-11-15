#!/usr/bin/env python3
"""Multi-Agent Chain & Attack Driver for WIMSE interoperability testing.

Executes and verifies:
- Normal Path (B_CHAIN): 3-agent 2-domain call chain with unified txn correlation
- Negative / Attack Cases (C5, C6, C7, C8, C9, C9b, C10, D1, D2, D3_exp, D3_sig,
  D3_typ, D3_reqwl, D3_dup, D4, D5, D6, D7)
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

import wimse as w
from domain_a import validate_narrowed_replacement

KEYS_DIR = ROOT / "keys"


def _load_private_key(name: str):
    p = KEYS_DIR / f"{name}.pem"
    return serialization.load_pem_private_key(p.read_bytes(), None)


def _load_jwks(name: str) -> dict:
    p = KEYS_DIR / f"{name}.jwks.json"
    return json.loads(p.read_text(encoding="utf-8"))


PEER_KEY = _load_private_key("peer")
ROGUE_KEY = _load_private_key("rogue")
RICH_KEY = _load_private_key("rich")
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


# ---------------------------------------------------------------------------
# Case Implementations
# ---------------------------------------------------------------------------


def run_b_chain(with_maurice: bool) -> tuple[bool, list[str], list[dict]]:
    notes = []
    journal = []

    # 1. POST http://127.0.0.1:5051/tts/token
    tts_payload = {
        "sub": "user:alice",
        "scope": "files:read files:list",
        "tctx": {"file": "Q3.pdf"},
        "req_wl": "wimse://peer.ietf127.example/client",
    }
    r1 = safe_send(
        w.Req(
            "POST",
            "http://127.0.0.1:5051/tts/token",
            {"Content-Type": "application/json"},
            json.dumps(tts_payload).encode("utf-8"),
        ),
        case="B_CHAIN",
    )
    if r1.status != 200:
        return False, [f"Step 1 TTS-A failed ({r1.status}): {r1.body.decode()}"], journal
    d1 = json.loads(r1.body.decode("utf-8"))
    txn_token_a = d1["txn_token"]
    txn_a = d1["txn"]
    notes.append(f"step1=tts-a status={r1.status} txn={txn_a}")
    journal.append({
        "case": "B_CHAIN",
        "step": 1,
        "service": "tts-a",
        "status": r1.status,
        "txn": txn_a,
        "decision": "accept",
    })

    # 2. If with_maurice or port 5050 is open:
    if with_maurice:
        wkey_m = w.new_workload_key("ES256")
        wit_m = w.issue_wit(
            PEER_KEY,
            kid="peer-1",
            iss="http://peer.ietf127.example",
            sub="wimse://peer.ietf127.example/client",
            workload_pub_jwk=w.jwk_from_public(wkey_m.public_key()),
        )
        req_m = w.http_sig(
            "POST",
            "http://127.0.0.1:5050/api/v2/agents/dbsccjan18nkaiapu9v0/workflows/text-stats/executions",
            b'{"inputs": {"text": "hello wimse"}}',
            wit_m,
            wkey_m,
            aud="http://maurice.ietf127.example:5050",
            headers={"Txn-Token": txn_token_a},
        )
        r_m = safe_send(req_m, case="B_CHAIN")
        if r_m.status != 200:
            return False, notes + [f"Step 2 Maurice failed ({r_m.status}): {r_m.body.decode()}"], journal
        notes.append(f"step2=maurice status={r_m.status}")
        journal.append({
            "case": "B_CHAIN",
            "step": 2,
            "service": "maurice",
            "status": r_m.status,
            "txn": txn_a,
            "decision": "accept",
        })

    # 3. POST http://127.0.0.1:5051/oauth/token
    wkey_as_a = w.new_workload_key("ES256")
    wit_as_a = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey_as_a.public_key()),
    )
    req_as_a = w.http_sig(
        "POST",
        "http://127.0.0.1:5051/oauth/token",
        json.dumps({"subject_token": txn_token_a}).encode("utf-8"),
        wit_as_a,
        wkey_as_a,
        aud="http://maurice.ietf127.example:5051",
    )
    r3 = safe_send(req_as_a, case="B_CHAIN")
    if r3.status != 200:
        return False, notes + [f"Step 3 AS-A failed ({r3.status}): {r3.body.decode()}"], journal
    d3 = json.loads(r3.body.decode("utf-8"))
    assertion = d3["assertion"]
    if d3["txn"] != txn_a:
        return False, notes + [f"Step 3 AS-A txn mismatch: {d3['txn']} != {txn_a}"], journal
    notes.append(f"step3=as-a status={r3.status} txn={d3['txn']}")
    journal.append({
        "case": "B_CHAIN",
        "step": 3,
        "service": "as-a",
        "status": r3.status,
        "txn": txn_a,
        "decision": "accept",
    })

    # 4. POST http://127.0.0.1:5061/oauth/token
    req_as_b = w.Req(
        "POST",
        "http://127.0.0.1:5061/oauth/token",
        {"Content-Type": "application/json"},
        json.dumps({"assertion": assertion}).encode("utf-8"),
    )
    r4 = safe_send(req_as_b, case="B_CHAIN")
    if r4.status != 200:
        return False, notes + [f"Step 4 AS-B failed ({r4.status}): {r4.body.decode()}"], journal
    d4 = json.loads(r4.body.decode("utf-8"))
    access_token = d4["access_token"]
    if d4["txn"] != txn_a:
        return False, notes + [f"Step 4 AS-B txn mismatch: {d4['txn']} != {txn_a}"], journal
    notes.append(f"step4=as-b status={r4.status} txn={d4['txn']}")
    journal.append({
        "case": "B_CHAIN",
        "step": 4,
        "service": "as-b",
        "status": r4.status,
        "txn": txn_a,
        "decision": "accept",
    })

    # 5. POST http://127.0.0.1:5060/coordinate
    wkey_coord = w.new_workload_key("ES256")
    wit_coord = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey_coord.public_key()),
    )
    req_coord = w.http_sig(
        "POST",
        "http://127.0.0.1:5060/coordinate",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit_coord,
        wkey_coord,
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
    journal.append({
        "case": "B_CHAIN",
        "step": 5,
        "service": "agent2-coordinator",
        "status": r5.status,
        "txn": txn_a,
        "decision": "accept",
    })
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
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 400 and reason == "proof-invalid")
    notes = [f"status={r.status} want=400 reason={reason} want_reason=proof-invalid"]
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
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        RICH_KEY,
        kid="rich-1",
        iss="http://rich.ietf127.example",
        sub="wimse://rich.ietf127.example/agent/coordinator",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
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
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        RICH_KEY,
        kid="rich-1",
        iss="http://rich.ietf127.example",
        sub="wimse://rich.ietf127.example/agent/coordinator",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
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


def run_c10() -> tuple[bool, list[str], list[dict]]:
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        RICH_KEY,
        kid="rich-1",
        iss="http://rich.ietf127.example",
        sub="wimse://rich.ietf127.example/agent/research",
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
        req_wl="wimse://rich.ietf127.example/agent/research",
        tctx={"file": "Q3.pdf"},
    )
    # Step 1: Valid call -> 200
    req1 = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok},
    )
    r1 = safe_send(req1, case="C10")

    # Step 2: Revoke workload
    req_rev = w.Req(
        "POST",
        "http://127.0.0.1:5063/admin/revoke",
        {"Content-Type": "application/json"},
        json.dumps({"workload": "wimse://rich.ietf127.example/agent/research"}).encode("utf-8"),
    )
    r_rev = safe_send(req_rev, case="C10")

    # Step 3: Call /files/read again -> 403 revoked
    req3 = w.http_sig(
        "POST",
        "http://127.0.0.1:5063/files/read",
        json.dumps({"file": "Q3.pdf"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://rich.ietf127.example:5063",
        headers={"Txn-Token": tok},
    )
    r3 = safe_send(req3, case="C10")
    reason3 = None
    try:
        reason3 = json.loads(r3.body.decode()).get("reason")
    except Exception:
        pass

    # Step 4: Clear revocation
    req_clr = w.Req(
        "POST",
        "http://127.0.0.1:5063/admin/revoke",
        {"Content-Type": "application/json"},
        json.dumps({"clear": True}).encode("utf-8"),
    )
    r_clr = safe_send(req_clr, case="C10")

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
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 400 and reason == "proof-invalid")
    notes = [f"status={r.status} want=400 reason={reason} want_reason=proof-invalid"]
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
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r.status == 401 and auth_hdr.startswith("WPT") and reason == "proof-invalid")
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
        reason_m = None
        try:
            reason_m = json.loads(rm.body.decode()).get("reason") or json.loads(rm.body.decode()).get("error")
        except Exception:
            pass
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
    req = w.Req(
        "POST",
        "http://127.0.0.1:5061/oauth/token",
        {"Content-Type": "application/json"},
        json.dumps({"assertion": non_grant}).encode("utf-8"),
    )
    r = safe_send(req, case="D5")
    reason = None
    try:
        reason = json.loads(r.body.decode()).get("reason")
    except Exception:
        pass
    ok = guard_blocked and (r.status == 403 and reason == "grant-invalid")
    notes.append(f"as-b status={r.status} want=403 reason={reason} want_reason=grant-invalid")
    journal.append({"case": "D5", "service": "as-b", "status": r.status, "decision": "reject", "reason": reason})
    return ok, notes, journal


def run_d6() -> tuple[bool, list[str], list[dict]]:
    notes = []
    journal = []

    # 1. Original token
    r1 = safe_send(
        w.Req(
            "POST",
            "http://127.0.0.1:5051/tts/token",
            {"Content-Type": "application/json"},
            json.dumps({
                "sub": "user:alice",
                "scope": "files:read files:list",
                "req_wl": "wimse://peer.ietf127.example/client",
            }).encode("utf-8"),
        ),
        case="D6",
    )
    if r1.status != 200:
        return False, [f"Orig token failed: {r1.status}"], journal
    orig_tok = json.loads(r1.body.decode())["txn_token"]

    # 2. Narrowed replacement
    r2 = safe_send(
        w.Req(
            "POST",
            "http://127.0.0.1:5051/tts/token",
            {"Content-Type": "application/json"},
            json.dumps({
                "parent_txn_token": orig_tok,
                "scope": "files:read",
            }).encode("utf-8"),
        ),
        case="D6",
    )
    if r2.status != 200:
        return False, [f"Narrowed token failed: {r2.status}"], journal
    nar_tok = json.loads(r2.body.decode())["txn_token"]
    ok_nar, msg_nar = validate_narrowed_replacement(orig_tok, nar_tok, TTS_A_JWKS)

    # 3. Widened replacement
    r3 = safe_send(
        w.Req(
            "POST",
            "http://127.0.0.1:5051/tts/token",
            {"Content-Type": "application/json"},
            json.dumps({
                "parent_txn_token": orig_tok,
                "scope": "files:read",
                "test_mode": "widen_scope",
            }).encode("utf-8"),
        ),
        case="D6",
    )
    if r3.status != 200:
        return False, [f"Widen token failed: {r3.status}"], journal
    widen_tok = json.loads(r3.body.decode())["txn_token"]
    ok_widen, msg_widen = validate_narrowed_replacement(orig_tok, widen_tok, TTS_A_JWKS)

    # 4. Mutated txn replacement
    r4 = safe_send(
        w.Req(
            "POST",
            "http://127.0.0.1:5051/tts/token",
            {"Content-Type": "application/json"},
            json.dumps({
                "parent_txn_token": orig_tok,
                "scope": "files:read",
                "test_mode": "change_txn",
            }).encode("utf-8"),
        ),
        case="D6",
    )
    if r4.status != 200:
        return False, [f"Change txn token failed: {r4.status}"], journal
    mut_tok = json.loads(r4.body.decode())["txn_token"]
    ok_mut, msg_mut = validate_narrowed_replacement(orig_tok, mut_tok, TTS_A_JWKS)

    ok = (
        ok_nar is True
        and msg_nar == "ok"
        and ok_widen is False
        and msg_widen == "scope-widened"
        and ok_mut is False
        and msg_mut == "txn-mutated"
    )
    notes = [f"nar=({ok_nar},{msg_nar}) widen=({ok_widen},{msg_widen}) mut=({ok_mut},{msg_mut})"]
    journal = [{"case": "D6", "service": "tts-a", "status": 200, "decision": "accept", "reason": "accept"}]
    return ok, notes, journal


def run_d7() -> tuple[bool, list[str], list[dict]]:
    notes = []
    journal = []

    # 1. Get Txn-Token from TTS-A
    r1 = safe_send(
        w.Req(
            "POST",
            "http://127.0.0.1:5051/tts/token",
            {"Content-Type": "application/json"},
            json.dumps({
                "sub": "user:alice",
                "scope": "files:read",
                "req_wl": "wimse://peer.ietf127.example/client",
            }).encode("utf-8"),
        ),
        case="D7",
    )
    if r1.status != 200:
        return False, [f"TTS-A failed: {r1.status}"], journal
    tok_a = json.loads(r1.body.decode())["txn_token"]

    # 2. Exchange at AS-A with test_mode="wrong_aud"
    wkey = w.new_workload_key("ES256")
    wit = w.issue_wit(
        PEER_KEY,
        kid="peer-1",
        iss="http://peer.ietf127.example",
        sub="wimse://peer.ietf127.example/client",
        workload_pub_jwk=w.jwk_from_public(wkey.public_key()),
    )
    req_as_a = w.http_sig(
        "POST",
        "http://127.0.0.1:5051/oauth/token",
        json.dumps({"subject_token": tok_a, "test_mode": "wrong_aud"}).encode("utf-8"),
        wit,
        wkey,
        aud="http://maurice.ietf127.example:5051",
    )
    r2 = safe_send(req_as_a, case="D7")
    if r2.status != 200:
        return False, [f"AS-A failed: {r2.status}"], journal
    wrong_grant = json.loads(r2.body.decode())["assertion"]

    # 3. Send wrong_grant to AS-B -> 403 grant-invalid
    req_as_b = w.Req(
        "POST",
        "http://127.0.0.1:5061/oauth/token",
        {"Content-Type": "application/json"},
        json.dumps({"assertion": wrong_grant}).encode("utf-8"),
    )
    r3 = safe_send(req_as_b, case="D7")
    reason = None
    try:
        reason = json.loads(r3.body.decode()).get("reason")
    except Exception:
        pass
    ok = (r3.status == 403 and reason == "grant-invalid")
    notes = [f"as_a_status={r2.status} as_b_status={r3.status} want=403 reason={reason} want_reason=grant-invalid"]
    journal = [
        {"case": "D7", "service": "as-a", "status": r2.status, "decision": "accept"},
        {"case": "D7", "service": "as-b", "status": r3.status, "decision": "reject", "reason": reason},
    ]
    return ok, notes, journal


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
}


def main():
    parser = argparse.ArgumentParser(description="Multi-Agent Chain & Attack Driver")
    parser.add_argument("--cases", default="all", help="Comma-separated case IDs or 'all'")
    parser.add_argument("--journal-out", type=pathlib.Path, help="Optional JSONL output path for journal records")
    parser.add_argument("--with-maurice", action="store_true", help="Include live Maurice on 127.0.0.1:5050")
    parser.add_argument("--with-p1-p8", action="store_true", help="Include P1-P8 executor on 127.0.0.1:5064")
    args = parser.parse_args()

    with_maurice = args.with_maurice or is_port_open(5050)
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
