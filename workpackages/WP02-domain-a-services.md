# WP02 — Trust Domain A Services (TTS-A and AS-A)

Tier: mini-code
Inputs: workpackages/README.md, workpackages/WP01-txn-and-chaining-primitives.md, peers/wimse.py

Create `peers/domain_a.py` implementing Trust Domain A's Transaction Token Service (`TTS-A`) and OAuth Authorization Server (`AS-A`) on `127.0.0.1:5051` for the multi-agent chain and negative tests.

## Why

In Phase B (`B1–B4`) and Phase C2 (`D-6`, `D-7`), Trust Domain A (`maurice.ietf127.example`) needs:
1. **TTS-A (`POST /tts/token`)** to issue an initial `txntoken+jwt` for user Alice (`sub="user:alice"`, `scope="files:read"`, `tctx={"file": "Q3.pdf"}`), to support scope narrowing on hop 2 (`D-6`), and to simulate a misbehaving TTS that returns a widened scope or mutated `txn` ID (`D-6` negative).
2. **AS-A (`POST /oauth/token`)** to perform RFC 8693 Token Exchange for Identity Chaining (`draft-ietf-oauth-identity-chaining-17`): consuming a valid Domain A `Txn-Token` (`aud="maurice.ietf127.example"`) and issuing a cross-domain JWT assertion grant (`typ="jwt-chg+jwt"`, `aud="http://rich.ietf127.example:5061/oauth/token"`) so the Domain A `Txn-Token` never leaves Domain A.

Depends on: WP01.

## Deliverables

1. Create `peers/domain_a.py` providing a `ThreadingHTTPServer` on `127.0.0.1:5051` (plus a `start_in_thread()` helper for in-process testing and a `__main__` entrypoint for standalone execution) with two JSON endpoints and an append-only decision journal writer:
   - **`POST /tts/token`**:
     - Request JSON: `{"sub": "user:alice", "scope": "files:read", "tctx": {"file": "Q3.pdf"}, "req_wl": "wimse://peer.ietf127.example/client", "txn": optional_existing_txn, "parent_txn_token": optional_token_for_narrowing, "test_mode": optional_str}`.
     - If `parent_txn_token` is provided: verifies it with `tts_a.jwks.json` (`expected_aud="maurice.ietf127.example"`), preserves its `txn` and `sub`, and checks that every requested scope token in `scope.split()` was present in the parent's `scope.split()` (unless `test_mode == "widen_scope"` or `test_mode == "change_txn"`, which intentionally return a widened scope `"files:read files:write"` or a new `txn` so the caller's outbound TXO-4/TXO-5 check in `D-6` can catch and reject the bad replacement).
     - Logs a journal entry `{"service": "tts-a", "direction": "issue", "txn": txn_id, "sub": sub, "scope": scope, "req_wl": req_wl, "decision": "accept", "status": 200}`.
     - Returns `200` with `{"txn_token": token, "txn": txn_id}`.
   - **`POST /oauth/token`**:
     - Request JSON: `{"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": "<txn_token>", "subject_token_type": "urn:ietf:params:oauth:token-type:txn_token", "audience": "http://rich.ietf127.example:5061/oauth/token", "scope": "files:read", "test_mode": optional_str}`.
     - Authenticates the caller via `w.verify_wimse_proof(..., expected_aud="http://maurice.ietf127.example:5051")` (requires a valid Domain A / peer WIT + HTTP-Sig or WPT). If proof fails, logs `decision="reject"` and returns the status (`400`/`401`).
     - Verifies `subject_token` using `tts_a.jwks.json` with `expected_typ="txntoken+jwt"` and `expected_aud="maurice.ietf127.example"`. If invalid, logs `{"service": "as-a", "decision": "reject", "reason": "txn-token-invalid", "status": 403}` and returns `403`.
     - Checks requested `scope` is a subset of `subject_token`'s `scope`.
     - Issues a cross-domain JWT assertion grant using `as_a.pem` (`kid="as_a-1"`, `iss="http://maurice.ietf127.example:5051"`, `aud=req["audience"]` or `"http://wrong.example/oauth/token"` when `test_mode == "wrong_aud"` for `D-7`, preserving `txn`, `sub`, `scope`, `tctx`).
     - Logs `{"service": "as-a", "direction": "exchange", "txn": claims["txn"], "sub": claims["sub"], "scope": scope, "decision": "accept", "status": 200}` and returns `200` with `{"assertion": grant_jwt, "txn": claims["txn"]}`.
   - **`validate_narrowed_replacement(original_txn_token: str, replacement_txn_token: str, tts_a_jwks: dict) -> tuple[bool, str]`**:
     - Client-side helper for `D-6` (TXO-4, TXO-5): verifies `replacement_txn_token`, checks `rep["txn"] == orig["txn"]` (else `(False, "txn-mutated")`), and checks `set(rep["scope"].split()) <= set(orig["scope"].split())` (else `(False, "scope-widened")`).

## Owns (touch only these)

- `peers/domain_a.py` — Domain A TTS-A, AS-A, and client narrowing check.

Do **not** modify any other files.

## Constraints / invariants

- Bind only to `127.0.0.1:5051` with `allow_reuse_address = True`.
- Forward any incoming `X-Test-Case` header in logs and allow `X-Test-Case` on all requests so `tshark` capture checkers can map traffic by case ID.
- Commit locally when `Verify:` passes; never push.

## Verification

Verify: .venv/bin/python -c 'import sys, urllib.request, json; sys.path.insert(0,"peers"); import domain_a, wimse as w; srv=domain_a.start_in_thread(); req=urllib.request.Request("http://127.0.0.1:5051/tts/token", data=json.dumps({"sub":"user:alice","scope":"files:read","tctx":{"file":"Q3.pdf"},"req_wl":"wimse://peer.ietf127.example/client"}).encode(), headers={"Content-Type":"application/json"}); r=json.loads(urllib.request.urlopen(req).read()); assert "txn_token" in r and r["txn"]; srv.shutdown()'
