# WP01 — Txn-Token, Identity-Chaining, and Verification Primitives

Tier: mini-code
Inputs: peers/wimse.py, setup/gen_keys.py

Extend `peers/wimse.py` and `setup/gen_keys.py` with JWS verification, `txntoken+jwt` issuance, cross-domain identity-chaining token helpers, and inbound WIMSE proof verification so Domain A and Domain B services can be implemented without duplicating crypto code.

## Why

The existing `peers/wimse.py` only *issues* WITs, WPTs, and RFC 9421 HTTP signatures for the client driver. To run the two-domain agent chain (`B1–B8`) and attacks (`C5–C10`, `D1–D7`), the lightweight Domain A and Domain B peers need deterministic helpers to issue `txntoken+jwt` (draft-ietf-oauth-transaction-tokens-11), issue/verify cross-domain JWT grants (draft-ietf-oauth-identity-chaining-17), and verify inbound `WIT + HTTP-Sig` and `WIT + WPT` proofs (including `txn-token` and `tth` binding).

Depends on: none.

## Deliverables

1. In `setup/gen_keys.py`: extend the key generation loop from `("peer", "rogue")` to `("peer", "rogue", "tts_a", "as_a", "as_b", "tts_b", "rich")` so all Domain A and Domain B test keys exist in `keys/<name>.pem` and `keys/<name>.jwks.json`.
2. In `peers/wimse.py`, keep all existing functions byte-compatible and add the following exact functions:
   - `parse_jwt(token: str) -> tuple[dict, dict, bytes, bytes]`: splits `h.c.s`, returns `(header_dict, claims_dict, signing_input_bytes, signature_bytes)` or raises `ValueError`.
   - `verify_raw_sig(pub_jwk: dict, data: bytes, sig: bytes) -> bool`: verifies ES256 (`r||s` 64 bytes) or Ed25519 raw signature against a JWK dict (`kty` `EC` or `OKP`); returns `True` or `False` (never raises on bad signature).
   - `verify_jwt(token: str, jwks: dict, *, expected_typ: str | None = None, expected_aud: str | None = None, now: int | None = None) -> dict`: verifies signature using matching `kid` (or single key in `jwks["keys"]`), checks `alg` (`ES256`, `EdDSA`, `Ed25519`, never `none`), checks `expected_typ` if given, checks `exp > now` and `iat <= now`, and checks `expected_aud` (matching string or list membership). Returns `claims` dict or raises `ValueError(reason)`.
   - `issue_txn_token(tts_key, *, kid: str, iss: str, aud: str, txn: str, sub: str, scope: str, req_wl: str, tctx: dict | None = None, ttl: int = 120, now: int | None = None, typ: str = "txntoken+jwt", drop: tuple = ()) -> str`: issues a Transaction Token JWT per TXN-11 §9 (`header = {"alg": "ES256", "kid": kid, "typ": typ}`, `claims = {"iss": iss, "aud": aud, "txn": txn, "sub": sub, "scope": scope, "req_wl": req_wl, "iat": now, "exp": now + ttl, "tctx": tctx or {}}`, dropping any key in `drop`).
   - `issue_chain_grant(as_a_key, *, kid: str, iss: str, aud: str, sub: str, scope: str, txn: str, tctx: dict | None = None, ttl: int = 60, now: int | None = None) -> str`: issues a cross-domain JWT assertion grant (`typ="jwt-chg+jwt"`) carrying `iss`, `aud`, `sub`, `scope`, `txn`, `tctx`, `iat`, `exp`, `jti`.
   - `issue_access_token(as_b_key, *, kid: str, iss: str, aud: str, sub: str, scope: str, txn: str, tctx: dict | None = None, ttl: int = 120, now: int | None = None) -> str`: issues an OAuth access token (`typ="at+jwt"`) for Domain B carrying `iss`, `aud`, `sub`, `scope`, `txn`, `tctx`, `iat`, `exp`, `jti`.
   - `verify_wimse_proof(method: str, path_and_query: str, headers: dict[str, str], body: bytes, trust_jwks: dict[str, dict], *, expected_aud: str, seen_nonces: set[str] | None = None, now: int | None = None) -> tuple[bool, int, str, dict | None]`:
     - Takes lowercase-keyed `headers`.
     - Verifies `workload-identity-token` via `trust_jwks[trust_domain]` and checks `sub` identifier rules.
     - If `signature-input` and `signature` are present: verifies RFC 9421 signature with `cnf.jwk`, checks `wimse-aud == expected_aud`, checks `content-digest` if `body` non-empty, checks `seen_nonces` for replay (`"replay"`), and **if `txn-token` is in `headers`, requires `"txn-token"` to be in the covered components** (else returns `(False, 400, "proof-invalid", None)`).
     - If `authorization` starts with `"WPT "`: verifies WPT with `cnf.jwk`, checks `aud == expected_aud`, checks `wth == b64u(sha256(wit))`, and **if `txn-token` is in `headers`, requires `tth == b64u(sha256(txn_token))`** (else returns `(False, 401, "proof-invalid", None)`).
     - Returns `(True, 200, "accept", {"peer_id": sub, "wit_claims": wit_claims, "mechanism": mech})` on success.

## Owns (touch only these)

- `setup/gen_keys.py` — add `"tts_a"`, `"as_a"`, `"as_b"`, `"tts_b"`, `"rich"` to the key generation tuple.
- `peers/wimse.py` — add the verification and token issuance functions listed in Deliverable 2.

Do **not** modify any other files.

## Constraints / invariants

- All existing 34 cases in `peers/driver.py` must continue to work without any change to `peers/driver.py`.
- Use only Python stdlib + `cryptography` (already in `.venv`).
- Commit locally when `Verify:` passes; never push.

## Verification

Verify: .venv/bin/python setup/gen_keys.py && .venv/bin/python -c 'import sys; sys.path.insert(0,"peers"); import wimse as w, json, pathlib; k=pathlib.Path("keys"); assert (k/"tts_a.pem").exists() and (k/"rich.jwks.json").exists(); from cryptography.hazmat.primitives import serialization; pk=serialization.load_pem_private_key((k/"tts_a.pem").read_bytes(),None); jwks=json.loads((k/"tts_a.jwks.json").read_text()); tok=w.issue_txn_token(pk,kid="tts_a-1",iss="http://a",aud="dom.a",txn="tx1",sub="user:alice",scope="files:read",req_wl="wimse://dom.a/edge",tctx={"file":"Q3.pdf"}); c=w.verify_jwt(tok,jwks,expected_typ="txntoken+jwt",expected_aud="dom.a"); assert c["txn"]=="tx1" and c["tctx"]["file"]=="Q3.pdf"'
