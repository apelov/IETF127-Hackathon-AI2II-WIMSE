# WP04 — Multi-Agent Chain & Attack Driver (`chain_cases.json` + `peers/chain_driver.py`)

Tier: mini-code
Inputs: workpackages/README.md, workpackages/WP02-domain-a-services.md, workpackages/WP03-domain-b-services.md, peers/driver.py

Create `chain_cases.json` and `peers/chain_driver.py` to execute and verify the complete multi-agent scenario: Normal Path (`B_CHAIN`) and all 14 negative/attack cases (`C5`, `C6`, `C7`, `C8`, `C9`, `C9b`, `C10`, `D1`, `D2`, `D3_exp`, `D3_sig`, `D3_typ`, `D3_reqwl`, `D3_dup`, `D4`, `D5`, `D6`, `D7`).

## Why

The user's scenario requires proving both the **Normal Path** (user request enters Domain A $\rightarrow$ `Txn-Token` issued $\rightarrow$ bound to hop proof through Maurice and Domain A $\rightarrow$ cross-domain identity chaining `Txn-Token` $\rightarrow$ JWT grant $\rightarrow$ access token where `Txn-Token` never leaves Domain A $\rightarrow$ Domain B `TTS-B` + `RICH` + `File Tool` $\rightarrow$ unified `txn` ID across all hop logs) and all **Negative / Attack Cases** (`C5–C10`, `D1–D7`).

Depends on: WP02, WP03.

## Deliverables

1. Create `chain_cases.json` defining the 19 cases and their expected wire/journal outcomes:
   - `B_CHAIN`: End-to-end 3-Agent cross-domain + intra-domain call chain (`TTS-A :5051` $\rightarrow$ `Agent 1: Maurice :5050` $\rightarrow$ `AS-A :5051` $\rightarrow$ `AS-B :5061` $\rightarrow$ `Agent 2: RICH Coordinator :5060` $\rightarrow$ `TTS-B :5061` [initial `Txn-Token`, `files:read files:list`] $\rightarrow$ `Agent 3: RICH Research Sub-Agent :5062` $\rightarrow$ `TTS-B :5061` [narrowed replacement `Txn-Token`, `files:read`] $\rightarrow$ `File Tool :5063`). Expects status `200` on every hop, identical `txn` ID across all Domain A & Domain B journal entries, and `"$4.2M"` summary returned.
   - `C5`: Txn-Token swapped after signing HTTP-Sig (`File Tool` & `Maurice` reject `400`, `reason="proof-invalid"`).
   - `C6`: Foreign Txn-Token (`aud="maurice.ietf127.example"` presented to Domain B `File Tool` $\rightarrow$ `403`, `reason="txn-token-invalid"`).
   - `C7`: Prompt injection data (`Q3.pdf` tells agent to read `salaries.xlsx` $\rightarrow$ `File Tool` rejects `salaries.xlsx` read with `403`, `reason="not-authorized"` while `Q3.pdf` succeeds).
   - `C8`: Prompt injection secrets (`Q3.pdf` asks agent to dump credentials $\rightarrow$ `caller_context` contains zero raw JWT strings `"eyJ"`, status `200`, `leaked_credentials=False`).
   - `C9`: Autonomous call (no `Txn-Token`) on delegated-only route `/files/read` (`delegation: required` $\rightarrow$ `403`, `reason="not-authorized"`).
   - `C9b`: Delegated call (with valid `Txn-Token`) on autonomous-only route `/files/index` (`delegation: forbidden` $\rightarrow$ `403`, `reason="not-authorized"`).
   - `C10`: Mid-transaction agent revocation (Step 1: `200 accept`; revoke workload via `/admin/revoke`; Step 2: `403 revoked`; clear revocation).
   - `D1`: `Txn-Token` header present on HTTP-Sig request but omitted from `@signature-params` covered components ($\rightarrow$ `400`, `reason="proof-invalid"`).
   - `D2`: `Txn-Token` header present on WPT request with wrong `tth` claim (tested against both `Maurice :5050` and `File Tool :5063` $\rightarrow$ `401`, `WWW-Authenticate: WPT`, `reason="proof-invalid"`).
   - `D3_exp`: Expired `Txn-Token` ($\rightarrow$ `403`, `reason="txn-token-invalid"`).
   - `D3_sig`: `Txn-Token` signed with wrong key `rogue.pem` ($\rightarrow$ `403`, `reason="txn-token-invalid"`).
   - `D3_typ`: `Txn-Token` with wrong `typ="jwt"` ($\rightarrow$ `403`, `reason="txn-token-invalid"`).
   - `D3_reqwl`: `Txn-Token` missing `req_wl` claim ($\rightarrow$ `403`, `reason="txn-token-invalid"`).
   - `D3_dup`: Request carrying two `Txn-Token` headers via `extra_headers` ($\rightarrow$ `403`, `reason="txn-token-invalid"`).
   - `D4`: `Txn-Token` with `scope="profile:view"` not matching grant `scopes_any=["files:read"]` ($\rightarrow$ `403`, `reason="not-authorized"`).
   - `D5`: Outbound guard (`wimse_fetch` cross-domain check) blocks sending a Domain A `Txn-Token` directly to Domain B (`reason="txn-cross-domain"`, zero packets sent to Domain B).
   - `D6`: Scope narrowing at `TTS-A` (`"files:read files:list"` $\rightarrow$ `"files:read"` accepted; `test_mode="widen_scope"` and `test_mode="change_txn"` rejected by `validate_narrowed_replacement` before sending).
   - `D7`: `AS-A` returns a JWT grant whose `aud` is not `AS-B` (`test_mode="wrong_aud"` $\rightarrow$ `AS-B` rejects `403`, `reason="grant-invalid"`).
2. Create `peers/chain_driver.py` with CLI flags `--cases <all|id1,id2>`, `--journal-out <path>`, and `--with-maurice` (when `--with-maurice` is passed or port 5050 is listening, `B_CHAIN` and `D2` also execute against live Maurice on `:5050`; standalone unit test mode can run against Domain A + Domain B in-process). Exits `0` only if all requested cases pass.

## Owns (touch only these)

- `chain_cases.json` — expected outcomes for the 19 chain/attack cases.
- `peers/chain_driver.py` — driver executing the 19 cases and writing the unified decision journal.

Do **not** modify any other files.

## Constraints / invariants

- Every HTTP request sent during a case MUST include `X-Test-Case: <case_id>`.
- In `B_CHAIN`, verify that all hops (`Agent 1`, `Agent 2`, `Agent 3`, `File Tool`, and the token services) log the exact same `txn` UUID and that no raw `txntoken+jwt` from Domain A ever appears in any request to ports `5060`, `5061`, `5062`, or `5063`.
- Commit locally when `Verify:` passes; never push.

## Verification

Verify: .venv/bin/python -c 'import sys; sys.path.insert(0,"peers"); import domain_a, domain_b, subprocess; sa=domain_a.start_in_thread(); sb=domain_b.start_all_in_threads(); rc=subprocess.call([".venv/bin/python","peers/chain_driver.py","--journal-out","/tmp/chain-j.jsonl"]); domain_b.shutdown_all(sb); sa.shutdown(); assert rc==0'
