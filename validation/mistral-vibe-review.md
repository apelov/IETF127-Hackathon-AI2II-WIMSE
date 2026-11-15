# Independent verification review — WIMSE checker suite (Mistral Vibe)

- **Reviewer:** Mistral Vibe (this session), acting as an independent verifier.
- **Date:** 2026-11-15 (UTC). **Repo commit:** `3d4fab4`, clean working tree at start and end of the run.
- **Environment:** macOS, tshark 4.6.9 (Wireshark.app), `.venv` Python 3.14.6, `PYTHONPATH=.` `PYTHONNOUSERSITE=1` as set by `reproduce.sh`.
- **Scope:** `checkers/observes_wimse.py`, `checkers/observes_chain.py`, `checkers/observes_p1_p8.py`, their negative-mutant generators (`make_negatives.py`, `make_chain_negatives.py`, `make_p1_p8_negatives.py`), and a full execution of `./reproduce.sh`.

## 1. Execution results

`./reproduce.sh` was executed in full and exited **0** with `=== ALL REPRODUCIBILITY CHECKS PASSED ===`. All six stages ran: venv prep, key generation, AI2II bundle verification (`wire verify-bundle` → `OK` for `bundle-inbound`, `bundle-chain`, `bundle-payment`; `wire summarize validation` → `PASS` x3), the four packet-checker suites with negative-mutant loops, the P1–P8 manifest/SHA-256 stage, and Anton's AEP offline verifier (`PASS`).

Each checker under review was then re-run **individually** (not just via the script), with exit codes captured:

| Checker | Capture | Exit | Result line |
|---|---|---:|---|
| `observes_wimse.py` | `validation/bundle-inbound/inbound/capture.pcap` (536 pkts) | 0 | `SUMMARY cases=34 errors=0` |
| `observes_chain.py` | `validation/bundle-chain/chain/capture.pcap` (824 pkts) | 0 | `SUMMARY cases=19 errors=0` |
| `observes_p1_p8.py` | `validation/bundle-chain/chain/capture.pcap` | 0 | `SUMMARY cases=10 errors=0` |
| `observes_p1_p8.py --verify-manifests scenarios/p1_p8` | — | 0 | 22/22 Redthread, MintID + sandbox controls verified |

**Positive-case tally covered by the three checkers under review: 34 + 19 + 10 + 22 = 85 test cases, all passing, 0 errors.** (The repo-wide total is 87: `reproduce.sh` additionally runs `observes_payment.py`, 2 scenarios, outside the requested review scope.)

**Negative mutants: all 9 rejected with exit 1**, each on its intended code path (verbatim first failure captured during individual re-runs):

| Mutant | Checker | Exit | Rejection reason observed |
|---|---|---:|---|
| `negatives/unrelated.pcap` (3 pkts) | wimse | 1 | `FAIL: empty capture` + `FAIL <case>: expected 1 step(s), got 0` |
| `negatives/request_only.pcap` | wimse | 1 | `FAIL stream N: unpaired request for case 'A2' (no response)` |
| `negatives/forbidden_fetch.pcap` | wimse | 1 | `FAIL: capture contains TCP traffic to forbidden port 47999` |
| `negatives/chain_unrelated.pcap` (3 pkts) | chain | 1 | `FAIL B_CHAIN: missing from capture` (all 19) |
| `negatives/chain_request_only.pcap` | chain | 1 | `FAIL B_CHAIN: request on stream 1 ... has no response` |
| `negatives/chain_leaked_txn.pcap` | chain | 1 | `FAIL: Domain A Txn-Token leaked to Domain B port 5062 on stream 41` |
| `negatives/p1_p8_unrelated.pcap` (3 pkts) | p1_p8 | 1 | `FAIL P2_revoke-upstream: missing from capture` (all 10) |
| `negatives/p1_p8_request_only.pcap` | p1_p8 | 1 | `FAIL P2_revoke-upstream: request on stream 0 has no response` |
| `negatives/p1_p8_missing_before_effect.pcap` (20 pkts) | p1_p8 | 1 | `FAIL P2_before-effect: ... missing from capture` |

(The 3 payment mutants — `payment_unrelated`, `payment_request_only`, `payment_tampered_digest` — were also rejected by `observes_payment.py` inside `reproduce.sh`, 12 mutants repo-wide.)

**Anti-vacuity check (my own fresh mutants, not the committed ones):** I derived three additional mutants with tshark filters and confirmed rejection — dropping all `X-Test-Case: C10` traffic from the chain capture → `FAIL C10: missing from capture`; stripping all responses from the inbound capture → `FAIL ... unpaired request`; dropping all `X-Test-Case: P8_*` traffic from the chain capture → `FAIL P8_no-delegation: missing from capture` (etc.). The checkers fail loudly on missing, unpaired, or leaked traffic; they are not passing vacuously.

## 2. Code review

### 2.1 `checkers/observes_wimse.py` (501 lines)

Mechanism: runs `tshark -d tcp.port==5050,http -Y http -T json` with a duplicate-key-collecting `object_pairs_hook`, groups request/response pairs per `tcp.stream` with explicit unpaired-request/response errors, maps requests to `cases.json` via the `X-Test-Case` header, and enforces: POST-only on the `/api/v2/agents/{a}/workflows/{w}/executions` route, per-step status sets, RFC 8941 problem `type` URIs, and `WWW-Authenticate` substrings. A second tshark pass over **all** TCP checks for any `dstport == 47999` when C12/C12b are in scope.

Strengths: strict route/method enforcement; missing-case and unexpected-case detection; duplicate-header-safe parsing; no-fetch check operates on raw TCP, so a fetch that tshark cannot decode as HTTP is still caught.

Observations (not defects for the controlled single-client capture, but worth recording):
- The per-step `reason` field declared in `cases.json` (present in 32 of 35 steps) is **not** verified here — `check_case` reads only `status`, `type`, `www_authenticate`. Journal/reason verification lives in the same-family driver (`peers/`) and dev checker (`checkers/wire.py`), so the "independent" checker's scope is wire-level status/problem-type/challenge, not journal reasons.
- Untagged requests that are not POSTs to the executions route are skipped (the JWKS readiness-probe carve-out flagged in `VERIFY.md`). This cannot hide an untagged POST to the executions route — that path raises `FAIL ... missing X-Test-Case header`.
- The no-fetch check inspects only `tcp.dstport == 47999` (client-side fetch direction) and only when C12/C12b are in the requested set.

### 2.2 `checkers/observes_chain.py` (345 lines)

Mechanism: decodes HTTP on all six service ports (5050/5051/5060–5063), pairs requests/responses positionally per stream, and verifies against `chain_cases.json` (19 cases): expected status sets and `expected_reason` per case; C10 ordering (200-accept must precede 403-revoked); D2's 401 must carry `WWW-Authenticate: WPT`; C7/C8 must not leak credentials or a compact JWS in the body; B_CHAIN must touch all six ports, carry exactly one unified `txn` UUID across hops, and present on :5063 a WPT whose `wth`/`tth` equal the **recomputed** base64url SHA-256 of the WIT and Txn-Token (cryptographic binding, not just presence). Cross-domain isolation: any `Txn-Token` on ports 5060–5063 whose JWT `aud == maurice.ietf127.example`, or whose `kid == tts_a-1` / `iss` mentions maurice, is a hard `SystemExit(1)`.

Strengths: the leak check and the WPT binding are genuine cryptographic checks; the C6 exemption in the leak heuristic is correct by design (C6 intentionally presents a Domain-A token to Domain B and must be rejected — verified via the expected `403 txn-token-invalid`).

Observations:
- Request/response pairing is positional per stream; sound for sequential HTTP/1.1 on a controlled capture, but a reordered or pipelined stream would mispair rather than fail cleanly.
- All untagged requests on chain ports are silently skipped; the `/.well-known/wimse/jwks.json` / `/health` condition is dead code (both branches `continue`). An untagged non-probe request would not be flagged here.
- Leak detection is heuristic (aud/kid/iss strings); a Domain-A token minted with different claims would not match. The committed mutant uses `aud: maurice...` and is caught.

### 2.3 `checkers/observes_p1_p8.py` (372 lines)

Two halves. `verify_manifests` (run on every capture invocation as well): SHA-256-verifies all manifest-listed JSONL files, asserts 22/22 `match` flags and 22 distinct (scenario, case) pairs in the Redthread P1–P6 traces, requires all 8 mandated fields per row, enforces hard-coded canonical reason sets per scenario (P1–P6), re-checks each trace row's final decision/reason against its own declared `expected_decision`/`expected_reason` (including `" then "` multi-step reasons), and asserts the specific transitions: P1/low-value-grace `allow → allow(status-grace) → deny(status-stale)`, P4/single-accounting-rp exactly 5×`allow:ok` then `deny:limit-exceeded`, P2 `bound_s == 120` asserted with 50000 ms last-allow → 51000 ms first-deny and first-refusal ≤ bound, and before-effect `authorize(pending) → before-effect(deny, status-revoked, effect:none, 0 ms)`. The MintID testnet manifest is checked for `tracked_changes is False`, file digests, the witness-refresh attribution control (revoked agent's `holder_refresh` → `credential_revoked` while `sibling_control` is accepted), and the dual-time-origin delta window 13.5–14.5 s (~13.9 s). The sandbox negative-control manifest is checked for 4 JSONL records with the exact session IDs and `proof_invalid` / `no-agent-answer` outcomes. `verify_capture` decodes port 5064 and checks 10 `EXPECTED_LIVE_CASES` (P2×4, P7×2, P8×4) for exact status plus body fields (`decision`, `reason`, `effect`, `bound_s`, `token_released`, `ts`), rejecting duplicate `X-Test-Case` values and missing cases.

Strengths: expectations are cross-checked against hard-coded constants (reason sets, bound_s, timings, session IDs, delta window), not only against the manifests; duplicates and omissions fail.

Observations:
- `expected_decision`/`expected_reason` are read from the same JSONL rows under test, so that portion is partially self-referential; the hard-coded reason sets and transition assertions are what make it independent.
- Capture mode always runs `verify_manifests` first — a side effect that makes the pcap check depend on the scenarios directory being intact (true in this repo).
- `P8_revoked-after-token-released` has no `decision` expectation (only status/reason/`token_released`), by design of that boundary case.

### 2.4 Negative-mutant generators

`make_negatives.py` / `make_chain_negatives.py` / `make_p1_p8_negatives.py` derive mutants from a real capture: `unrelated` = first 3 frames via `editcap`; `request_only` = responses stripped via tshark filter; `forbidden_fetch` = a synthetic TCP SYN to port 47999 appended at the pcap record level (validated to be little-endian DLT_NULL); `chain_leaked_txn` = a synthetic HTTP POST to :5062 carrying a Domain-A-audience `Txn-Token` JWT, appended likewise; `p1_p8_missing_before_effect` = first 20 frames. Each mutant targets a distinct checker invariant (presence, pairing, no-fetch, isolation, completeness), and each was observed to fail on exactly that invariant (Section 1). The synthetic-packet mutants are fair: they exercise the all-TCP scan and the JWT-decoding leak check rather than the HTTP dissector alone.

## 3. Verdict

- `./reproduce.sh` exits 0 end-to-end; all three bundles verify, all four checker suites pass, all 12 committed negative mutants are rejected (the 9 in scope individually re-confirmed with exit 1 and the intended FAIL reasons).
- The three checkers under review account for exactly **85 passing test cases** (34 WIMSE wire + 19 chain wire + 10 P1–P8 live + 22 P1–P6 manifest traces) and **9 rejected negative mutants**.
- Fresh self-derived mutants (dropped case traffic, stripped responses) are also rejected, so the passes are not vacuous.

Residual risks to keep in mind (consistent with `VERIFY.md`): `X-Test-Case` is unsigned, so the wire checkers are valid only for a controlled single-client capture; each suite is backed by a single committed capture (no flakiness re-run); and `observes_wimse.py` does not verify journal `reason` expectations — that coverage comes from the same-family driver, not from this independent checker.

Note: running `./reproduce.sh` regenerates the audit-date line in `handover/aep/aep_verification_report.md` (step 6 re-runs the AEP verifier); I restored that file afterwards, so the tree is clean at `3d4fab4`.

## 4. Verification goals (Vibe brief, 2026-11-15)

### 4.1 Wire correctness (AI2II Rule L4) — CONFIRMED

Source audit of the three checkers: the **only** capture access is `tshark -r <pcap> [-d tcp.port==…,http] -Y http -T json` (plus one all-TCP pass in `observes_wimse.py` for the port-47999 scan). The only non-pcap inputs are `cases.json`, `chain_cases.json`, and the P1–P8 scenario manifests/JSONL traces — the latter pinned by SHA-256 inside the manifests themselves. `grep -i "journal|\.log|decision-journal"` over all three checkers returns **nothing**: no application logs are read or trusted. Status lines, request lines, headers (`X-Test-Case`, `Txn-Token`, `WIT`/`WPT`, `WWW-Authenticate`) and bodies (`http.file_data` hex) all come from packet bytes via tshark.

Byte-level tamper tests on copies of the committed captures (same-length in-place byte flips, so pcap structure stays valid):

| Tamper (raw bytes in pcap copy) | Checker | Result |
|---|---|---|
| Rename `X-Test-Case: C12` → `X12` in inbound capture | wimse | exit 1 — `FAIL stream 44: unexpected case ID 'X12'` + `FAIL C12: expected 1 step(s), got 0` |
| Flip all 9 `HTTP/1.1 200 OK` → `401 OK` in inbound capture | wimse | exit 1 — `FAIL A2/A4/A12a–d …: status 401 not in expected [200]` |
| Flip one B_CHAIN hop response (frame 243) 200 → 400 | chain | exit 1 — `FAIL B_CHAIN: request on stream 34 … has no response` |
| Flip all 25 `HTTP/1.0 200 OK` → `400 OK` in chain capture | chain | exit 1 (but see finding F2 below — it crashes instead of printing a clean FAIL) |

Two findings from these probes:

- **F1 (strictness, medium):** `observes_chain.py` uses subset semantics for per-case statuses (`exp_set.issubset(observed)`). Flipping **one** B_CHAIN hop's response from 200 to 403 in the raw pcap (`HTTP/1.0 403 OK`, same length) still passes with exit 0 — `CHECK B_CHAIN statuses=[403, 200, …]`. The wimse checker, by contrast, requires exact step-count equality and per-step status membership, so the equivalent flip there fails. Mitigated by the unpaired-request check, the port-coverage check, the unified-txn check, and the WPT binding check — but a single wrong-status hop on a multi-request case is not flagged by the status check itself.
- **F2 (robustness, low):** `observes_chain.py:282` — `c10_seq.index(200) > c10_seq.index(403)` raises an unhandled `ValueError` when C10's observed statuses contain a 403 but no 200 (reproduced with the all-200→400 tamper). Exit code is still nonzero, so negative-control semantics in `reproduce.sh` are unaffected, but the failure surfaces as a traceback rather than a structured `FAIL C10: …` line. The guard should be `200 not in c10_seq or c10_seq.index(200) > c10_seq.index(403)`.

### 4.2 Negative controls — CONFIRMED (observed on the wire, from checker output)

All observed statuses below are read from the pcap by the checkers (not from logs), and match the expectations in `cases.json` / `chain_cases.json` / `EXPECTED_LIVE_CASES`:

| Attack class | Cases | Expected → observed status |
|---|---|---|
| Invalid token / wrong key / bad proof | C2, C4, C4b, C5, D1 | 400 → 400 |
| Invalid Txn-Token variants | C6, D3_exp, D3_sig, D3_typ, D3_reqwl, D3_dup | 403 → 403 (`txn-token-invalid`) |
| Expired credential | IN4 | 400 → 400 |
| Tampered body / replay / duplicate or keyid signature | IN10, IN11, IN12, C3 step 2 | 400 → 400 (C3 step 1: 200 → 200, then replay 400) |
| Revoked credential | C10, P2_revoke-upstream, P2_before-effect, P8_revoked-between-authz-and-use | 403 → 403 (`revoked` / `status-revoked`); C10 observed `[200, 200, 403, 200]` with the checker enforcing 200-before-403 ordering |
| Missing / mismatched proof | A5, A6b, IN13, D2 | 401 → 401 (A6b allows 400/401); D2's 401 carries `WWW-Authenticate: WPT` |
| Valid identity but no grant / not authorized / grant-invalid | IN15, C9, C9b, D4, D5, D7, A13j, P8_no-delegation, P8_write-under-read, P7_display-mismatch | 403 → 403 |
| SSRF via `jku`/`x5u`/`iss` URL | C12, C12b, C11, IN6 | 400 → 400, 403 → 403 — and zero TCP packets to port 47999 in the capture (all-TCP scan) |
| `wimse://` URI parsing attacks | A13a–A13h | 400 → 400 |
| Prompt-injection containment | C7, C8 | final hop 403 → 403, no `leaked_credentials`, no JWS in body |

### 4.3 Reproducibility — CONFIRMED

- `./reproduce.sh` was executed **twice** in this session; both runs exited **0** with `ALL REPRODUCIBILITY CHECKS PASSED` and identical `SUMMARY` lines (`cases=34/19/10 errors=0`, payment PASS), identical bundle `OK`/`PASS` lines, and the same 12 mutant rejections. The only byte that differs between runs is the regenerated audit-date timestamp in `handover/aep/aep_verification_report.md` (step 6 rewrites the report each run; restored afterwards — tree clean at `3d4fab4`).
- Checker determinism: each of the three checkers was run twice on the same pcap; stdout+stderr are **byte-identical** across runs (verified with `diff`), as are the negative-mutant rejections (exit 1, identical output).
- Digest integrity, checked independently of `reproduce.sh`: `sha256sum -c SHA256SUMS` passes for all **13** entries in `validation/bundle-inbound/inbound`, **17** in `validation/bundle-chain/chain`, **10** in `validation/bundle-payment/payment` (40/40 OK, including `capture.pcap`, `verdict.json`, journals, and the negative-mutant inputs); plus all **8** SHA-256 entries embedded in the two `scenarios/p1_p8` manifests (Redthread local + MintID testnet trace). `wire verify-bundle` independently returns `OK` for all three bundles, and `wire summarize validation` prints `PASS` ×3.
