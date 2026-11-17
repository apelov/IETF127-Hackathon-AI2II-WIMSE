<!-- Mistral Vibe, headless (`vibe --prompt-file`), run 17 Nov 2026 on a separate checkout of ae228cc. Report as written, with one local path removed. -->

# Independent review 1 of 2 — code, checkers, evidence (IETF 127 WIMSE, commit `ae228cc`)

Reviewed at `ae228cc`; during the session the maintainer's session committed `bf10aed` and `73cd9e0` (bundle re-recording). `git diff ae228cc HEAD -- checkers reproduce.sh chain_cases.json cases.json interop.yaml .github peers scenarios` is empty except `wire/run.py` (local-path scrubbing only), so all findings below cite `ae228cc` content. No tracked file was modified, added, or deleted by me; all scratch work is under `/tmp/vibe-review-77272`. No `--live`/`--live-testnet` run, no servers on 5050–5064, no network access except none (the venv already existed, so no pip run was needed).

## 1. `./reproduce.sh` full run

```
$ ./reproduce.sh        # EXIT=0
... wire verify-bundle -> OK (bundle-inbound, bundle-chain, bundle-payment)
... wire summarize validation -> PASS rows
... observes_wimse.py  capture.pcap  -> SUMMARY cases=34 errors=0
... 3 inbound mutants rejected (exit 1 each)
... observes_chain.py  capture.pcap  -> SUMMARY cases=19 errors=0
... 4 chain mutants rejected, incl. chain_hop_flipped.pcap
... observes_p1_p8.py  capture.pcap  -> SUMMARY cases=10 errors=0
... 3 p1_p8 mutants rejected
... step 5: Redthread 22/22, MintID manifest, sandbox negative control, cred-P8 manifest verified
=== ALL REPRODUCIBILITY CHECKS PASSED ===
```

Result: **exit 0, all stages pass, 10 committed negative mutants rejected.** Working tree clean afterwards.

## 2. Mutation testing of the packet checkers (copies under `/tmp/vibe-review-77272`)

Method: same-length byte edits inside individual pcap records (pcap structure stays valid), run with `.venv/bin/python checkers/<checker> <mutant>`. Frame map was dumped first with `tshark -T fields` (e.g. B_CHAIN = requests at frames 240/254/268/282/296/304/319/325/340 on ports 5051/5050/5051/5061/5060/5061/5062/5061/5063).

| Mutant (chain capture) | Expected | Observed |
|---|---|---|
| M1: one B_CHAIN hop response 200→403 | reject | **rejected** `FAIL B_CHAIN: expected all hops to return 200, observed non-200 in [403, 200, ...]` |
| M8: C7 intermediate 5061 hop 200→403 (status *set* unchanged — the old F1 case) | reject | **rejected** `FAIL C7: hops ['5062 200 -', '5061 403 -', ...] differ from expected_hops [...]` |
| M2: drop the whole `:5050` Maurice hop (stream 35) | reject | **rejected** (hops length + missing port 5050) |
| M3/M3b: C5 deny reason `proof-invalid`→`proof-invalix` (reason member only / both members) | reject | **rejected** `FAIL C5: hops ['5063 400 proof-invalix'] differ from expected_hops ['5063 400 proof-invalid']` |
| M4: reorder hops (move `:5050` hop records to end of file) | reject | **rejected** (observed order ≠ expected order) |
| M5: remove WPT binding (rename `Authorization: WPT ` header in the `:5063` B_CHAIN request) | reject | **rejected** `FAIL B_CHAIN: missing verified WPT wth/tth SHA-256 binding on :5063` |
| M7: C10's `403 revoked` → 200 | reject | **rejected** (both the C10 ordering check and the hops check fire) |
| **M6: swap the `X-Test-Case` labels of C9 and D4 (frames 505/701, same length)** | reject | **WRONGLY ACCEPTED** — exit 0, `SUMMARY cases=19 errors=0` |

P1–P8 (`observes_p1_p8.py`, port 5064): P7 reason text changed → rejected (`FAIL P7_display-mismatch: body['reason']='display-mismatxh' != 'display-mismatch'`); P2 status 403→200 → rejected. Changing the free-text `decision` of `P8_revoked-after-token-released` is accepted — by design (no `decision` expectation for that case).

WIMSE (`observes_wimse.py`, inbound capture): A5 401→400 → rejected; A6a problem-`type` suffix changed → rejected. Changing the RFC 9457 `title` text is accepted (not a checked field).

**The `ae228cc` change works.** The hop-by-hop comparison (`checkers/observes_chain.py:310`) rejects every status/reason/order/drop/WPT mutation I tried; prior findings F1 (subset status semantics) and F2 (C10 `ValueError` crash) from `mistral-vibe-review.md` are closed — the C10 guard at `observes_chain.py:299-303` now checks membership before `index()`.

**`expected_hops` vs the case titles and `peers/chain_driver.py`:** I dumped every tagged request (frame, stream, port, route) and compared with `chain_cases.json`. B_CHAIN's 9 hops match both the driver's 5 requests and the 4 server-side hops (domain_b propagates `X-Test-Case`); C7/C8's 4 hops, C10's 4, D2's 2 (5063+5050), D7's 3 all match. Two titles overclaim relative to what `expected_hops` encodes: **D5** (`chain_cases.json:229`) says "guard blocks Domain A Txn-Token from leaving Domain A / AS-B rejects raw Txn-Token", but the guard half never appears on the wire (`safe_send` raises before sending, `chain_driver.py:88-96`) — `expected_hops` encodes only the `:5061 403 grant-invalid` hop, and that is AS-B's own `at+jwt`, not a raw Txn-Token; **D6** (`chain_cases.json:240`) says "widened scope and mutated txn rejected" while `expected_hops` are 4× `5051 200 -` — the rejection is driver-side only (the `wire_note` at line 253 admits this). Also C8 has `expected_statuses: [200]` but an `expected_hops` entry `5063 403 not-authorized` (inconsistent fields, explained by its `wire_note`).

**Wrongly accepted mutant (only one): M6.** C9, C9b and D4 all have identical `expected_hops` (`["5063 403 not-authorized"]`), and the checker never looks at the request URI or token claims, so swapping the unsigned `X-Test-Case` labels between two such cases passes. Inherent to unsigned case tags, but it means the checker cannot distinguish these attack classes — see finding F5 below.

## 3. Findings

| # | Severity | Location | Evidence | Why it matters |
|---|---|---|---|---|
| F1 | medium | `reproduce.sh:67-72` | `env PATH=/usr/bin:/bin ./reproduce.sh` → `EXIT=0`, output contains `[WARN] tshark not found on PATH; skipping the packet checkers. Nothing in step 4 was checked.` **and** `=== ALL REPRODUCIBILITY CHECKS PASSED ===` | A local run without tshark exits 0 and prints "ALL CHECKS PASSED" while zero packet checks ran. CI mitigates this (`REQUIRE_TSHARK=1` in `.github/workflows/reproduce.yml`, verified: with tshark hidden and `REQUIRE_TSHARK=1` the script exits 1), but the default local path over-reports. |
| F2 | medium | `checkers/observes_wimse.py:385-407` (check_case); `cases.json` step `reason` fields | `grep -n reason checkers/observes_wimse.py` → no matches; wire bodies of the 401/400 responses are `{"type":...,"title":...,"status":...}` (RFC 9457) with **no** `reason` member (e.g. frame 101: `{"type":"about:blank","title":"Unauthorized","status":401}`) | The per-step `reason` expectations declared in `cases.json` (32 of 35 steps) are never checked by the "independent" wimse checker, and are not even present on the wire; they are checked only by the same-family driver against its own journal (`peers/driver.py:159-160`). A capture with wrong Suite-1 reject reasons would pass `observes_wimse.py`. Chain reasons *are* checked (`observes_chain.py:313-320`), so this is Suite-1 specific. Still open from `mistral-vibe-review.md` §2.1. |
| F3 | low | `wire/__main__.py:42-65` (`_summarize`); `reproduce.sh:27` | Copied `validation/bundle-chain/chain` to `/tmp`, set `verdict.json` `verdict:"FAIL"`, regenerated `SHA256SUMS`: `.venv/bin/python -m wire verify-bundle <copy>` → `OK` (exit 0); `wire summarize <copy>` → prints `FAIL ... deliberately flipped for review`, **exit 0** | Step 3 of `reproduce.sh` verifies only digest/layout integrity; a bundle whose recorded verdict is FAIL/BLOCKED but whose digests are consistent does not fail the script. Step 4 re-checks the captures, so only non-wire failures (e.g. a peer crash with a well-formed capture) slip through. `wire summarize` exiting 0 on FAIL/UNVERIFIED rows is the root cause. |
| F4 | low | `checkers/observes_chain.py:195-212` | Code reads only `Txn-Token` **headers** of requests to ports 5060-5063; request bodies are never scanned. (Opus B3, still open: kid/iss were added, bodies were not.) | A Domain-A token sent in a body (e.g. `subject_token` to `:5061/oauth/token`) is not flagged by the cross-domain isolation check. No committed case does this, so no published result is wrong, but the isolation negative control is narrower than claimed. |
| F5 | low | `checkers/observes_chain.py:178-190,310`; `chain_cases.json` C9/C9b/D4 | Mutant M6 above: swapping `X-Test-Case: C9`↔`D4` labels (same-length byte edit, frames 505/701) → exit 0, `SUMMARY cases=19 errors=0` | Case identity is the unsigned `X-Test-Case` header plus an expected hop shape; the checker does not verify route/URI/token claims, so cases with identical shapes (C9, C9b, D4) are interchangeable in a forged capture. Single-client controlled capture, so low severity, but it is the one mutant I found wrongly accepted. |
| F6 | low | `peers/domain_a.py:113,144,158-160,271-272`; `peers/domain_b.py:535-544` | `test_mode` is read from the request body at TTS-A (`widen_scope`, `change_txn`) and AS-A (`wrong_aud`); `POST :5063/admin/revoke` is unauthenticated and `{"clear":true}` wipes all revocations | Request-switchable "test mode" and an unauthenticated admin endpoint in the peers under test. Neither corrupts a published result: `SCENARIOS_AND_AUTHORS.md:109` and the D6 `wire_note` disclose that D6's rejections are driver-side, and C10's claim doesn't assert the admin endpoint is secured. In a real deployment both would be critical; here they are labeled harness affordances. (Opus C2, still open in code.) |
| F7 | low | `peers/p2_p7_p8_executor.py:160-165,206-210` | `/p2/execute` takes `verifier_url`, `session_id`, `utc` from the **request body**; with `verifier_url` set it performs a live outbound call (`mintid_outside.outside(verifier_url, ...)`) instead of the replay | A request can switch the "replayed" P2 outside cases into live calls to an arbitrary URL (SSRF-shaped) and can forge the `session_id`/`utc` in the response; `EXPECTED_LIVE_CASES` does not check `session_id`. The committed capture does not use this path and `TEST_RESULTS_SUMMARY.md` labels the capture as a replay, so the published result is unaffected. |
| F8 | low | `checkers/observes_live_partners.py:60-70,196`; `deploy/networks.json` | Local loopback test (port 18080): verifier answers 200 with `sync_status:"catching_up"` → `cases=3 errors=0 mode=DEGRADED`, hooks `live_cases=0 mocked=4 errors=0`, `main()` would exit 0 | `ae228cc` makes dead endpoints fail, but a reachable-yet-not-synced verifier still exits 0 with all four hook cases mocked. The SUMMARY line does print `mode=DEGRADED mocked_cases=4` and `TEST_RESULTS_SUMMARY.md` discloses the mocking, so labeling is honest; only the exit code doesn't flag it. Additionally `load_networks` reads `networks["testnet"]["endpoints"]` (line 53) but `deploy/networks.json` nests URLs under `profiles.testnet.chains`, so the checker always silently falls back to the hardcoded `*.testnet.mintid.net` defaults. I could not test the LIVE path (no network allowed). |
| F9 | low | `chain_cases.json:229` (D5 title), `:240-253` (D6 title) | D5 `expected_hops` = only `["5061 403 grant-invalid"]`; the guard-block half of the title is never on the wire (`chain_driver.py:88-96` raises before send). D6 `expected_hops` = 4× `"5051 200 -"` while the title says "widened scope and mutated txn rejected" | Titles promise more than the checker verifies. Both are partially disclosed (`wire_note` for D6; `SCENARIOS_AND_AUTHORS.md:109`), but a reader of the titles alone would over-read the wire evidence. |

## 4. What I checked and found correct

- **`./reproduce.sh` in full: exit 0**, all five stages, 34+19+10 wire cases pass, all 10 committed negative mutants rejected with exit 1, partner manifests verified (log at `/tmp/vibe-review-repro.log`).
- **The new `expected_hops` comparison is sound**: rejects single-hop status flips (B_CHAIN and C7), dropped hops, changed reason strings, reordered hops, removed WPT binding, and C10 revoked→200 (mutants M1–M5, M7, M8 above). Prior F1/F2 and opus B1/B2 and nemotron CHK-1/CHK-2 are closed.
- **`expected_hops` matches the wire and the driver** for all 19 cases (per-case frame/port/route dump vs `chain_cases.json` vs `peers/chain_driver.py`).
- **All checkers exit non-zero on bad input** (commands run per checker): missing file (exit 1), 0-byte file (exit 1), directory (exit 1), 5 KB of `/dev/urandom` (exit 1), no args (exit 2), `observes_p1_p8.py --verify-manifests <missing>` (exit 1). `wire verify-bundle <missing>` → `NOT OK: SHA256SUMS missing`, exit 1; `wire summarize <empty dir>` → exit 2.
- **Failure propagation**: `reproduce.sh` has `set -euo pipefail`; with a stub `tshark` that exits 1, the script aborted with `EXIT=1` at the first checker (`FAIL: tshark failed: stub failure`), never printing PASS. The negative-mutant loops explicitly `exit 1` if a mutant is accepted. The CI workflow (`.github/workflows/reproduce.yml`) installs tshark and runs `REQUIRE_TSHARK=1 ./reproduce.sh`, so a missing-tshark CI run fails instead of skipping (verified locally: exit 1). I could not execute GitHub Actions itself.
- **P1–P8 checker**: rejects changed reason/status on `:5064` live cases, duplicate and missing cases (committed mutants); manifest half verifies SHA-256s, 22/22 decisions+reasons independently of the partner's `match` flag, the P2 50 s→51 s boundary and `bound_s` bound, MintID dual-time-origin and witness-refresh controls.
- **:5064 executor labels are honest**: `peers/p2_p7_p8_executor.py:1-15` docstring states P7/P8 are fixed answers with `impl: "p7-fixed-answer-mock"`/`"p8-fixed-answer-mock"` and "No OmniArx or Cred code runs"; P2 is "a copy of Redthread's ProtectedOperation with a simulated verifier… plus two replayed MintID sandbox outcomes"; log lines carry `clock: "simulated"`. `TEST_RESULTS_SUMMARY.md` rows for P7/P8/Suite-4 say "mocked"/"replayed" and do not claim partner code ran. No overclaim found.
- **WIMSE checker strictness**: exact step-count equality, per-step status membership, problem-`type` URI check, `WWW-Authenticate` substring check, all-TCP scan for port 47999, untagged POST to the executions route fails (`FAIL stream N: request missing X-Test-Case header`), unexpected case IDs fail.
- **Prior-review open items re-checked**: opus B3 (leak check bodies) still open → F4; opus C2 (test_mode) still open in code but disclosed → F6; gemini RT-1 (`run_local.py:194` `match` still compares reason only) remains in the partner runner, but the checker-side gap is closed (decision verified independently in `observes_p1_p8.py:125-129`).
- **Known out-of-scope item confirmed benign in effect**: the external commits after `ae228cc` re-recorded the bundles and scrubbed absolute local paths from `env.json` (`wire/run.py` `rel()`); no consequence for the checker logic found.

**Not verified** (state explicitly): the LIVE mode of `checkers/observes_live_partners.py` against the real testnet (network access was out of scope); GitHub Actions execution of the workflow; the P7 Ed25519 vectors and Cred runs are partner-attested only, as the docs themselves state.

## Maintainer triage (17 Nov 2026)

| # | Decision | Change |
|---|---|---|
| F1 | accepted | `reproduce.sh` now fails when tshark is missing; `ALLOW_NO_TSHARK=1` skips step 4 and the last line then says the packet checkers did not run. CI no longer needs `REQUIRE_TSHARK`. |
| F2 | accepted, documented | Maurice's problem details carry no reason member, so the wire cannot show it. `TEST_RESULTS_SUMMARY.md` now says Suite 1 reasons are checked by the driver against Maurice's journal, not by the wire checker. |
| F3 | accepted | `reproduce.sh` step 3 fails when any committed bundle's recorded verdict is not PASS. |
| F4 | accepted | `observes_chain.py` also scans request bodies to Domain B for Domain A Txn-Tokens; new mutant `chain_leaked_txn_body.pcap` (untagged, so only the body scan rejects it; the previous checker accepts it). |
| F5 | accepted, documented | Inherent to unsigned case labels; listed under "What the captures do not show" in `TEST_RESULTS_SUMMARY.md`. |
| F6 | accepted, documented | Listed there as test affordances that do not change a published result. |
| F7 | accepted | The executor no longer takes `verifier_url` from the request body; live outside calls need `WIMSE_EXECUTOR_LIVE_VERIFIER` set by the operator. |
| F8 | accepted | `observes_live_partners.py` fails when the verifier is not synced, and reads `profiles.testnet.chains` from `deploy/networks.json`. |
| F9 | accepted | D5 and D6 titles in `chain_cases.json` now describe only what is on the wire; D5 has a `wire_note`. |
