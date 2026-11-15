# Independent review: multi-hop call chain and P1–P8, 2026-11-15

| | |
|---|---|
| **Reviewer** | `claude -p --model opus` / `claude-opus-5-5-high` (Anthropic Claude Opus family) |
| **Date** | 2026-11-15 (wire timestamps `iat=1794715816` = `2026-11-15T04:10:16Z`) |
| **Repository HEAD** | `cd9cd3d` (WP08), working tree clean except this file |
| **Scope** | Cell `chain`: `validation/bundle-chain/chain/capture.pcap` (824 packets, 106 HTTP messages = 53 request/response exchanges, request frames `f39`–`f816`). It covers the 19 Suite 2 cases in `chain_cases.json` and the 10 live Suite 3 `P2/P7/P8` cases on `:5064`. Also in scope: `checkers/observes_chain.py`, `checkers/observes_p1_p8.py`, `checkers/make_chain_negatives.py`, `checkers/make_p1_p8_negatives.py`, the six chain and P1–P8 negative mutants, `scenarios/p1_p8/` manifests, `EVIDENCE.md`, and `SCENARIOS_AND_AUTHORS.md`. |
| **Inputs** | Full `tshark` dissection (`chain_dump.txt`), `verify_crypto.py` (ES256 / RFC 9421 / WPT binding), `verify_evidence.py` (32 SHA-256 digests), stdout, stderr and exit codes of both checkers on the live capture, the manifest directory and all six mutants. |
| **Verdict** | **PASS** on the wire evidence, the checkers and the artifact digests, with the required documentation items in §8.1 to be applied by `@sonnet-builder` before the final commit. |

**Limit of this review (AI2II Rule L4):** the peers under test are listed as authored with **Anthropic Claude Opus 4.6**. This reviewer is from the same model family. So this review checks the evidence but **does not establish model-family separation** for the `chain` cell. That separation has to come from a checker whose authoring model family is named and differs from Anthropic Claude (see item A9). Like `validation/nemotron-review.md`, this review does not replace an independently authored capture checker.

---

## 1. Summary of results

| Check | Result |
|---|---|
| `observes_chain.py capture.pcap` | `exit=0`, `SUMMARY cases=19 errors=0` |
| `observes_p1_p8.py capture.pcap` | `exit=0`, `SUMMARY cases=10 errors=0` |
| `observes_p1_p8.py --verify-manifests scenarios/p1_p8` | `exit=0`: 22/22 Redthread cases, MintID dual time origins and witness-refresh control, 2/2 sandbox negative controls |
| Negative mutants (6) | **6/6 rejected with `exit=1`** (§6) |
| ES256 JWS signatures | **84/84 verify** under the key named by their header (`jwt_bad=0`) |
| RFC 9421 signatures | **18/20 valid.** The 2 invalid ones are the intended negatives `C5` f366 and `D3_dup` f690. |
| WPT `wth`/`tth` binding | **5/7 valid.** The 2 invalid ones are the intended negatives `D2` f606 (`:5063`) and f620 (`:5050`), both `tth="wrong_hash"`. |
| `EVIDENCE.md` digests | **32/32 SHA-256 match.** Packet counts and JSONL line counts match. One HTTP-message count is wrong (104 claimed, 106 observed; item A6). |
| Deny reasons on the wire vs `chain_cases.json` `expected_reason` | Checked by hand: **every deny response matches**. The one exception is f620, where Maurice returns RFC 9457 `about:blank` without a `reason` member. The checker itself does not test reasons (item B1). |
| Domain A Txn-Token on Domain B ports (`5060–5063`) | **None during `B_CHAIN`.** The only Domain A-signed Txn-Token seen on a Domain B port is the deliberate `C6` attack at f379, which was rejected with `403`. |

---

## 2. `B_CHAIN`: 9-hop, 2-domain call chain

All hops carry `txn = feb0e93d-29ec-42e0-b777-b15262f178d9`. Request frames are f240–f340. The response frames continue to f357.

| # | Frame / stream | Port and endpoint | Caller on the wire (WIT `sub`) | Credentials presented | Token issued / result | Status |
|---:|---|---|---|---|---|---:|
| 1 | f240 / s34 | `:5051 POST /tts/token` (TTS-A) | *none* (no WIT or signature) | body: `sub=user:alice`, `scope="files:read files:list"`, `tctx={file:Q3.pdf}` | `T_A` (`kid=tts_a-1`, `typ=txntoken+jwt`, `aud=maurice.ietf127.example`, 120 s lifetime) | 200 |
| 2 | f254 / s35 | `:5050 POST /api/v2/agents/…/workflows/text-stats/executions` (Maurice) | `wimse://peer.ietf127.example/client` | WIT + RFC 9421 (`@method @path @query content-type content-digest txn-token workload-identity-token`, `wimse-aud=…:5050`) + `T_A` | workflow `completed`, `{"count":11,"upper":"HELLO WIMSE"}` | 200 |
| 3 | f268 / s36 | `:5051 POST /oauth/token` (AS-A) | `wimse://peer.ietf127.example/client` | WIT + RFC 9421; `subject_token=T_A` in body | assertion (`kid=as_a-1`, `typ=jwt-chg+jwt`, `aud=http://rich.ietf127.example:5061/oauth/token`, 60 s) | 200 |
| 4 | f282 / s37 | `:5061 POST /oauth/token` (AS-B) | *none* | `assertion` in body | `AT_B` (`kid=as_b-1`, `typ=at+jwt`, `aud=[:5060, :5062]`) | 200 |
| 5 | f296 / s38 | `:5060 POST /coordinate` (Agent 2, Coordinator) | `wimse://peer.ietf127.example/client` | WIT + `Authorization: Bearer AT_B` + RFC 9421 covering `authorization` | `summary="$4.2M"`, `hops=[agent1:maurice, agent2:coordinator, agent3:research, tool:files]` | 200 |
| 6 | f304 / s39 | `:5061 POST /tts/token` (TTS-B) | *none* | `access_token=AT_B`, `req_wl=…/agent/coordinator` | `T_B1` (`kid=tts_b-1`, `scope="files:read files:list"`) | 200 |
| 7 | f319 / s40 | `:5062 POST /research` (Agent 3, Research) | `wimse://rich.ietf127.example/agent/coordinator` | WIT + RFC 9421 covering `txn-token` + `T_B1` | `summary="$4.2M"`, `leaked_credentials=false` | 200 |
| 8 | f325 / s41 | `:5061 POST /tts/token` (TTS-B replacement) | *none* | `txn_token=T_B1`, `scope=files:read`, `req_wl=…/agent/research` | `T_B2` (`scope="files:read"`) | 200 |
| 9 | f340 / s42 | `:5063 POST /files/read` (File Tool) | `wimse://rich.ietf127.example/agent/research` | WIT + WPT (`aud=…:5063`, `wth=0r5nBi…`, `tth=IJpkzQ…`) + `T_B2` | Q3.pdf content, which contains the prompt-injection payload used by C7/C8 | 200 |

**Confirmed on the wire**

- **One transaction ID end to end.** `feb0e93d-…` appears in `T_A`, the AS-A assertion, `AT_B`, `T_B1`, `T_B2`, and every response body that carries `txn`. The checker found exactly one transaction ID.
- **Scope narrowing.** `T_B1` has `files:read files:list`; `T_B2` has `files:read` (f325).
- **`req_wl` matches the presenting workload** at every Txn-Token hop: f254 `peer/client`, f319 `agent/coordinator`, f340 `agent/research`.
- **WPT binding at f340.** `tth` equals `sha256(T_B2)` = `IJpkzQ4BwI50wlxmEOE24nkOKDMWRRPui_ix1dhlIkg`. `wth` equals `sha256(WIT)` = `0r5nBiC6bOcqBQl4SJNOws3B_7PH3UmjBHjFaGAO0gc`.
- **Domain separation.** `T_A` (`tts_a-1`) appears only on `:5050` and `:5051`. Only the AS-A assertion (`jwt-chg+jwt`, audience AS-B) crosses into Domain B, as intended.

**Differences from the documentation (feed items A2 and A3)**

- **Agent 1 is not a forwarding hop.** Hops 2, 3 and 5 are all sent by the driver identity `wimse://peer.ietf127.example/client`. Maurice runs a separate workflow; it does not call AS-A or Agent 2. Only the Domain B side (hops 7 → 9) is genuine agent-to-agent nesting.
- **No `act` claim exists** in any Txn-Token, assertion or access token in the capture. The documented claim of "recursive `act` nesting (research-subagent → coordinator → maurice)" is not supported by the evidence.
- **Shared key.** The Coordinator WIT (f319) and the Research WIT (f340) share one `cnf.jwk` (`x=L-66qqjGAshn9hDbPmtqaoCztv7EePnXewNJtL8gG74`). Two workload identities can therefore produce proofs for each other (item C3).

---

## 3. Suite 2: all 19 `chain_cases.json` cases

| Case | Ref | Request frames (port) | Observed statuses | Observed reason / evidence | Expected (`chain_cases.json`) | Result |
|---|---|---|---|---|---|:---:|
| `B_CHAIN` | Phase-B | f240–f340 (§2) | 200 ×9 | one `txn`, scope narrowed, `tth`/`wth` OK | `[200]` accept | ✓ |
| `C5` | ATK-5 | f366 (`:5063`) | 400 | `proof-invalid`. Txn-Token swapped to `sub=user:bob` after signing, so the RFC 9421 signature fails (SIG-BAD). | `[400]` proof-invalid | ✓ |
| `C6` | ATK-6 | f379 (`:5063`) | 403 | `txn-token-invalid`. `tts_a-1`-signed token with `aud=foreign.ietf127.example`. | `[403]` txn-token-invalid | ✓ |
| `C7` | ATK-7 | f393 (`:5062`), f403 (`:5061`), f416, f430 (`:5063`) | 200, 200, 200, 403 | Agent 3 follows the injection; `salaries.xlsx` at f430 is denied with `not-authorized`; `injection_read_status=403` | `[200,403]` not-authorized | ✓ |
| `C8` | ATK-8 | f450 (`:5062`), f459 (`:5061`), f472, f487 (`:5063`) | 200, 200, 200, 403 | `leaked_credentials=false`. No compact JWS appears in any response body. f487 `not-authorized`. | `[200]` accept | ✓ |
| `C9` | ATK-9a | f506 (`:5063 /files/read`) | 403 | `not-authorized`. No Txn-Token sent to a route that requires delegation. | `[403]` not-authorized | ✓ |
| `C9b` | ATK-9b | f520 (`:5063 /files/index`) | 403 | `not-authorized`. Txn-Token sent to a route that allows only autonomous calls. | `[403]` not-authorized | ✓ |
| `C10` | ATK-10 | f534, f548 `/admin/revoke`, f562, f576 `/admin/revoke {clear}` | 200, 200, 403, 200 | accepted before revocation, then `revoked` after, then the revocation list is cleared | `[200,403]` revoked | ✓ |
| `D1` | TXN-1 | f592 (`:5063`) | 400 | `proof-invalid`. The signature is valid, but `txn-token` is not among the covered components. | `[400]` proof-invalid | ✓ |
| `D2` | TXN-2 | f606 (`:5063`), f620 (`:5050`) | 401, 401 | f606 `proof-invalid`; f620 RFC 9457 `about:blank` without `reason`. Both have `tth=wrong_hash`. | `[401]` proof-invalid, `WWW-Authenticate: WPT` | ✓ (status; `WWW-Authenticate` not checked) |
| `D3_exp` | TXN-3a | f634 | 403 | `txn-token-invalid` (`exp=…807 < iat=…817`) | `[403]` | ✓ |
| `D3_sig` | TXN-3b | f649 | 403 | `txn-token-invalid` (`kid=rogue-1`, verifies only under `rogue.jwks.json`) | `[403]` | ✓ |
| `D3_typ` | TXN-3c | f662 | 403 | `txn-token-invalid` (`typ=jwt`) | `[403]` | ✓ |
| `D3_reqwl` | TXN-3d | f676 | 403 | `txn-token-invalid` (`req_wl` missing) | `[403]` | ✓ |
| `D3_dup` | TXN-3e | f690 | 403 | `txn-token-invalid`. Two `Txn-Token` headers (alice / bob). The RFC 9421 signature is **also** invalid (item C5). | `[403]` | ✓ |
| `D4` | TXN-4 | f705 | 403 | `not-authorized` (`scope=profile:view`) | `[403]` not-authorized | ✓ |
| `D5` | CHAIN-1 | f718 (`:5061`) | 403 | `grant-invalid`. The rejected assertion is AS-B's **own** `at+jwt`, not a Domain A Txn-Token (item C5). | `[403]` grant-invalid | ✓ (title does not match wire) |
| `D6` | TXO-4/5 | f732, f746, f760, f775 (`:5051`) | 200 ×4 | f746 narrowing accepted. With `test_mode`, TTS-A **issues** a widened (`files:read files:write`, f760) and a mutated (`txn=mutated-7d32ff81`, f775) replacement token. **No rejection appears on the wire** (items A3 and C2). | `[200]` accept | ✓ (status only) |
| `D7` | CHAIN-2 | f788, f802 (`:5051`), f816 (`:5061`) | 200, 200, 403 | AS-A `test_mode=wrong_aud` produces `aud=http://wrong.example/oauth/token`; AS-B rejects it with `grant-invalid` | `[403]` grant-invalid | ✓ |

---

## 4. Suite 3: the 10 live `P2/P7/P8` cases on `:5064` (f100–f226)

| Case | Frame / stream | Status | `decision` | `reason` | `effect` / extras | Checker |
|---|---|---:|---|---|---|:---:|
| `P2_revoke-upstream` | f100 / s24 | 403 | deny | `status-revoked` | `none`, `bound_s=120` | ✓ |
| `P2_before-effect` | f114 / s25 | 403 | deny | `status-revoked` | log goes `authorize(allow, pending)` → `before-effect(deny, none, 0 ms)` | ✓ |
| `P2_outside-made-up-proof` | f128 / s26 | 403 | deny | `proof_invalid` | `session_id=01eac0157bbfc1f54af295fadb53dafc` | ✓ |
| `P2_outside-no-agent-answer` | f143 / s27 | 403 | deny | `no-agent-answer` | `session_id=ea27daa1d8be8f59a1c5e43963facc2d` | ✓ |
| `P7_display-match` | f156 / s28 | 200 | allow | `ok` | `ran`, `ts=1800000000`, expected digest = presented digest | ✓ |
| `P7_display-mismatch` | f170 / s29 | 403 | deny | `display-mismatch` | `none`, `ts=1800000000`, digests differ | ✓ |
| `P8_no-delegation` | f184 / s30 | 403 | deny | `no-delegation` | `token_released=false` | ✓ |
| `P8_write-under-read` | f198 / s31 | 403 | deny | `scope-exceeded` | `scopes_requested=[read, write]`, `token_released=false` | ✓ |
| `P8_revoked-between-authz-and-use` | f212 / s32 | 403 | deny | `status-revoked` | `token_released=false` | ✓ |
| `P8_revoked-after-token-released` | f226 / s33 | 200 | *free text* | `token-released` | `token_released=true`, effect "may still occur until the token expires" | ✓ |

**What this evidence does and does not show**

- **The P2 "outside" cases are replays.** Their `session_id` values equal the recorded sandbox manifest values, both responses carry the same `utc=2026-11-15T04:10:16Z`, and every log row is marked `clock: simulated`. The `:5064` executor returns recorded MintID and Redthread outcomes; it does not call MintID live (item A4).
- **The P7 digests are placeholder constants.** They are `sha256:4a8b9c0d1e2f…` and `sha256:ba9876543210fedc…`. No Ed25519 verification of the OmniArx `V1`/`V4`/`V5`/`R2` vectors appears on the wire (item A4).
- **One P2 transition is trace-only.** The `P2_revoke-upstream` allow-at-50 s → deny-at-51 s transition exists only in `redthread-P2-local.jsonl`, which `--verify-manifests` checks. The live run shows only the final deny.

---

## 5. Cryptographic verification (`verify_crypto.py`)

```text
{"jwt_ok": 84, "jwt_bad": 0, "sig9421_ok": 18, "sig9421_bad": 2,
 "digest_ok": 0, "digest_bad": 0, "wpt_bind_ok": 5, "wpt_bind_bad": 2}
```

| Class | Valid | Invalid | Notes |
|---|---:|---:|---|
| **ES256 JWS** (Txn-Tokens, WITs, WPTs, assertions, access tokens, in headers and bodies) | 84 | 0 | Keys used: `tts_a`, `tts_b`, `as_a`, `as_b`, `peer`, `rich`, `cnf.jwk`, and `rogue` (`D3_sig` only). "Valid" means the signature verifies under the key its header names. It does not mean the token is acceptable: `D3_sig`, `D3_exp`, `D3_typ` and `D3_reqwl` all verify and were correctly refused on their claims or issuer. |
| **RFC 9421** (20 signed requests: f254, f268, f296, f319, f366, f379, f393, f450, f506, f520, f534, f562, f592, f634, f649, f662, f676, f690, f705, f802) | 18 | 2 | Both invalid ones are intended: **`C5` f366** (Txn-Token swapped after signing) and **`D3_dup` f690** (duplicate `Txn-Token`). Every signature has a 60 s window (`created=…817`, `expires=…877`), `tag="wimse-workload-to-workload"`, and a `wimse-aud` that matches the destination port. |
| **WPT `wth`/`tth`** (f340, f416, f430, f472, f487, f606, f620) | 5 | 2 | Both invalid ones are intended: **`D2` f606 `:5063`** and **f620 `:5050`**, each with `tth="wrong_hash"` and a correct `wth`. Both were refused with `401`. |
| **`Content-Digest`** | — | — | **Not recomputed** (`digest_ok=0`). The RFC 9421 signatures cover the header, but nothing independently checks that the body matches the digest (item B8). |

---

## 6. Negative mutant rejection

| Mutant | Checker | Exit | Exact stderr |
|---|---|:---:|---|
| `checkers/negatives/chain_unrelated.pcap` (3 packets, 0 HTTP) | `observes_chain.py` | **1** | 21 lines (below); stdout `SUMMARY cases=19 errors=21` |
| `checkers/negatives/chain_request_only.pcap` (522 packets, 40 HTTP) | `observes_chain.py` | **1** | 61 lines (below); stdout `SUMMARY cases=19 errors=61` |
| `checkers/negatives/chain_leaked_txn.pcap` (563 packets, 81 HTTP) | `observes_chain.py` | **1** | `FAIL: Domain A Txn-Token leaked to Domain B port 5062 on stream 41` |
| `checkers/negatives/p1_p8_unrelated.pcap` (3 packets, 0 HTTP) | `observes_p1_p8.py` | **1** | 10 lines (below); stdout `SUMMARY cases=10 errors=10` |
| `checkers/negatives/p1_p8_request_only.pcap` (70 packets, 10 HTTP) | `observes_p1_p8.py` | **1** | `ERROR: Case P2_revoke-upstream on stream 0 has request without response` |
| `checkers/negatives/p1_p8_missing_before_effect.pcap` (20 packets, 3 HTTP) | `observes_p1_p8.py` | **1** | `ERROR: Case P2_before-effect on stream 1 has request without response` |

<details><summary><code>chain_unrelated.pcap</code>: full stderr</summary>

```text
FAIL B_CHAIN: missing from capture
FAIL C5: missing from capture
FAIL C6: missing from capture
FAIL C7: missing from capture
FAIL C8: missing from capture
FAIL C9: missing from capture
FAIL C9b: missing from capture
FAIL C10: missing from capture
FAIL D1: missing from capture
FAIL D2: missing from capture
FAIL D3_exp: missing from capture
FAIL D3_sig: missing from capture
FAIL D3_typ: missing from capture
FAIL D3_reqwl: missing from capture
FAIL D3_dup: missing from capture
FAIL D4: missing from capture
FAIL D5: missing from capture
FAIL D6: missing from capture
FAIL D7: missing from capture
FAIL B_CHAIN: missing expected multi-agent hop ports {5060, 5061, 5062, 5063, 5051}
FAIL B_CHAIN: expected exactly 1 unified txn UUID across hops, got set()
```
</details>

<details><summary><code>chain_request_only.pcap</code>: full stderr</summary>

```text
FAIL B_CHAIN: request on stream 1 (dstport 5051) has no response
FAIL B_CHAIN: request on stream 2 (dstport 5051) has no response
FAIL B_CHAIN: request on stream 3 (dstport 5061) has no response
FAIL B_CHAIN: request on stream 4 (dstport 5060) has no response
FAIL B_CHAIN: request on stream 5 (dstport 5061) has no response
FAIL B_CHAIN: request on stream 6 (dstport 5062) has no response
FAIL B_CHAIN: request on stream 7 (dstport 5061) has no response
FAIL B_CHAIN: request on stream 8 (dstport 5063) has no response
FAIL C5: request on stream 9 (dstport 5063) has no response
FAIL C6: request on stream 10 (dstport 5063) has no response
FAIL C7: request on stream 11 (dstport 5062) has no response
FAIL C7: request on stream 12 (dstport 5061) has no response
FAIL C7: request on stream 13 (dstport 5063) has no response
FAIL C7: request on stream 14 (dstport 5063) has no response
FAIL C8: request on stream 15 (dstport 5062) has no response
FAIL C8: request on stream 16 (dstport 5061) has no response
FAIL C8: request on stream 17 (dstport 5063) has no response
FAIL C8: request on stream 18 (dstport 5063) has no response
FAIL C9: request on stream 19 (dstport 5063) has no response
FAIL C9b: request on stream 20 (dstport 5063) has no response
FAIL C10: request on stream 21 (dstport 5063) has no response
FAIL C10: request on stream 22 (dstport 5063) has no response
FAIL C10: request on stream 23 (dstport 5063) has no response
FAIL C10: request on stream 24 (dstport 5063) has no response
FAIL D1: request on stream 25 (dstport 5063) has no response
FAIL D2: request on stream 26 (dstport 5063) has no response
FAIL D3_exp: request on stream 27 (dstport 5063) has no response
FAIL D3_sig: request on stream 28 (dstport 5063) has no response
FAIL D3_typ: request on stream 29 (dstport 5063) has no response
FAIL D3_reqwl: request on stream 30 (dstport 5063) has no response
FAIL D3_dup: request on stream 31 (dstport 5063) has no response
FAIL D4: request on stream 32 (dstport 5063) has no response
FAIL D5: request on stream 33 (dstport 5061) has no response
FAIL D6: request on stream 34 (dstport 5051) has no response
FAIL D6: request on stream 35 (dstport 5051) has no response
FAIL D6: request on stream 36 (dstport 5051) has no response
FAIL D6: request on stream 37 (dstport 5051) has no response
FAIL D7: request on stream 38 (dstport 5051) has no response
FAIL D7: request on stream 39 (dstport 5051) has no response
FAIL D7: request on stream 40 (dstport 5061) has no response
FAIL B_CHAIN: missing from capture
FAIL C5: missing from capture
FAIL C6: missing from capture
FAIL C7: missing from capture
FAIL C8: missing from capture
FAIL C9: missing from capture
FAIL C9b: missing from capture
FAIL C10: missing from capture
FAIL D1: missing from capture
FAIL D2: missing from capture
FAIL D3_exp: missing from capture
FAIL D3_sig: missing from capture
FAIL D3_typ: missing from capture
FAIL D3_reqwl: missing from capture
FAIL D3_dup: missing from capture
FAIL D4: missing from capture
FAIL D5: missing from capture
FAIL D6: missing from capture
FAIL D7: missing from capture
FAIL B_CHAIN: missing expected multi-agent hop ports {5060, 5061, 5062, 5063, 5051}
FAIL B_CHAIN: expected exactly 1 unified txn UUID across hops, got set()
```
</details>

<details><summary><code>p1_p8_unrelated.pcap</code>: full stderr</summary>

```text
FAIL P2_revoke-upstream: missing from capture
FAIL P2_before-effect: missing from capture
FAIL P2_outside-made-up-proof: missing from capture
FAIL P2_outside-no-agent-answer: missing from capture
FAIL P7_display-match: missing from capture
FAIL P7_display-mismatch: missing from capture
FAIL P8_no-delegation: missing from capture
FAIL P8_write-under-read: missing from capture
FAIL P8_revoked-between-authz-and-use: missing from capture
FAIL P8_revoked-after-token-released: missing from capture
```
</details>

**The committed chain mutants were not built from the committed capture.** Three facts show this:

- `chain_request_only.pcap` has 8 `B_CHAIN` requests on streams 1–8 and no `:5050` hop. It has one `D2` request, not two.
- `chain_leaked_txn.pcap` has 563 packets (562 + 1 injected frame), but the committed capture has 824.
- The injected leak lands on stream 41.

All three point to an earlier run from before `8f8441e` (the fix to the Maurice path). The mutants still reject correctly, but their digests cannot be reproduced from `capture.pcap`. `add_leaked_txn()` also stamps the injected frame with `time.time()`, so a rebuild would not be byte-identical anyway (items A8 and B7). The inbound mutants (`unrelated`, `request_only`, `forbidden_fetch`) were not re-run in this review.

---

## 7. `EVIDENCE.md` digest verification (`verify_evidence.py`)

`SUMMARY ok=32 bad=0`. Every one of the 32 listed artifacts matches its SHA-256 digest:

- 2 `verdict.json` bundle hashes
- 2 live captures
- 9 negative captures
- 2 decision journals
- 14 partner scenario, trace and manifest files under `scenarios/p1_p8/`
- 3 unmodified partner archives under `scenarios/p1_p8/originals/`

Packet counts match for all captures, and JSONL line counts match: 35, 38, 9, 122, 6, 8, 4, 2, 92, 4. One mismatch passed because the script compares digests and packet counts only: **line 32 claims 104 HTTP messages for the chain capture, but there are 106** (53 exchanges).

---

## 8. Items for `@sonnet-builder`

### 8.1 Required before the final commit (documentation)

**A1. `SCENARIOS_AND_AUTHORS.md` §4, Suite 2 table.** Every C and D row disagrees with `chain_cases.json` and the wire. Replace the table with the case, ref, title, status and reason columns of §3 above. The current text describes a different attack catalog: "C5 `401 transaction-revoked`", "C6 `400 invalid_target`", "C7 `403 actor-revoked`", "C8 `401 wit-revoked`", "C9 `400 invalid_grant`", "C10 `401 key-compromised`", "D1 `invalid_scope`", "D2 `transaction-leak-detected`", "D3 `wpt-tth-mismatch`", "D4a/b/c", "D5 `actor-mismatch`", "D6a/b/c", "D7a/b". None of these appear in the capture. Also:
- add `C9b`
- change "`D1`–`D7` (`12` subcases)" to **11 entries**: D1, D2, D3_exp, D3_sig, D3_typ, D3_reqwl, D3_dup, D4, D5, D6, D7

**A2. `SCENARIOS_AND_AUTHORS.md` §4, `B_CHAIN` row and diagram.**
- Change "11 Hops" to **9 hops**, matching `chain_cases.json` `hops` and §2.
- Make the diagram show the real caller. Hops 2, 3 and 5 are sent by the driver workload `wimse://peer.ietf127.example/client`; Maurice runs a side workflow and does not forward.
- Remove "recursive `act` nesting" and "nested act: research-subagent → coordinator → maurice". No `act` claim exists on the wire. Alternatively, implement `act` in TTS-B (C-series) and re-capture.

**A3. Document what D5 and D6 actually show.**
- **D5:** the rejected assertion at f718 is AS-B's own `at+jwt`, not a Domain A Txn-Token. Either retitle the case to "AS-B rejects a non-`jwt-chg+jwt` assertion", or change the driver to present `T_A` (`kid=tts_a-1`) as the assertion (item C5).
- **D6:** "widened scope and mutated txn rejected" is **not shown on the wire**. TTS-A issues both tokens with `200`. State that the rejection happens in the driver (and point to the `chain-journal.jsonl` line numbers), or add the hop where it happens on the wire (item C5).

**A4. `SCENARIOS_AND_AUTHORS.md` §4, Suite 3 rows.**
- **P2:** replace `control-unrevoked` / `cache-only-stale-window` / `before-effect-recheck` / `mintid-outside-revoked`, and "`credential_revoked`", with the four wire cases and reasons: `revoke-upstream` / `before-effect` → `status-revoked`; `outside-made-up-proof` → `proof_invalid`; `outside-no-agent-answer` → `no-agent-answer`. All four return `403`. Say that the `:5064` executor **replays** the recorded MintID sandbox outcomes (same `session_id`, `clock: simulated`) rather than calling MintID live.
- **P7:** the case names are `display-match` (reason `ok`, not `display-match`) and `display-mismatch`. Say that the live executor compares fixed placeholder digests and that the Ed25519 `V1`/`V4`/`V5`/`R2` vectors are checked only in the partner JSON, not on the wire.
- **P8:** `P8_CONTROL`, `P8_BEFORE_RELEASE` and `P8_AFTER_RELEASE` do not exist. Replace them with `no-delegation`, `write-under-read`, `revoked-between-authz-and-use` and `revoked-after-token-released`. Remove `revocation_visible_to_third_party`, which is not in any response.

**A5. `SCENARIOS_AND_AUTHORS.md` §2, align with the wire tokens.**
- WIT media type: the wire carries `typ=wit+jwt`, not `wimse-id+jwt`.
- Txn-Token: the wire carries `typ=txntoken+jwt`, not `txn-token+jwt`. It has `txn, sub, scope, tctx, req_wl` but no `purp`, `azd` or `act`.
- The HTTP signature profile covers `@method @path @query content-type content-digest [txn-token|authorization] workload-identity-token`. There is no `@target-uri` component; `wimse-aud` is a signature **parameter**, not a covered component.
- RFC 8693 / RFC 7523: f268 and f282 send JSON bodies (`subject_token`, `assertion`) with no `grant_type` and no `subject_token_type`. Say "modeled on" or make the requests conformant (item C6).
- RFC 9457: only Maurice (f620) returns problem details, and as `about:blank`. Domain B returns `{"error","reason"}`. No `urn:ietf:params:wimse:problem:*` appears in this capture.

**A6. `EVIDENCE.md` line 32:** change the HTTP Messages value for `validation/bundle-chain/chain/capture.pcap` from **104 to 106** (53 request/response exchanges).

**A7. `EVIDENCE.md` line 45 (`chain_leaked_txn.pcap`):** the leak is injected on **`:5062` (`POST /research`, stream 41)**, not `:5060`. The token has `aud=maurice.ietf127.example`, `txn=leaked` and **no `iss`**, so "`iss = https://tts.maurice.ietf127.example`" is wrong. The checker detects the leak by `aud`.

**A8. `EVIDENCE.md` line 48 (`p1_p8_missing_before_effect.pcap`):** the case names are `P2_before-effect` and `P2_outside-made-up-proof` / `P2_outside-no-agent-answer`; `P2_BEFORE_EFFECT` and `P2_MINTID_OUTSIDE` do not exist. Also, the mutant does not strip those cases. It keeps frames 1–20 (`editcap … 1-20`), so the `P2_before-effect` **request is present and its response is cut off**, and all later cases are absent. In the same section:
- Record which capture each negative mutant was built from, with its SHA-256, **or** rebuild all six from the committed `capture.pcap` and update the digests and packet counts (§6).

**A9. `SCENARIOS_AND_AUTHORS.md` §3, AI2II L4 provenance.**
- "Independent Verifier Harness (Cross-Checked against Nemotron & Partner Manifests)" is not a model family. Name the model that wrote `observes_chain.py` and `observes_p1_p8.py`. If that model is Anthropic Claude, L4 separation is **not met** for the `chain` cell until a checker written by another model family passes the live capture and rejects at least 3 mutants. This review cannot fill that gap (same family).
- Reconcile the `inbound` row's `nvidia/llama-3.1-nemotron-ultra-253b-v1` with `nvidia/nemotron-3-ultra-550b-a55b:free`, which `validation/nemotron-review.md` names as the reviewer. If one model reviewed and the other wrote the checker, say so.

### 8.2 Recommended checker hardening

**B1. Check reasons.** `observes_chain.py` reads `expected_reason` but never compares it. Compare `resp.reason` on every non-2xx response and require `proof-invalid` at f606. For f620, accept RFC 9457 and check `WWW-Authenticate` contains `WPT`, as `chain_cases.json` `D2.www_authenticate` declares.

**B2. Strengthen the `B_CHAIN` checks.**
- Add `5050` to `required_b_ports`. Since `8f8441e` the Maurice hop is live, and nothing currently requires it.
- Take the `txn` values from the **request** Txn-Token claims (and token bodies), not only from response `txn`.
- Assert `req_wl == WIT.sub` at f254, f319 and f340.
- Assert scope only narrows from `T_B1` to `T_B2`.
- Assert WPT `tth == sha256(Txn-Token)` and `wth == sha256(WIT)` at f340.

**B3. Strengthen the leak check.** It currently keys only on `aud == "maurice.ietf127.example"`, so a Domain A token with a changed `aud` gets through; `C6` f379 (`kid=tts_a-1`, `aud=foreign…`) is an example.
- Key on `iss`/`kid` from Domain A (`http://maurice.ietf127.example:5051`, `tts_a-1`).
- Scan request bodies (`subject_token`, `txn_token`, `parent_txn_token`) as well as headers.
- Explicitly allow the tagged attack case `C6`, and require that it was rejected with `403`.

**B4. Check order in C10.** Assert accept (`200`) → `/admin/revoke` → `403 revoked`. Today the check is set membership only.

**B5. Collect all P1–P8 errors.** `observes_p1_p8.py` stops at the first missing response. Collect all errors as `observes_chain.py` does. Also compare live `session_id`s with the sandbox manifest.

**B6. Reject credential echoes.** In `C7`/`C8`, fail if any response body contains a compact JWS. This turns `leaked_credentials=false` into a checked property.

**B7. Make mutants reproducible.** In `make_chain_negatives.py`, stamp the injected frame with the last record's timestamp + 1 µs instead of `time.time()`. Also check that the source capture matches the SHA-256 recorded in `EVIDENCE.md` before building.

**B8. Close two gaps in the verification scripts.** `verify_crypto.py` should recompute `Content-Digest` against the body (`digest_ok` is currently 0). `verify_evidence.py` should also check the HTTP Messages column (it missed 104 vs 106).

### 8.3 Recommended peer hardening

**C1. Authenticate token-service requests.** TTS-A, TTS-B and AS-B mint tokens for requests that carry no WIT or proof (f240, f282, f304, f325, f403, f459, f732–f788). In f325 the caller simply names `req_wl` in the body. TTS and AS endpoints should require WIT + WPT or WIT + HTTP-Sig and bind `req_wl` to the authenticated caller.

**C2. Gate the `test_mode` switch.** It is accepted from request bodies (`widen_scope`, `change_txn` at TTS-A; `wrong_aud` at AS-A). Turn it off by default behind a startup flag, and record in the bundle that the flag was on during the run.

**C3. Give each workload its own key.** The Coordinator and Research WITs share one `cnf.jwk` (`x=L-66qq…`). Issue a distinct key per workload in `peers/domain_b.py`.

**C4. Check audience at TTS-B.** TTS-B accepted `AT_B` with `aud=[:5060, :5062]` at f304, which does not include `:5061`. Require that TTS-B appears in the audience, or that the token is a subject token exchanged by an authenticated actor.

**C5. Isolate the tests.**
- Build `D3_dup` with a **valid** RFC 9421 signature over the combined field value, so the `403` is due to the duplicate-header rule and not the bad signature.
- Make `D5` present a real `T_A`.
- Make `D6` present the widened and mutated tokens to a verifier and capture the `403`s.

**C6. Make the token exchanges conformant.** Send form-encoded RFC 8693 (`grant_type`, `subject_token_type=urn:ietf:params:oauth:token-type:txn_token`) and RFC 7523 (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`) requests. Also use a registered or documented `typ` in place of `jwt-chg+jwt`.

**C7. Use RFC 9457 consistently.** Return problem details from Domain B and from Maurice with WIMSE problem `type` URIs instead of `about:blank`.

---

## 9. Sign-off

```text
Reviewed-by:   claude -p --model opus (claude-opus-5-5-high)
Date:          2026-11-15
HEAD:          cd9cd3d
Capture:       validation/bundle-chain/chain/capture.pcap
               sha256 fdad7743ec8a69288cef24bfccab1a2740a2f10e8b7063d2426fdbe067f2ca88
Bundle:        validation/bundle-chain/chain/verdict.json
               sha256 937ea8a9728c6d35d79535eeab4603b97a269900a312dc75601e9b472f364d44
Result:        PASS: 19/19 Suite 2, 10/10 Suite 3, 6/6 mutants rejected,
               84/84 JWS, 18+2/20 RFC 9421, 5+2/7 WPT binding, 32/32 digests
Conditions:    A1–A9 applied before final commit
L4 status:     NOT established by this review (same model family as peers; see A9)
```

This sign-off is a written attestation, not a cryptographic signature. The review is advisory. Every finding above was checked against the dissected frames, not inferred from the documentation.
