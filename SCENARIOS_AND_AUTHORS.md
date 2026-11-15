# Scenarios, Contributors, Implementations, and Normative Specifications

This document provides the complete contributor attribution, implementation inventory, AI model provenance (AI2II Rule L4), normative Internet-Draft / RFC references, and scenario catalog for the **IETF 127 Hackathon WIMSE + OAuth + Agent Call-Chain Interop Repository**.

For a sanitized technical summary of the multi-party coordination emails and design discussions that shaped scenarios `P1–P8` (without exposing raw private correspondence), see [`scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md`](scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md).

---

## 1. Contributors & Implementations

| Contributor | Affiliation / Project | Implementations & Contributions |
|---|---|---|
| **Alexander Pelov** | IMT Atlantique / AgentMaurice & RICH | Overall WIMSE interop architecture, AI2II evidence harness (`interop.yaml`, `wire/`), Phase A/B/C multi-domain 3-agent call-chain & mid-transaction revocation specifications (`specs/maurice-wimse-spec.md`, `specs/maurice-demo-scenario-spec.md`, `specs/hackathon-test-scenario.md`), RICH Coordinator & Research Sub-Agent runtime (`rich.ietf127.example`, `peers/domain_b.py`), Domain A TTS/AS (`peers/domain_a.py`), AgentMaurice WIMSE integration (`maurice.ietf127.example`), and Wireshark Lua post-dissector (`dissectors/wimse.lua`). |
| **Iman Schrock** | Independent / WIMSE Scenario Design | Before-effect revalidation test design (`P2` `before-effect` gate between delegation/status-cache validation and downstream tool effect), cross-implementation scenario schema (`ietf127-wimse-scenario/1`), and bound/latency taxonomy across `P1–P8`. |
| **Ben Le** | Redthread Security | Author of `draft-le-agent-passport` (*Chain Validation*, *Status and Revocation*, *Exposure After Revocation*), scenarios `P1–P6` (`ietf127-wimse-scenario/1`), Redthread verifier & `ProtectedOperation` executor (`v0.7.584` / `v0.7.586`, commits `a09a616`, `ac4d088`, `39f7531`, `358c1ad`), tool-digest pinning (`P6`), local JSONL traces (`redthread-P1..P6-local.jsonl`), and the MintID outside-verifier hook (`scenarios/p1_p8/mintid_outside.py`, `scenarios/p1_p8/protected_op.py`). |
| **Marc Miro i Rierola** | MintID | MintID zero-knowledge non-revocation verifier (`mintid-testnet-3`, `public-v2026-11-11.1`, `proof-core 0.6.0`, `SPEC-1 v3.7`), 10 s presentation proof lifetime, 185 s issuer / 245 s holder / 395 s cascade revocation bounds, live testnet revocation traces (`scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.jsonl` & `.md`), dual time-origin measurement (`t0` on-chain anchor vs `trigger_request_unix`), and the sibling witness-refresh control proving revocation attribution. |
| **Arun Thallapelly** | OmniArx | Author of `draft-thallapelly-oasnt-02` & `draft-thallapelly-oasnt-enforce-01`, scenario `P7` (*"Approval display differs from the executed action"*, `scenarios/p1_p8/P7-approval-display-differs-from-the-executed-action.json`), deterministic Ed25519 approval vectors `V1`/`V4`/`V5`/`R2` at fixed verification clock `1800000000` (`display-match` vs `display-mismatch`). |
| **Kieran Sweeney** | Cred | Author of `draft-sweeney-wimse-credential-delegation`, scenario `P8` (*"Final hop to a bearer-only third-party API"*, `scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json`), separating `revoked-between-authz-and-use` (`token_released: false`, pre-release recheck denies) from `revoked-after-token-released` (`token_released: true`, post-release bearer revocation is unobserved by bearer-only APIs). |

---

## 2. Normative Internet-Drafts & RFCs

| Specification | Title / Scope in This Interop |
|---|---|
| `draft-ietf-wimse-arch-08` | Workload Identity in Multi-System Environments (WIMSE) Architecture — trust domains (`wimse://maurice.ietf127.example`, `wimse://rich.ietf127.example`, `wimse://peer.ietf127.example`) and cross-domain workload authentication. |
| `draft-ietf-wimse-aims-01` | Agent Identity Management System (AIMS) — agent identity, lifecycle, and delegation semantics. |
| `draft-ietf-wimse-workload-creds-03` | WIMSE Workload Credentials — `Workload-Identity-Token` (WIT, JOSE `typ: "wit+jwt"`) structure, `sub`, `iss`, `exp`, and `cnf.jwk` proof-of-possession binding. |
| `draft-ietf-wimse-wpt-02` | WIMSE Workload Proof Token — `Workload-Proof-Token` (WPT, JOSE `typ: "wpt+jwt"`) over HTTP delivery (`wth` WIT hash, `aud`, `jti`, `exp`, `tth` transaction token hash). |
| `draft-ietf-wimse-http-signature-08` | WIMSE Workload-to-Workload Authentication via HTTP Message Signatures — RFC 9421 profile binding `@method`, `@path`, `@query`, `content-type`, `content-digest`, `txn-token`/`authorization`, and `workload-identity-token` with signature parameter `wimse-aud`. |
| `draft-ietf-wimse-identifier-04` | WIMSE Workload Identifier Format — `wimse://<trust-domain>/<path>` URI validation (scheme, authority, path normalization, query/fragment rejection). |
| `draft-ietf-oauth-transaction-tokens-11` | OAuth 2.0 Transaction Tokens (JOSE `typ: "txntoken+jwt"`) — `Txn-Token` header, `txn`, `sub`, `scope`, `tctx`, `req_wl` workload binding, and monotonically narrowing replacement tokens (`files:read files:list` $\rightarrow$ `files:read`). |
| `draft-ietf-oauth-identity-chaining-17` | OAuth Identity and Authorization Chaining Across Domains — cross-domain token exchange at AS-A (`subject_token` $\rightarrow$ `typ: "jwt-chg+jwt"` assertion) paired with JWT assertion grant at AS-B (`assertion` $\rightarrow$ `typ: "at+jwt"`); Domain A's internal `Txn-Token` never crosses the trust boundary. |
| `draft-le-agent-passport` | Agent Passport (`Chain Validation`, `Status and Revocation`, `Exposure After Revocation`) — delegation depth, scope attenuation, status-list grace vs fail-closed behavior (`P1`), before-effect revalidation (`P2`), tool-digest pinning (`P6`). |
| `draft-thallapelly-oasnt-02` & `draft-thallapelly-oasnt-enforce-01` | OAuth Agent Signed Notification / Approval Tokens (OASNT) — cryptographic binding between human approval display text and the executed action (`P7`). |
| `draft-sweeney-wimse-credential-delegation` | Credential Delegation to Bearer-Only Third-Party APIs — pre-release revocation gate (`token_released: false`) vs post-release bearer exposure boundary (`token_released: true`) (`P8`). |
| `RFC 9421` & `RFC 9530` | HTTP Message Signatures & Digest Fields (`Content-Digest: sha-256=:...:`). |
| `RFC 9457` | Problem Details for HTTP APIs (`application/problem+json`, `urn:ietf:params:wimse:problem:*` in Suite 1, `about:blank` / JSON error reasons in Suite 2). |
| `RFC 8693` & `RFC 7523` | OAuth 2.0 Token Exchange & JWT Profile for OAuth 2.0 Authorization Grants (modeled via JSON token endpoints on `:5051/oauth/token` and `:5061/oauth/token`). |

---

## 3. AI Model Provenance & Independent Checker Separation (AI2II Rule L4)

Under the **AI2II** (AI-Assisted Interop & Implementation) evidence rules, the packet checker that validates a `.pcap` capture must be authored by an AI model family distinct from the peer implementations under test, and must pass on the live capture while rejecting at least three negative mutant captures. Independent protocol and wire-evidence reviews are recorded in [`validation/nemotron-review.md`](validation/nemotron-review.md) (`inbound` cell), [`validation/nemotron-p1-p8-review.md`](validation/nemotron-p1-p8-review.md) (**NVIDIA Nemotron 3 Ultra** `nvidia/nemotron-3-ultra-550b-a55b:free` review of `observes_p1_p8.py`, `observes_chain.py`, and Redthread `P1–P6` traces), [`validation/gemini-p1-p8-review.md`](validation/gemini-p1-p8-review.md) (**Google Gemini 4** cross-family L4 review), and [`validation/opus-chain-review.md`](validation/opus-chain-review.md) (`chain` cell).

| Cell | Peer Implementations Under Test | Implementation Author / Model Family | Independent Packet Checker(s) | Checker / Reviewer Model Family & Audit Report | Negative Mutants Rejected |
|---|---|---|---|---|---|
| `inbound` | `bin/maurice` (v2.2.18, Go/Rust binary) + `peers/driver.py`, `peers/wimse.py` | **Anthropic Claude Opus 4.6** + human authors (Alexander Pelov) | `checkers/observes_wimse.py` | **NVIDIA Nemotron Ultra (`nvidia/llama-3.1-nemotron-ultra-253b-v1` / `nvidia/nemotron-3-ultra-550b-a55b:free`)** — see [`validation/nemotron-review.md`](validation/nemotron-review.md) | `unrelated.pcap`, `request_only.pcap`, `forbidden_fetch.pcap` |
| `chain` | `bin/maurice` (`:5050`), `peers/domain_a.py` (`:5051`), `peers/domain_b.py` (`:5060–5063`), `peers/p2_p7_p8_executor.py` (`:5064`), `peers/chain_driver.py` | **Google Gemini 4 Argon** + **Anthropic Claude Opus 4.6** + Partner Implementations (Ben Le / Redthread, Marc Miro / MintID, Arun Thallapelly / OmniArx, Kieran Sweeney / Cred) | `checkers/observes_chain.py`, `checkers/observes_p1_p8.py` | Cross-family audited by **NVIDIA Nemotron 3 Ultra (`nvidia/nemotron-3-ultra-550b-a55b:free`)** ([`validation/nemotron-p1-p8-review.md`](validation/nemotron-p1-p8-review.md)), **Google Gemini 4 (`gemini-4-argon`)** ([`validation/gemini-p1-p8-review.md`](validation/gemini-p1-p8-review.md)), and **Anthropic Claude Opus 5.5 / Sonnet 5.5** ([`validation/opus-chain-review.md`](validation/opus-chain-review.md)) | `chain_unrelated.pcap`, `chain_request_only.pcap`, `chain_leaked_txn.pcap`, `p1_p8_unrelated.pcap`, `p1_p8_request_only.pcap`, `p1_p8_missing_before_effect.pcap` |

---

## 4. Complete Scenario Catalog

### Suite 1 — Phase A & C WIMSE Inbound Matrix (`cases.json`, 34 Cases against Maurice `:5050`)

Tested in cell `inbound` (`validation/bundle-inbound/inbound/capture.pcap`):

| Case ID(s) | Category | Expected HTTP Status & Problem Type / Outcome |
|---|---|---|
| `A2`, `A3` | Unauthenticated Discovery | `401 Unauthorized` with `WWW-Authenticate: Workload-Identity-Token ...` challenge + `200 OK` on `GET /.well-known/wimse-Server-metadata`. |
| `A4`, `A5` | Valid WIMSE Profiles | `200 OK` for Profile 1 (`WIT + WPT`, `A4`) and Profile 2 (`WIT + RFC 9421 HTTP Message Signatures`, `A5`). |
| `A6`, `A6a`, `A6b` | Dual-Profile & Mixed-Credential Rejections | `200 OK` when both WPT and RFC 9421 are valid (`A6`); `401 invalid-wpt` (`A6a`) or `401 invalid-http-signature` (`A6b`) when either proof is corrupted (never silently downgraded). |
| `A7`–`A12` | Proof & Binding Rejections | `401 missing-proof` (`A7`), `401 invalid-wit` (`A8`), `401 invalid-wpt` (`A9` wrong `wth`, `A10` wrong `aud`, `A12` replayed `jti`), `401 invalid-http-signature` (`A11` tampered body vs `Content-Digest`). |
| `A13`–`A13j` | Trust Domain, Identifier & Policy Rejections | `401 untrusted-trust-domain` (`A13`), `401 invalid-wit` (`A13a`–`A13i`: non-`wimse://` scheme, empty trust domain, query/fragment in `sub`, `iss`/`sub` mismatch, missing `cnf.jwk`, symmetric `HS256` alg, wrong `typ`, missing `exp`), `403 insufficient-policy` (`A13j`). |
| `C2`, `C3`, `C4` | WIT Revocation Lifecycle | `200 OK` before revocation (`C2`), `200 OK` on `POST /v1/wimse/revocations` (`C3`), `401 wit-revoked` immediately after revocation (`C4`). |
| `C11`, `C12`, `C12b` | Key Compromise (`kid`) & SSRF Protection | `401 key-compromised` (`C11`), `401 untrusted-trust-domain` with **zero outbound fetches** to attacker `jku`/`x5u` URLs on port `47999` (`C12`, `C12b`). |
| `IN4`–`IN15` | Clock Skew & Input Hardening | `200 OK` within $\pm 30\text{ s}$ clock skew (`IN4`, `IN5`), `401` beyond skew (`IN6`, `IN7`), `401` on duplicate headers (`IN8`, `IN9`), oversized WIT (`IN11`), malformed `Signature-Input` (`IN12`), missing covered components (`IN13`), and WPT `alg: "none"` (`IN15`). |

---

### Suite 2 — Phase B & C 3-Agent Cross-Domain Call Chain & Attack Matrix (`chain_cases.json`, 19 Cases across `:5050–5063`)

Tested in cell `chain` (`validation/bundle-chain/chain/capture.pcap`) and audited frame-by-frame in [`validation/opus-chain-review.md`](validation/opus-chain-review.md):

```text
Driver / Client Workload (wimse://peer.ietf127.example/client)
  ├─ 1. POST :5051/tts/token        -> mints Domain A Txn-Token T_A (scope="files:read files:list", tctx={file:Q3.pdf})
  ├─ 2. POST :5050/api/v2/...       -> Agent 1: Maurice workflow execution with WIT + RFC 9421 + T_A (200 OK)
  ├─ 3. POST :5051/oauth/token      -> AS-A exchanges T_A for cross-domain assertion (typ=jwt-chg+jwt; T_A stays in Domain A!)
  ├─ 4. POST :5061/oauth/token      -> AS-B exchanges assertion for Domain B Access Token AT_B (typ=at+jwt)
  └─ 5. POST :5060/coordinate       -> Agent 2: RICH Coordinator (wimse://rich.ietf127.example/agent/coordinator)
        ├─ 6. POST :5061/tts/token  -> TTS-B mints initial Domain B Txn-Token T_B1 (scope="files:read files:list", req_wl=coordinator)
        └─ 7. POST :5062/research   -> Agent 3: RICH Research Sub-Agent (wimse://rich.ietf127.example/agent/research)
              ├─ 8. POST :5061/tts/token -> TTS-B mints narrowed replacement Txn-Token T_B2 (scope="files:read", req_wl=research)
              └─ 9. POST :5063/files/read -> File Tool verifies WIT + WPT (wth + tth) + T_B2 -> 200 OK (unified txn UUID end-to-end)
```

| Case ID | Ref | Expected HTTP Status(es) | Expected Reason | Description & Verified Wire Outcome |
|---|---|---|---|---|
| `B_CHAIN` | `Phase-B` | `200` (×9 hops) | `accept` | Full 9-hop, 3-agent, 2-domain call chain (`TTS-A -> Maurice -> AS-A -> AS-B -> Agent 2:Coordinator -> TTS-B -> Agent 3:Research -> TTS-B -> File Tool`), verifying unified `txn` UUID across all hops, `req_wl` binding, scope narrowing (`files:read files:list` $\rightarrow$ `files:read`), WPT `wth`/`tth` SHA-256 binding at `:5063`, and **zero leakage** of Domain A `Txn-Token` onto Domain B ports (`5060–5063`). |
| `C5` | `ATK-5` | `400` | `proof-invalid` | `Txn-Token` swapped to `sub=user:bob` after signing the RFC 9421 HTTP Message Signature; rejected by `:5063`. |
| `C6` | `ATK-6` | `403` | `txn-token-invalid` | Foreign `Txn-Token` (signed by `tts_a-1` with non-Domain-B audience) presented to Domain B File Tool (`:5063`) is rejected. |
| `C7` | `ATK-7` | `200`, `403` | `not-authorized` | Prompt injection in `Q3.pdf` instructs Agent 3 to read out-of-scope `salaries.xlsx`; File Tool (`:5063`) blocks the out-of-scope file read with `403 not-authorized` (`injection_read_status=403`). |
| `C8` | `ATK-8` | `200` (and `403` on injected hop) | `accept` | Prompt injection attempting credential exfiltration from `caller_context`; response confirms `leaked_credentials: false` with zero compact JWS tokens echoed in any response body. |
| `C9` | `ATK-9a` | `403` | `not-authorized` | Autonomous workload call (no `Txn-Token`) to delegated-only route `POST :5063/files/read` is rejected. |
| `C9b` | `ATK-9b` | `403` | `not-authorized` | Delegated call (carrying a `Txn-Token`) to autonomous-only route `POST :5063/files/index` is rejected. |
| `C10` | `ATK-10` | `200`, `403` | `revoked` | Mid-transaction workload revocation via `POST :5063/admin/revoke`: request succeeds (`200`) before revocation, fails with `403 revoked` immediately after revocation, and cleanup restores state. |
| `D1` | `TXN-1` | `400` | `proof-invalid` | `Txn-Token` header present on an RFC 9421 request to `:5063` but omitted from `@signature-params` covered components. |
| `D2` | `TXN-2` | `401` | `proof-invalid` | `Txn-Token` header present on a WPT request with wrong `tth` hash (`tth="wrong_hash"`), rejected with `401` and `WWW-Authenticate: WPT` on `:5063` and `:5050`. |
| `D3_exp` | `TXN-3a` | `403` | `txn-token-invalid` | Expired `Txn-Token` (`exp < iat`) rejected by File Tool (`:5063`). |
| `D3_sig` | `TXN-3b` | `403` | `txn-token-invalid` | `Txn-Token` signed with untrusted rogue key (`kid=rogue-1`) rejected by File Tool (`:5063`). |
| `D3_typ` | `TXN-3c` | `403` | `txn-token-invalid` | `Txn-Token` with wrong JOSE header `typ="jwt"` (instead of `txntoken+jwt`) rejected by File Tool (`:5063`). |
| `D3_reqwl` | `TXN-3d` | `403` | `txn-token-invalid` | `Txn-Token` missing required `req_wl` claim rejected by File Tool (`:5063`). |
| `D3_dup` | `TXN-3e` | `403` | `txn-token-invalid` | Request carrying duplicate `Txn-Token` headers rejected by File Tool (`:5063`). |
| `D4` | `TXN-4` | `403` | `not-authorized` | `Txn-Token` with insufficient `scope="profile:view"` rejected on `files:read` route (`:5063`). |
| `D5` | `CHAIN-1` | `403` | `grant-invalid` | Cross-domain guard blocks raw Domain A `Txn-Token` from leaving Domain A (`chain-journal.jsonl` line 34), and AS-B (`:5061`) rejects a non-`jwt-chg+jwt` assertion (`at+jwt`) with `403 grant-invalid` (line 35). |
| `D6` | `TXO-4/5` | `200` | `accept` | Replacement `Txn-Token` scope narrowing (`files:read`) accepted on `:5051` (`chain-journal.jsonl` line 36); widened scope (`files:read files:write`) and mutated `txn` tokens issued under `test_mode` are rejected by the driver's monotonic scope/txn invariant check. |
| `D7` | `CHAIN-2` | `200`, `403` | `grant-invalid` | Cross-domain JWT assertion minted with wrong audience (`aud="http://wrong.example/oauth/token"`) is rejected by AS-B (`:5061`) with `403 grant-invalid`. |

---

### Suite 3 — Extended Multi-Partner Scenarios `P1–P8` (`ietf127-wimse-scenario/1`)

Executed on `:5064` (`peers/p2_p7_p8_executor.py`) and verified against partner traces by `checkers/observes_p1_p8.py` (cross-family audited in [`validation/gemini-p1-p8-review.md`](validation/gemini-p1-p8-review.md)):

| Scenario | Title & Lead Author(s) | Evidence Artifacts & Verified Outcomes |
|---|---|---|
| `P1` | **Status unavailable** (Ben Le / Redthread `v0.7.584`, simulated clock) | `scenarios/p1_p8/redthread-P1-local.jsonl` (5 cases, 9 lines, **simulated clock**): `confirmed-revocation` (`status-revoked`), `expired-cache` (`status-stale`), `service-unavailable` (`status-unavailable`), `low-value-grace` (`status-grace` then `status-stale`), and `one-element-in-chain` (`status-unavailable`). |
| `P2` | **Revocation after delegation, before effect** (Iman Schrock, Ben Le / Redthread `v0.7.584` & `v0.7.586`, Marc Miro / MintID `public-v2026-11-11.1`) | **1. Redthread (`v0.7.584`, simulated clock):** `redthread-P2-local.jsonl` (2 cases, 122 lines) + `:5064/p2/execute` local HTTP cases: `revoke-upstream` (`50 s` simulated last acceptance $\rightarrow$ `51 s` simulated first refusal `status-revoked` against `bound_s=120` simulated) and `before-effect` (`authorize(allow, pending)` $\rightarrow$ `before-effect(deny, status-revoked, effect=none)` at `0 s` simulated after revocation).<br>**2. MintID (`mintid-testnet-3`, live network):** `revocation-trace-testnet-20261114T104257Z.jsonl` (92 lines): 10 s presentation proof lifetime, 13.9 s dual-origin offset (`trigger_request_unix` vs `t0` on-chain root). **The MintID verifier returns `status_root_stale` for both `status-revoked` and `status-stale` (not a confirmed revocation by itself); revocation is attributed by the holder witness refresh (`credential_revoked`) paired with `sibling_control` (`accepted`)**.<br>**3. Combined Redthread + MintID sandbox (`v0.7.586`):** `redthread-P2-mintid-sandbox-negative.jsonl` — the two negative controls (`outside-made-up-proof` $\rightarrow$ `403 proof_invalid` and `outside-no-agent-answer` $\rightarrow$ `403 no-agent-answer`) were run live against `verifier.testnet.mintid.net` once on **15 November 2026 at `01:23 UTC`** (sessions `01eac0157bbfc1f54af295fadb53dafc` and `ea27daa1d8be8f59a1c5e43963facc2d`); `:5064/p2/execute` replays those **recorded** outcomes. Positive and revoked-agent sandbox cases have not been run yet (pending a MintID agent credential). |
| `P3` | **Delegation that widens** (Ben Le / Redthread `v0.7.584`, simulated clock) | `scenarios/p1_p8/redthread-P3-local.jsonl` (6 cases, **simulated clock**): `wider-host` (`attenuation:host`), `more-methods` (`attenuation:methods`), `longer-lifetime` (`attenuation:exp`), `dropped-tools` (`attenuation:tools`), `absent-means-default` (`allow: ok` for an absent member compared as its default), and `unknown-member` (`attenuation:unknown-member`). |
| `P4` | **Cumulative limit across two services** (Ben Le / Redthread `v0.7.584`, simulated clock) | `scenarios/p1_p8/redthread-P4-local.jsonl` (3 cases, 8 lines, **simulated clock**): `per-rp-counting` (`limit-aud-not-single`), `single-accounting-rp` (5 calls `allow: ok` then 6th call `deny: limit-exceeded`), and `child-limit-wider` (`attenuation:max_calls`). |
| `P5` | **Request rewritten in transit** (Ben Le / Redthread `v0.7.584`, simulated clock) | `scenarios/p1_p8/redthread-P5-local.jsonl` (4 cases, **simulated clock**): `rewrite-authority` (`signature-invalid`), `rewrite-path` (`signature-invalid`), `authenticated-proxy-verifies` (`allow: ok` for an authenticated proxy), and `forwarded-headers-unauthenticated` (`forwarded-target-uri-unauthenticated`). |
| `P6` | **Tool or build change between hops** (Ben Le / Redthread `v0.7.584`, simulated clock) | `scenarios/p1_p8/redthread-P6-local.jsonl` (2 cases, **simulated clock**): `build-changed` (`build-mismatch`, verifier code `dlg-build-mismatch`) and `tool-swapped` (`tool-digest-mismatch`). |
| `P7` | **Approval display differs from the executed action** (Arun Thallapelly / OmniArx) | **1. OmniArx OASNT Verifier (reported external run in `P7-approval-display-differs-from-the-executed-action.json`):** At fixed verification clock `1800000000` with enrolled key `A.1`, action `A.2` (`V1`), request `A.5` (`V4`), and fresh replay state, OmniArx verified `V5` (`display-match` $\rightarrow$ `allow: ok`) and `R2` (`display-mismatch` $\rightarrow$ `deny: display-mismatch`).<br>**2. Local `:5064/p7/execute` Simulation:** Replays the two `display-match` (`200 ok`) and `display-mismatch` (`403 display-mismatch`) decision outcomes over loopback HTTP using representative digest constants. |
| `P8` | **Final hop to a bearer-only third-party API** (Kieran Sweeney / Cred) | Live HTTP execution on `:5064/p8/execute` + `scenarios/p1_p8/P8-final-hop-to-a-bearer-only-third-party-api.json`: verifies `P8_no-delegation` (`403 no-delegation`, `token_released: false`), `P8_write-under-read` (`403 scope-exceeded`, `token_released: false`), `P8_revoked-between-authz-and-use` (`403 status-revoked`, `token_released: false`), and `P8_revoked-after-token-released` (`200 token-released`, `token_released: true`, proving why revocation enforcement must happen before releasing a bearer token to an external API). |
