# IETF 127 Hackathon — WIMSE Partner Scenarios (`P1–P8`) Coordination Summary

This document summarizes the technical coordination, scenario definitions (`format: "ietf127-wimse-scenario/1"`), reproduction commands, and empirical/simulated traces exchanged by the IETF 127 WIMSE Hackathon participants on 13–14 November 2026. Raw private emails are omitted; all original partner files, manifests, and traces are preserved in `scenarios/p1_p8/` and `scenarios/p1_p8/originals/`.

---

## 1. Participants & Roles

| Participant | Organization / Project | Contributions |
|---|---|---|
| **Iman Schrock** | EMILIA Protocol (interop reviewer; `P2` before-effect test design, no EMILIA runtime integration) | Scenario synthesis (`P1–P8`), cross-vendor bound & manifest verification, time-origin alignment |
| **Ben Le** | Redthread Security (`v0.7.584` / `v0.7.586`) | `P1–P6` verifier & `ProtectedOperation` executor (`protected_op.py`), `run_local.py`, `P2`/`P7`/`P8` JSON revisions, live MintID sandbox outside-verifier runner (`run_mintid_sandbox.py`) |
| **Marc Miro i Rierola** | MintID (`public-v2026-11-13.1` / `public-v2026-11-11.1`) | `P2` live testnet revocation traces (`issuer`, `kill_switch`, `cascade`) on `mintid-testnet-3`, witness-refresh attribution control, SPEC-1 R18 verifier notes |
| **Arun Thallapelly** | OmniArx | `P7` test vectors (`V1`, `V4`, `V5`, `R2`) at fixed clock `1800000000` (`A.1` key, `A.2` action, `A.5` request, fresh replay state) |
| **Kieran Sweeney** | Cred | `P8` intermediary bearer-token vaulting vs. post-release provider enforcement (`token_released`) |
| **Alexander Pelov** | IMT Atlantique / AgentMaurice (`v2.2.18`) | WIMSE inbound & two-domain agent call-chain (`A1–D7`), AI2II wire verification harness (`interop.yaml`), unified `P1–P8` evidence bundle |

---

## 2. Scenario Matrix (`P1–P8`)

| ID | Title | Primary Focus & Reason Codes | Implementations & Artifacts |
|---|---|---|---|
| **P1** | **Status unavailable** | Status source transitions (`status-revoked`, `status-stale`, `status-unavailable`, `status-grace`) on a **simulated clock** | Redthread Security `v0.7.584` (`redthread-P1-local.jsonl`, 5 cases, 9 lines, simulated clock) |
| **P2** | **Revocation after delegation, before effect** | Upstream or leaf revocation between delegation and protected side effect (`status-revoked`); Redthread `50 s` (simulated clock) last acceptance $\rightarrow$ `51 s` (simulated clock) first refusal against `120 s` (simulated clock) bound, and `0 s` (simulated clock) before-effect refusal; MintID verifier `status_root_stale` + witness-refresh (`credential_revoked` vs `sibling_control`) attribution | Redthread Security `v0.7.584` (`redthread-P2-local.jsonl`, 2 cases, 122 lines, simulated clock) + MintID `public-v2026-11-11.1` (`revocation-trace-testnet-20261114T104257Z.jsonl`, 92 lines live testnet) + Redthread `v0.7.586` recorded live sandbox negative controls (`redthread-P2-mintid-sandbox-negative.jsonl`, 2 cases run live on **15 Nov 2026 at `01:23 UTC`**) |
| **P3** | **Delegation that widens** | Child grant widening rejection (`attenuation:host`, `attenuation:methods`, `attenuation:exp`, `attenuation:tools`, `attenuation:unknown-member`) and `allow: ok` for an absent member compared as its default | Redthread Security `v0.7.584` (`redthread-P3-local.jsonl`, 6 cases, simulated clock) |
| **P4** | **Cumulative limit across two services** | Multi-RP call-count limit enforcement (`limit-aud-not-single`, `limit-exceeded`, `attenuation:max_calls`) | Redthread Security `v0.7.584` (`redthread-P4-local.jsonl`, 3 cases, 8 lines, simulated clock) |
| **P5** | **Request rewritten in transit** | Transit request target/header tampering (`signature-invalid`, `forwarded-target-uri-unauthenticated`) and `allow: ok` for an authenticated proxy | Redthread Security `v0.7.584` (`redthread-P5-local.jsonl`, 4 cases, simulated clock) |
| **P6** | **Tool or build change between hops** | Pinned build/tool digest verification at invocation time (`build-mismatch`, `tool-digest-mismatch`) | Redthread Security `v0.7.584` (`redthread-P6-local.jsonl`, 2 cases, simulated clock; `tool-digest-mismatch` added in commit `39f7531`) |
| **P7** | **Approval display differs from the executed action** | Cryptographic binding between human approval UI display text and executed action at fixed clock `1800000000` (`A.1` key, `A.2`/`V1` action, `A.5`/`V4` request, fresh replay state: `V5` `allow: ok`, `R2` `deny: display-mismatch`) | OmniArx verifier external run + Redthread scenario spec (`P7-approval-display-differs-from-the-executed-action.json`) + local `:5064/p7/execute` simulation |
| **P8** | **Final hop to a bearer-only third-party API** | Upstream chain verification before bearer release (`no-delegation`, `scope-exceeded`, `status-revoked` with `token_released: false` vs `token-released` with `token_released: true`) | Cred + Redthread Security (`P8-final-hop-to-a-bearer-only-third-party-api.json`) + `:5064/p8/execute` |

---

## 3. Redthread Security Local Runs (`P1–P6`) & Revisions (`P2`, `P7`, `P8`)

### Repository & Commits
- **Version:** `0.7.584`
- **Commits:**
  - `a09a616`: Chain validation
  - `ac4d088`: Executor (`ProtectedOperation`)
  - `39f7531`: Tool-definition digest check (`tool-digest-mismatch` for `P6/tool-swapped`) and local runner
  - `358c1ad`: Revised `P2`, `P7`, and `P8` scenario files
- **Reproduction Command (from Redthread checkout `358c1ad` or standalone in `scenarios/p1_p8/`):**
  ```bash
  python3 docs/hackathon/ietf127/run_local.py
  ```

### Technical Notes from Coordination
1. **P2 120-Second High-Value Bound Formula (Simulated Clock):**
   - At high value, the upper bound from revocation recorded at the issuer to refusal at `E` is **`120 s` (simulated clock)**, computed as **`status-list TTL (60 s) + clock-skew allowance (60 s)`**.
   - Earlier drafts described the bound as `TTL + grace`; grace applies only to low-value operations and is `0 s` at high value. `P2-revocation-after-delegation-before-effect.json` (v2) explicitly states this.
   - Every Redthread time in `P1` to `P6` is **simulated seconds on a fake clock** (`clock: "simulated"`). In `redthread-P2-local.jsonl`, `revoke-upstream` shows last acceptance at **`50 s` (simulated clock)** and first refusal at **`51 s` (simulated clock)** against the **`120 s` (simulated clock)** bound (`reason: "status-revoked"`), while `before-effect` refetches every status list immediately before executing the protected operation and refuses at **`0 s` (simulated clock)** after revocation is recorded (`effect: "none"`, `operation_ran: false`).
2. **P6 Tool-Definition Pinning:**
   - While running `P1–P6` (22 cases total across the 6 scenarios), Redthread identified that its verifier did not previously check the pinned tool definition digest, leaving `P6/tool-swapped` uncovered. Commit `39f7531` added `tool_digest` verification so `P6/tool-swapped` now refuses with `reason: "tool-digest-mismatch"`. All **22/22** cases in `redthread-local.manifest.json` match expected decisions and reasons.
3. **P7 (OmniArx Alignment):**
   - Incorporates Arun Thallapelly's fixed clock (`1800000000`), `A.1` key, `A.2` action, `A.5` request, fresh replay state, and a verifier that holds the action.
   - Uses `V5` as the positive control (`expected: "allow"`), `V4` for approval-display/executed-action mismatch, `V1` for wrong key, and `R2` for replay under fresh replay state, with vendor name standardized to **OmniArx**.
4. **P8 (Cred Alignment):**
   - Distinguishes a bearer token still held in the intermediary vault (`revoke-before-release`, `token_released: false`, `effect: "none"`) from a token already released to the caller or downstream hop (`revoke-after-release`, `token_released: true`). Once released, preventing effect requires an enforcement mechanism at the third-party provider or an intermediary proxy that still mediates egress.

---

## 4. MintID Testnet Revocation Trace (`P2` Live Network Measurements)

### Repository, Service Release & Reproduction
- **Trace Checkout:** Tag `public-v2026-11-13.1`, public commit `dca3d605b46e66598da0c46be8148081414140d0` (source revision `82c455ed79fc2f14d12ef128c0283cf40ff5e7b3`, `tracked_changes: false`).
- **Testnet Services (`mintid-testnet-3`):** Tag `public-v2026-11-11.1` (service revision `89d6af3f4612`).
  - Issuer: `https://issuer.testnet.mintid.net`
  - Verifier: `https://verifier.testnet.mintid.net`
  - Relay: `https://relay.testnet.mintid.net`
  - Node RPC: `https://rpc.testnet.mintid.net:443`
  - Availability window: Saturday 14 November 2026 17:00 UTC to Monday 16 November 2026 00:00 UTC.
- **Reproduction Command (requires Python 3.12+, `uv`, and Rust toolchain):**
  ```bash
  SSL_CERT_FILE="$(uv run --frozen python -m certifi)" uv run --frozen python test-harness/trace/revocation_trace.py --target testnet --paths issuer,kill_switch,cascade
  ```
  *(Note: `--frozen` is required so `uv` does not rewrite `uv.lock` and set `tracked_changes: true` in the generated manifest.)*

### Time Origins & Measurements (`2026-11-14T10:42:57Z` to `10:47:56Z`)

MintID's proof presentation lifetime is **`10 s`** (which bounds replay of a single presentation, not credential revocation). Credential revocation takes effect when the verifier rejects the old status root (`status_root_stale`) and the issuer refuses to refresh the credential's Merkle witness (`credential_revoked`).

Because `P2` defines time zero as the **issuer revocation record/response**, whereas MintID's native cascade clock starts at the **trigger status commitment root**, both time origins are preserved side-by-side:

| Path | Subject | Issuer Revoke Response (`t_revoke`) | Trigger Root (`t_root`) | Delta (`t_root - t_revoke`) | Last Accepted (from `t_root` / from `t_revoke`) | First Refused (from `t_root` / from `t_revoke`) | Native Bound (from `t_root` / from `t_revoke`) |
|---|---|---|---|---|---|---|---|
| **`issuer`** | `target` (direct agent) | `10:42:59.092Z` | — | — | `17.1 s` | **`23.1 s`** | **`185 s`** |
| **`kill_switch`** | `target` (holder-initiated) | `10:43:37.547Z` (holder trigger) | — | — | `11.1 s` | **`17.1 s`** | **`245 s`** |
| **`cascade`** | `principal` (person root) | `10:44:27.096Z` | `10:44:41Z` | `13.9 s` | `9.9 s` / `23.8 s` | **`15.9 s`** / **`29.8 s`** | **`185 s`** / `198.9 s` |
| **`cascade`** | `cascade_agent_1` (delegated agent) | `10:44:27.096Z` | `10:44:41Z` | `13.9 s` | `34.8 s` / `48.7 s` | **`40.8 s`** / **`54.7 s`** | **`395 s`** / **`408.9 s`** |
| **`cascade`** | `cascade_agent_2` (delegated agent) | `10:44:27.096Z` | `10:44:41Z` | `13.9 s` | `185.9 s` / `199.8 s` | **`189.1 s`** / **`203.0 s`** | **`395 s`** / **`408.9 s`** |

### Refusal Attribution & Verifier Decision Logs
- **Shared Refusal Code (`status_root_stale`) + Witness-Refresh Control:**
  - The MintID verifier does not learn which credential was revoked; it only checks whether the presented status root is within its acceptance window. When a status root ages out, the verifier returns `status_root_stale` (covering both `status-revoked` and `status-stale`; `status-unavailable` corresponds to `state_unproven` when the verifier has no finalized root).
  - Attribution to revocation comes from the **witness-refresh control**: the revoked subject (`target`, `principal`, `cascade_agent_1`, `cascade_agent_2`) requests a witness refresh from the issuer and is refused with `409 Conflict` (`credential_revoked`), while `sibling_control` refreshes its witness onto the new root and continues to be `accepted` (`accepted_under_stale_grace: false`).
- **Operator Decision Logs (SPEC-1 R18):**
  - The public testnet operator does not publish raw verifier console decision logs (`MINTID_VERIFIER_CONSOLE_PASSWORD`). Every probe event in `revocation-trace-testnet-20261114T104257Z.jsonl` already records the trigger root, current finalized root, epoch, and `accepted_under_stale_grace` flag. Any participant requiring direct verifier console logs can register a permissionless verifier instance against `https://rpc.testnet.mintid.net:443` using testnet faucet funds.

---

## 5. Combined Redthread + MintID Sandbox Integration (`P2` Outside-Verifier Hook)

### Architecture & Live Negative Control Run (`v0.7.586`)
To connect Redthread's `ProtectedOperation` executor (`E`) with MintID's live testnet verifier (`https://verifier.testnet.mintid.net`) without leaking MintID's internal proof format into Redthread's core verifier, Redthread added an `outside` callback hook (`mintid_outside.py` + `run_mintid_sandbox.py`):

1. `E` runs Redthread's `authorize` check (`decision: "allow"`, `effect: "pending"`).
2. Immediately before executing the side effect (`op`), `E` invokes `outside(base_url, answer_fn, policy)`:
   - Calls `POST /v1/challenges` on `https://verifier.testnet.mintid.net` with the policy (`iot_Command` by default) to obtain a live `session_id` and challenge payload.
   - Passes the challenge to `answer_fn(challenge)`.
   - If `answer_fn` returns `None`, refuses immediately with `reason: "no-agent-answer"` (`effect: "none"`, `operation_ran: false`).
   - Otherwise submits the proof to `POST /v1/presentations` and maps the HTTP response (`accepted: true` $\rightarrow$ `allow`; error code $\rightarrow$ `deny` with MintID's error code such as `proof_invalid` or `status_root_stale`).
3. On `2026-11-15T01:23:35Z–01:23:36Z`, Ben Le executed the two negative controls that do not require a live MintID wallet (`redthread-P2-mintid-sandbox-negative.jsonl`):
   - `outside-made-up-proof` (`txn_id: "mi-1"`): Live challenge session `01eac0157bbfc1f54af295fadb53dafc` $\rightarrow$ `POST /v1/presentations` returned HTTP 400 `proof_invalid` $\rightarrow$ `decision: "deny"`, `effect: "none"`, `operation_ran: false`.
   - `outside-no-agent-answer` (`txn_id: "mi-2"`): Live challenge session `ea27daa1d8be8f59a1c5e43963facc2d` $\rightarrow$ `decision: "deny"`, `reason: "no-agent-answer"`, `effect: "none"`, `operation_ran: false`.

---

## 6. Inventory of Partner Artifacts & SHA-256 Digests

### Active Scenario & Trace Files (`scenarios/p1_p8/`)

| File | Size (Bytes) | SHA-256 | Source |
|---|---:|---|---|
| `P2-revocation-after-delegation-before-effect.json` | 4,772 | `54e5d3a826fd9c4ee2c3bf50db8289be4bd43479a5ca3ef6414f741c249895ca` | Redthread `v0.7.584` (`358c1ad`, v2 with MintID + Redthread `implementations_offered`) |
| `P7-approval-display-differs-from-the-executed-action.json` | 3,046 | `0f8527bd09ba719d0f6a82d2093a67b14eb9f21f9bf92e367a42bc1a444d695b` | Redthread `v0.7.584` + OmniArx (`358c1ad`) |
| `P8-final-hop-to-a-bearer-only-third-party-api.json` | 3,069 | `c2a42eb3eb949b21cd0d6b267b56a0e4b0107a0f4db9f91bc2f20b706d8ab2b2` | Redthread `v0.7.584` + Cred (`358c1ad`) |
| `protected_op.py` | 3,740 | `781f9740900d2dc89d47e947f79a2682550b211a9d16db2d8dc0ec1743931d21` | Redthread `v0.7.584` (`ac4d088`) |
| `run_local.py` | 9,866 | `1a2bdbf71975fb009dfcbeb2a51eb67413edfd0ac166c86a5bc2a96a71dddc3f` | Redthread `v0.7.584` (`39f7531`) |
| `redthread-local.manifest.json` | 5,167 | `b00501fa5a0b384718a627490315238c5e565e1bd249218f8dc7d7f4aa4dd50f` | Redthread `v0.7.584` (`P1–P6` 22/22 manifest) |
| `redthread-P2-local.manifest.json` | 491 | `e21e0a31a8ec262fb0ec97bb5304f1e2e89275cbef9d35b17357b4a07cf6c8a8` | Redthread `v0.7.584` (`P2` manifest) |
| `redthread-P1-local.jsonl` | 3,178 | `da65a31d198a359f9dc1baeb5a039dc96b01518b49ef180e8eb6ddaa84457b79` | Redthread `v0.7.584` |
| `redthread-P2-local.jsonl` | 41,977 | `b31868c824bf891ca977dc6d8da5baad9a690628510f7f29fa23a75772ab12e2` | Redthread `v0.7.584` |
| `redthread-P3-local.jsonl` | 2,109 | `9915d87e2d52c7da3e5b733cfbbab0e834410d7023c67ff013f78b62a9d22473` | Redthread `v0.7.584` |
| `redthread-P4-local.jsonl` | 2,909 | `e2309025f45dc04ac50995bfbbdfee3da5f9fa1f0a69503df9941ba018a57a94` | Redthread `v0.7.584` |
| `redthread-P5-local.jsonl` | 1,500 | `32888f0917e649f778bb47f6e68a2352c4dbcccf1dfbc49b0d1de646d1f6127c` | Redthread `v0.7.584` |
| `redthread-P6-local.jsonl` | 708 | `258ab62052c44f570d88b1a749b2be0d20b34c3cbbfab9cfbc944b53445ab254` | Redthread `v0.7.584` |
| `revocation-trace-testnet-20261114T104257Z.jsonl` | 59,523 | `7090edc46994cbd039d281841043a68a41919188eb952a9b4da117b980182a32` | MintID `public-v2026-11-13.1` (`dca3d605`) |
| `revocation-trace-testnet-20261114T104257Z.manifest.json` | 32,623 | `ca1703c3e7c0c40c71d80d8be046d2c1ba3bd7f06e7d4f35d0ef4e4604100963` | MintID `public-v2026-11-13.1` (`dca3d605`) |
| `revocation-trace-testnet-20261114T104257Z.md` | 9,653 | `dd0dbdf619da23fd622ed707a19711b636f1bd56663edf4adbb1e0f5bea4cd5f` | MintID `public-v2026-11-13.1` (`dca3d605`) |
| `redthread-P2-mintid-sandbox-negative.jsonl` | 1,080 | `ac9c2463a5f6f97da10497c1094e8aa60264e995eb208fbdaaa84654231c922c` | Redthread `v0.7.586` + MintID `mintid-testnet-3` |
| `redthread-P2-mintid-sandbox-negative.manifest.json` | 971 | `fb4e9b65884ef59be4916ab7263ba6280d6c011cb0e9133407740ab5ec0bc45c` | Redthread `v0.7.586` + MintID `mintid-testnet-3` |
| `run_mintid_sandbox.py` | 3,359 | `f66c8e0db1fa3efdd1330dd9fa95a496f82a4fc541f577492184ef8dc511c295` | Redthread `v0.7.586` |

### Preserved Originals (`scenarios/p1_p8/originals/`)

| File | Size (Bytes) | SHA-256 | Notes |
|---|---:|---|---|
| `P2-revocation-after-delegation-before-effect-v1.json` | 3,636 | `bdfaf486c5639addddc3c318aa6fd18f338bc5cdf27be5a87c630730aa261218` | Initial `P2` JSON revision with single-string MintID `implementations_offered` entry |
| `redthread-p1-p6-local-runs.zip` | 17,973 | `b86918ac89f293305aae3e58824c2eaf76dc563078a22e925e98168a07a77739` | Exact zip archive from Ben Le (`v0.7.584`) |
| `redthread-p2-mintid-sandbox.zip` | 5,789 | `415722e426dd56c054cae0b319243157a2dee8638348964d0b12b988f4e67a1a` | Downloaded archive from Ben Le (`v0.7.586`; contains intact `redthread-P2-mintid-sandbox-negative.jsonl`, `.manifest.json`, and `run_mintid_sandbox.py`) |
