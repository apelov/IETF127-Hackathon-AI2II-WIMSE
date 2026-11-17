# WP07 — Extended Scenarios P1–P8 (`ietf127-wimse-scenario/1`) & Independent Checker

Tier: mini-code
Inputs: workpackages/README.md, scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md, scenarios/p1_p8/redthread-local.manifest.json, scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.manifest.json, scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.manifest.json

Integrate the `P1–P8` extended interop scenarios (`ietf127-wimse-scenario/1`: Ben Le / Redthread, Marc Miro / MintID, Arun Thallapelly / OmniArx, Kieran Sweeney / Cred, Iman Schrock) into the WIMSE repository and create an independent cross-family checker (`checkers/observes_p1_p8.py`) plus Domain B `P2`/`P7`/`P8` endpoints so the results are no longer a same-family self-report.

## Why

In Ben Le's and Iman Schrock's emails:
1. **Checker assignment (Iman & Ben):** Ben noted *"Our checks were written by the same model family as our code, so under Alexander's runbook everything above is a self-report. Alexander, if you assign a checker from another family to this P2 integration, we will provide the executor peer and its checks."*
2. **P2 ("Revocation after delegation, before effect"):**
   - **Redthread (`0.7.584` / `0.7.586`):** 120 s high-value bound (`status_ttl_s=60` + `clock_skew_s=60`; low-value grace is `0` at high value). Simulated clock (`0 s` before-effect refusal when executor refetches status lists just before effect; `50 s` last acceptance / `51 s` first refusal on `revoke-upstream`). Logs `authorize` (`effect="pending"`), `before-effect` (or `outside-verifier` with MintID `session_id` beside `txn_id`), and `effect="ran"|"none"`.
   - **MintID (Marc Miro, `mintid-testnet-3`, tag `public-v2026-11-13.1` / `dca3d605`, services `public-v2026-11-11.1`):** 10 s presentation proof lifetime; native bounds: **185 s** issuer revocation, **245 s** holder self-revocation, and **395 s** cascade from trigger root (`408.9 s` from the principal's revocation request). Keep the **13 Nov one-run figures** reported by Marc Miro by email (`issuer: 19.7 s / 25.2 s`, `holder: 14.6 s / 17.1 s`; no trace file for that run is in this repository) and the **14 Nov testnet trace** (`issuer: 19.7 s / 23.1 s`, `kill_switch: 14.5 s / 17.1 s`, `cascade` from trigger root `10:44:41Z`: `34.8 s -> 40.8 s` (`cascade_agent_2`) and `185.9 s -> 189.1 s` (`cascade_agent_1`); from the principal's revocation request `10:44:27.096Z` [+`13.9 s`]: `48.7 s -> 54.7 s` and `199.8 s -> 203.0 s`) clearly labeled as single-run measurements alongside the promised bounds, and record the **witness-refresh control** (`sibling_control` refreshes witness onto the new root and is `accepted`, whereas revoked agents get `credential_revoked` on witness refresh) that supplies revocation attribution when the verifier returns the shared `status_root_stale` code.
3. **P1–P6 (22 Redthread cases):**
   - `P1`: `confirmed-revocation` (`status-revoked`), `expired-cache` (`status-stale`), `service-unavailable` (`status-unavailable`), `low-value-grace` (`status-grace` then `status-stale`), `one-element-in-chain` (`status-unavailable`).
   - `P2`: `revoke-upstream` (`status-revoked`), `before-effect` (`status-revoked`, `effect: none`), plus `outside-made-up-proof` (`proof_invalid`) and `outside-no-agent-answer` (`no-agent-answer`).
   - `P3`: `wider-host`, `more-methods`, `longer-lifetime`, `dropped-tools`, `absent-means-default` (`allow: ok`), `unknown-member`.
   - `P4`: `per-rp-counting` (`limit-aud-not-single`), `single-accounting-rp` (5 `allow`, 6th `deny: limit-exceeded`), `child-limit-wider` (`attenuation:max_calls`).
   - `P5`: `rewrite-authority`, `rewrite-path` (`signature-invalid`), `authenticated-proxy-verifies` (`allow: ok`), `forwarded-headers-unauthenticated` (`forwarded-target-uri-unauthenticated`).
   - `P6`: `build-changed` (`build-mismatch`), `tool-swapped` (`tool-digest-mismatch`).
4. **P7 ("Approval display differs from the executed action" — OmniArx / Arun Thallapelly):**
   - Fixed clock `1800000000`, `A.1` key enrolled, `A.2` action (`V1`), `A.5` request (`V4`), fresh replay state, verifier holds the action.
   - Positive control `display-match` (`V5`, run first with fresh replay state $\rightarrow$ `allow: ok`, `effect: ran`).
   - Negative `display-mismatch` (`R2`, run with fresh replay state so it doesn't fail on `jti` replay $\rightarrow$ `deny: display-mismatch`, `effect: none`, logging `display_digest_expected` and `display_digest_presented`).
5. **P8 ("Final hop to a bearer-only third-party API" — Cred / Kieran Sweeney):**
   - Intermediary sitting in front of a bearer-only third-party API (`domain="B"`, `hop="E"`), logging `reason`, `provider`, `scopes_requested`, `token_released`:
   - `no-delegation` $\rightarrow$ `deny: no-delegation`, `token_released: false`.
   - `write-under-read` $\rightarrow$ `deny: scope-exceeded`, `token_released: false`.
   - `revoked-between-authz-and-use` (revoked while intermediary still holds token) $\rightarrow$ `deny: status-revoked`, `effect: none`, `token_released: false`.
   - `revoked-after-token-released` (revoked after intermediary handed bearer token out) $\rightarrow$ `decision: "revocation recorded, token already released"`, `reason: "token-released"`, `effect: "may still occur until the token expires"`, `token_released: true`.

Depends on: WP03, WP04.

## Deliverables

1. Verify that all canonical scenario definitions, submitted traces, and original archives are staged in `scenarios/p1_p8/` and `scenarios/p1_p8/originals/` (see `scenarios/p1_p8/PARTNER_COORDINATION_SUMMARY.md`), and add `scenarios/p1_p8/mintid_outside.py` (`outside(base_url, answer_fn, policy="iot_Command")` calling `POST /v1/challenges` and `POST /v1/presentations` and returning `(ok: bool, reason: str, extra: dict)`) plus the optional `outside=None` parameter in `ProtectedOperation.__init__` so `scenarios/p1_p8/run_mintid_sandbox.py` can be imported and self-tested offline or against `https://verifier.testnet.mintid.net`.
2. Create `peers/p2_p7_p8_executor.py` to execute live loopback HTTP exchanges for `P2`, `P7`, and `P8` on `127.0.0.1:5064` so they appear in `capture.pcap` as real wire traffic and emit `ietf127-wimse-scenario/1` JSONL log lines (`scenario`, `case`, `impl`, `hop`, `domain`, `txn_id`, `decision`, `reason`, `ts`, plus scenario-specific `log` fields):
   - **`P2` live HTTP cases (`revoke-upstream`, `before-effect`, `outside-made-up-proof`, `outside-no-agent-answer`):**
     - Uses `ProtectedOperation` pattern (`authorize` $\rightarrow$ `before_effect` hook / fresh status list fetch on `:5051/status` and optional MintID outside verifier hook $\rightarrow$ operation execution).
     - Logs `check="authorize"` (`effect="pending"`), `check="before-effect"` (or `"outside-verifier"` with `session_id`), `effect="none"`, `t_since_revocation_ms=0`, `bound_s=120`.
   - **`P7` live HTTP cases (`display-match` [V5], `display-mismatch` [R2], `impl="omniarx"`):**
     - Verifies at fixed clock `ts=1800000000` with fresh replay state per case and action held by the verifier.
     - Logs `display_digest_expected` and `display_digest_presented`; returns `200` (`allow`, `reason="ok"`, `effect="ran"`) for `display-match` and `403` (`deny`, `reason="display-mismatch"`, `effect="none"`) for `display-mismatch`.
   - **`P8` live HTTP cases (`no-delegation`, `write-under-read`, `revoked-between-authz-and-use`, `revoked-after-token-released`, `impl="cred"`):**
     - Intermediary in front of a bearer-only API; logs `provider`, `scopes_requested`, `token_released` (`false` for the first three, `true` for `revoked-after-token-released`).
3. Create `checkers/observes_p1_p8.py` (**MUST be authored/verified by a model family different from Redthread/MintID**, e.g. Nemotron or Gemini):
   - Verifies the SHA-256 digests of every JSONL file in `scenarios/p1_p8/redthread-local.manifest.json`.
   - Audits all 22 cases across `redthread-P1-local.jsonl` .. `redthread-P6-local.jsonl`:
     - Checks that every line conforms to `ietf127-wimse-scenario/1` required fields (`scenario`, `case`, `impl`, `hop`, `domain`, `txn_id`, `decision`, `reason`, `ts`).
     - In `P1`: verifies `status-revoked`, `status-stale`, `status-unavailable`, and `status-grace` are distinct in the log.
     - In `P2`: verifies `bound_s == 120` (60 s TTL + 60 s clock skew at high value, labeled `simulated`), `revoke-upstream` last acceptance at `50 s` and first refusal at `51 s` (`<= 120 s`), and `before-effect` logs `authorize` (`effect="pending"`) followed by `before-effect` (`decision="deny"`, `reason="status-revoked"`, `effect="none"`, `t_since_revocation_ms == 0`).
     - In `MintID trace` (`revocation-trace-testnet-20261114T104257Z.manifest.json` / `.jsonl`): verifies `tracked_changes is False`, `proof_lifetime_s == 10`, `issuer` refusal (`23.1 s <= 185 s` bound), `kill_switch` refusal (`17.1 s <= 245 s` bound), `cascade` dual time origins (`10:44:27.096Z` issuer revoke response vs `10:44:41Z` trigger root, `13.9 s` delta; refusals at `40.8 s` / `189.1 s <= 395 s` from trigger root and `54.7 s` / `203.0 s <= 408.9 s` from issuer revoke response), and verifies the **witness-refresh control** (`sibling_control` refreshes witness and is `accepted`, while revoked agents fail witness refresh with `credential_revoked`).
     - In `MintID sandbox negative controls` (`redthread-P2-mintid-sandbox-negative.manifest.json` / `.jsonl`): verifies `outside-made-up-proof` (`reason == "proof_invalid"`, `session_id == "01eac0157bbfc1f54af295fadb53dafc"`, `effect == "none"`) and `outside-no-agent-answer` (`reason == "no-agent-answer"`, `session_id == "ea27daa1d8be8f59a1c5e43963facc2d"`, `effect == "none"`).
   - Decodes the live HTTP capture (`capture.pcap` on port `5064`) for `P2`, `P7` (`display-match` V5 allow, `display-mismatch` R2 deny at clock `1800000000`), and `P8` (`token_released: false` vs `token_released: true`), and rejects 3 negative mutants (`p1_p8_unrelated.pcap`, `p1_p8_tampered_effect.jsonl`, `p1_p8_missing_before_effect.pcap`).

## Owns (touch only these)

- `scenarios/p1_p8/**`
- `peers/p2_p7_p8_executor.py`
- `checkers/observes_p1_p8.py`
- `checkers/make_p1_p8_negatives.py`
- `checkers/negatives/p1_p8_*`

Do **not** modify `peers/driver.py`, `checkers/observes_wimse.py`, or `cases.json`.

## Constraints / invariants

- Keep Redthread's simulated clock figures (`0 s`, `50 s`/`51 s`, `120 s` bound) explicitly labeled `"clock": "simulated"`.
- Keep MintID's `10 s` proof lifetime, `185 s` / `245 s` / `395 s` bounds, `13 Nov` one-run figures, and `14 Nov` testnet figures separate, with the witness-refresh control supplying the revocation attribution.
- Use `OmniArx` (exact spelling) for `P7` and run `display-match` (`V5`) and `display-mismatch` (`R2`) with fresh replay state at fixed clock `1800000000`.
- Commit locally when `Verify:` passes; never push.

## Verification

Verify: .venv/bin/python peers/p2_p7_p8_executor.py --self-test && .venv/bin/python checkers/observes_p1_p8.py --verify-manifests scenarios/p1_p8
