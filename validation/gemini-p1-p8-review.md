# Independent Cross-Family L4 Review: `observes_p1_p8.py`, `observes_chain.py`, and Redthread `P1–P6` Traces

- **Reviewer Model Family:** Google Gemini 4 (`gemini-4-argon`, non-Claude model family — distinct from the Anthropic Claude family that authored Redthread's `v0.7.584`/`v0.7.586` verifier, `run_local.py`, and [`validation/opus-chain-review.md`](opus-chain-review.md))
- **Review Date:** 2026-11-15
- **Scope:**
  1. Independent audit and hardening of [`checkers/observes_p1_p8.py`](../checkers/observes_p1_p8.py) and [`checkers/observes_chain.py`](../checkers/observes_chain.py) (including `expected_reason` verification across Suite 2 and Suite 3).
  2. Line-by-line audit of Redthread Security's `P1–P6` local traces (`scenarios/p1_p8/redthread-P1..P6-local.jsonl`), [`scenarios/p1_p8/redthread-local.manifest.json`](../scenarios/p1_p8/redthread-local.manifest.json), [`scenarios/p1_p8/run_local.py`](../scenarios/p1_p8/run_local.py), [`scenarios/p1_p8/protected_op.py`](../scenarios/p1_p8/protected_op.py), and [`scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.jsonl`](../scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.jsonl).

---

## 1. Summary Verdict

| Target | Verdict | Summary |
|---|---|---|
| **Redthread `P1–P6` Traces (`22 / 22` cases, 151 JSONL lines)** | **PASS (with 5 advisory findings for Redthread)** | All 22 cases across `P1–P6` (`v0.7.584`, simulated clock) and the 2 recorded MintID sandbox negative controls (`v0.7.586`, live run `2026-11-15T01:23:35Z–01:23:36Z`) produce the expected terminal decisions and canonical scenario reason codes. Five concrete findings (`RT-1` through `RT-5`) in `run_local.py` and the `P1`/`P2` trace emission are documented in Section 3 for Ben Le. |
| **`checkers/observes_chain.py`** | **HARDENED & PASS (`19 / 19` cases)** | Added explicit wire-level `expected_reason` extraction and comparison against `chain_cases.json` for all 19 Suite 2 cases, closing Finding 3.1 of `opus-chain-review.md`. Rejects all 3 negative chain PCAP mutants. |
| **`checkers/observes_p1_p8.py`** | **HARDENED & PASS (`22 / 22` trace cases + `10 / 10` wire cases)** | Added independent per-scenario canonical reason-code checks across `P1–P6`, independent `expected_decision` + `expected_reason` comparison on all 22 cases (no longer trusting `manifest["results"][i]["match"]`), multi-step transition verification (`P1/low-value-grace`, `P4/single-accounting-rp`), and exact `50000 ms` $\rightarrow$ `51000 ms` (simulated clock) boundary verification on `P2/revoke-upstream`. Rejects all 3 negative `P1–P8` PCAP mutants. |

---

## 2. Checker Audit & Hardening (`observes_chain.py` & `observes_p1_p8.py`)

### 2.1 `checkers/observes_chain.py` — Wire-Level `expected_reason` Comparison
- **Previous Gap:** `observes_chain.py` verified that `expected_statuses` from `chain_cases.json` were present on the wire for each `X-Test-Case`, but did not compare `spec["expected_reason"]` (`accept`, `proof-invalid`, `txn-token-invalid`, `not-authorized`, `revoked`, `grant-invalid`) against the decoded HTTP response JSON body.
- **Fix Applied:** `observes_chain.py` now extracts `resp_body.get("reason") or resp_body.get("error")` (recording `"accept"` on `200 OK` responses without an error field) into `case_reasons[case_id]` and asserts `spec["expected_reason"] in case_reasons[cid]` for all 19 cases in `chain_cases.json`.

### 2.2 `checkers/observes_p1_p8.py` — Independent `P1–P6` Trace & Reason Verification
- **Previous Gaps Identified by Cross-Family Review:**
  1. `verify_manifests()` only checked reason codes for `P1` and `P2`, leaving `P3`, `P4`, `P5`, and `P6` reason codes unchecked except via `all(r.get("match") is True for r in results)` in `redthread-local.manifest.json`.
  2. Relying on `r.get("match")` in `redthread-local.manifest.json` delegated verification to `run_local.py` line 194, which itself only checked `x["reason"] == x["expected_reason"].split(" then ")[-1]` on the last line of each case.
  3. `P2/revoke-upstream` checked that both `allow` and `deny` lines existed, without asserting that the last acceptance occurred at `t_since_revocation_ms == 50000` (`50 s` simulated) and the first refusal at `t_since_revocation_ms == 51000` (`51 s` simulated).
- **Fixes Applied in `checkers/observes_p1_p8.py`:**
  1. Enforces `EXPECTED_SCENARIO_REASONS` across all six scenarios:
     - `P1`: `{"status-revoked", "status-stale", "status-unavailable", "status-grace"}`
     - `P2`: `{"status-revoked"}`
     - `P3`: `{"attenuation:host", "attenuation:methods", "attenuation:exp", "attenuation:tools", "attenuation:unknown-member", "ok"}`
     - `P4`: `{"limit-aud-not-single", "limit-exceeded", "attenuation:max_calls"}`
     - `P5`: `{"signature-invalid", "forwarded-target-uri-unauthenticated", "ok"}`
     - `P6`: `{"build-mismatch", "tool-digest-mismatch"}`
  2. Groups all 151 lines across `redthread-P1..P6-local.jsonl` into the 22 `(scenario, case)` pairs and independently verifies both `decision` vs `expected_decision` and `reason` vs `expected_reason`.
  3. Explicitly verifies multi-step sequences:
     - `P1/low-value-grace`: 3 steps — step 0 `allow: ok` (`ts=1000000`), step 1 `allow: ok` with `record: ["status-grace"]` (`ts=1000100`), step 2 `deny: status-stale` (`ts=1000200`).
     - `P4/single-accounting-rp`: 6 steps — calls 1..5 `allow: ok` (`ts=1000000..1000004`), call 6 `deny: limit-exceeded` (`ts=1000005`).
     - `P2/revoke-upstream`: 120 steps — last `allow` at `t_since_revocation_ms == 50000` (`ts=60` simulated) and first `deny: status-revoked` at `t_since_revocation_ms == 51000` (`ts=61` simulated) against `bound_s == 120`.
     - `P2/before-effect`: 2 steps — `check="authorize"` (`allow`, `effect="pending"`) followed by `check="before-effect"` (`deny`, `reason="status-revoked"`, `effect="none"`, `t_since_revocation_ms == 0`).

---

## 3. Findings on Redthread `P1–P6` Runner & Traces (for Ben Le)

### Finding RT-1 (Medium): `run_local.py` line 194 `match` calculation ignores `decision` vs `expected_decision`
- **Location:** `scenarios/p1_p8/run_local.py:189-194`
- **Detail:**
  ```python
  for x in ls:
      final[x["case"]] = x                                          # the line that settles each case: the last one
  for case, x in final.items():
      table.append({"scenario": scn, "case": case, "observed": "%s: %s" % (x["decision"], x["reason"]),
                    "expected": "%s: %s" % (x["expected_decision"], x["expected_reason"]),
                    "match": x["reason"] == x["expected_reason"].split(" then ")[-1]})
  ```
  1. `match` compares `x["reason"]` against `x["expected_reason"].split(" then ")[-1]`, but **never checks `x["decision"]` against `x["expected_decision"]`**. If a bug caused a verifier to return `decision: "allow"` alongside a non-empty reason (or vice-versa), `match` would still evaluate to `True`.
  2. Because `final[x["case"]]` overwrites all prior lines and keeps only the final line of each case, `run_local.py` never checks that the earlier steps of multi-step cases (`P1/low-value-grace` step 2 `allow` with `status-grace`, `P4/single-accounting-rp` calls 1–5 `allow` before call 6 `deny: limit-exceeded`, or `P2/before-effect` step 1 `authorize: allow (pending)`) actually occurred as expected.
- **Suggested Fix for Redthread:** Compare both `x["decision"]` and `x["reason"]` on the settling line, andfor multi-step cases (`low-value-grace`, `single-accounting-rp`, `before-effect`), assert the intermediate step decisions/records before setting `match: True`.

### Finding RT-2 (Medium): `P1/low-value-grace` logs `bound_s: 3600` and `3500` (passport lifetime) instead of the status TTL + skew + grace bound
- **Location:** `scenarios/p1_p8/redthread-P1-local.jsonl:6-7` and `scenarios/p1_p8/run_local.py:78-84`
- **Detail:**
  - In `redthread-P1-local.jsonl` lines 1 and 3 (`confirmed-revocation-0` and `expired-cache-0`, run at `value=HIGH`), `"bound_s"` is `120` (`status_ttl 60 s + skew 60 s`).
  - However, in `low-value-grace` (`run_local.py:78-84`, run with `v = g.verifier(grace=120)` and `value=rp.LOW`), line 6 (`low-value-grace-0` at `ts=1000000`) logs `"bound_s": 3600`, and line 7 (`low-value-grace-1` at `ts=1000100`, 100 s into the outage under the 120 s grace period) logs `"bound_s": 3500`.
  - Per `draft-le-agent-passport` (*Exposure After Revocation*) and `P2-revocation-after-delegation-before-effect.json` (`bound_s = min(remaining passport lifetime, the largest of three mechanisms)` where the status mechanism adds `grace` for low-value operations: `60 s TTL + 60 s skew + 120 s grace = 240 s`), `bound_s` under `value=rp.LOW` with `grace=120` should be bounded by the status+grace window (`240 s` at `ts=1000000`), not the full `3600 s` passport lifetime.
  - Additionally, on line 7 (`low-value-grace-1`), `"reason"` is `"ok"` while `"status-grace"` is placed only in `"record": ["status-grace"]`. Consequently, in `redthread-local.manifest.json` (line 47), `low-value-grace` shows `"observed": "deny: status-stale"` next to `"expected": "allow then deny: status-grace then status-stale"`.
- **Suggested Fix for Redthread:** Include the low-value status+grace bound (`ttl + skew + grace`) in `Verifier`'s `exposure` calculation when `value == rp.LOW`, and include the intermediate `allow (status-grace)` step in the manifest's `observed` string for `low-value-grace`.

### Finding RT-3 (Low / Trace Clarity): Setup `allow` steps in multi-step cases carry `"expected_decision": "deny"`
- **Location:** `scenarios/p1_p8/run_local.py:44-48, 103`, `redthread-P1-local.jsonl:1,3`, `redthread-P2-local.jsonl:1-61,121`
- **Detail:**
  - `record()` stamps the case-level final expectation (`EXPECT[(scn, case)]`) onto every line emitted for that case.
  - As a result, 63 legitimate `allow` lines across `P1` and `P2` — specifically `confirmed-revocation-0` (`P1` line 1, before revocation), `expired-cache-0` (`P1` line 3, before cache expiry), `ru-0`..`ru-60` (`P2` lines 1–61, before revocation and during the 50 s cached status-list window), and `be-1` `check="authorize"` (`P2` line 121, before revocation) — have `"decision": "allow"` alongside `"expected_decision": "deny"` and `"expected_reason": "status-revoked"` (or `"status-stale"`).
- **Suggested Fix for Redthread:** Stamp step-specific expectations (`expected_decision: "allow"`, `expected_reason: "ok"`) on pre-revocation / cached-TTL setup calls, or only attach `expected_decision` / `expected_reason` to the settling step of each case.

### Finding RT-4 (Informational): `P2/revoke-upstream` `bound_s` is static (`120`) across the 50 s cached acceptance window
- **Location:** `scenarios/p1_p8/redthread-P2-local.jsonl:1-61`
- **Detail:**
  - In `P2/revoke-upstream`, the status list is fetched at `ts=0` (`ttl=60 s`), upstream passport A is revoked at `ts=10` (`t_since_revocation_ms: 0`), calls `ru-10`..`ru-60` (`ts=10..60`, `0..50 s` simulated after revocation) are allowed from cache, and `ru-61` (`ts=61`, `51 s` simulated after revocation) is the first refusal (`deny: status-revoked`).
  - Throughout `ts=0..60`, `"bound_s"` is logged as the static worst-case policy bound `120` rather than the remaining TTL+skew window. This is consistent with the definition of `bound_s` as a static upper bound in `P2-revocation-after-delegation-before-effect.json`, and the `50 s` simulated last acceptance / `51 s` simulated first refusal are well within `bound_s: 120`.

### Finding RT-5 (Low / Schema Hygiene): Individual JSONL lines omit `"clock": "simulated"`
- **Location:** `scenarios/p1_p8/redthread-P1..P6-local.jsonl` and `scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.jsonl`
- **Detail:**
  - The manifests (`redthread-local.manifest.json` and `redthread-P2-local.manifest.json`) state `"clock": "simulated"`, but the individual JSONL lines only carry `"ts": 1000000` (or `0..119`). In `redthread-P2-mintid-sandbox-negative.jsonl` lines 2 and 4, each `outside-verifier` line carries both `"ts": 1000000` (from Redthread's simulated clock) and `"utc": "2026-11-15T01:23:35Z"` (from the live MintID sandbox call).
- **Suggested Fix for Redthread:** Include `"clock": "simulated"` on simulated JSONL lines (or rename the simulated field `sim_ts_s`) so that any tool extracting numbers directly from `.jsonl` files automatically preserves the simulated-clock label.

---

## 4. Complete Case-by-Case Verification Table (`P1–P6`)

| Scenario | Case | JSONL Lines | Observed Sequence (`decision: reason`) | Expected (`expected_decision: expected_reason`) | Clock | Verdict |
|---|---|---:|---|---|---|---|
| **P1** | `confirmed-revocation` | 2 | `allow: ok` (`ts=1000000`) $\rightarrow$ `deny: status-revoked` (`ts=1000061`) | `deny: status-revoked` | simulated | **PASS** |
| **P1** | `expired-cache` | 2 | `allow: ok` (`ts=1000000`) $\rightarrow$ `deny: status-stale` (`ts=1000061`) | `deny: status-stale` | simulated | **PASS** |
| **P1** | `service-unavailable` | 1 | `deny: status-unavailable` (`ts=1000061`) | `deny: status-unavailable` | simulated | **PASS** |
| **P1** | `low-value-grace` | 3 | `allow: ok` (`ts=1000000`) $\rightarrow$ `allow: ok` (`record=["status-grace"]`, `ts=1000100`) $\rightarrow$ `deny: status-stale` (`ts=1000200`) | `allow then deny: status-grace then status-stale` | simulated | **PASS** *(see RT-2)* |
| **P1** | `one-element-in-chain` | 1 | `deny: status-unavailable` (`ts=1000000`) | `deny: status-unavailable` | simulated | **PASS** |
| **P2** | `revoke-upstream` | 120 | `allow: ok` (`ts=0..60`, last acceptance `50 s` simulated after revocation) $\rightarrow$ `deny: status-revoked` (`ts=61..119`, first refusal `51 s` simulated vs `bound_s=120`) | `deny: status-revoked` | simulated | **PASS** |
| **P2** | `before-effect` | 2 | `authorize`: `allow: ok` (`effect="pending"`, `ts=0`) $\rightarrow$ `before-effect`: `deny: status-revoked` (`effect="none"`, `t_since_revocation_ms=0`, `ts=5`) | `deny: status-revoked` | simulated | **PASS** |
| **P3** | `wider-host` | 1 | `deny: attenuation:host` | `deny: attenuation:host` | simulated | **PASS** |
| **P3** | `more-methods` | 1 | `deny: attenuation:methods` | `deny: attenuation:methods` | simulated | **PASS** |
| **P3** | `longer-lifetime` | 1 | `deny: attenuation:exp` | `deny: attenuation:exp` | simulated | **PASS** |
| **P3** | `dropped-tools` | 1 | `deny: attenuation:tools` | `deny: attenuation:tools` | simulated | **PASS** |
| **P3** | `absent-means-default` | 1 | `allow: ok` (`bound_s=120`) | `allow: ok` | simulated | **PASS** |
| **P3** | `unknown-member` | 1 | `deny: attenuation:unknown-member` | `deny: attenuation:unknown-member` | simulated | **PASS** |
| **P4** | `per-rp-counting` | 1 | `deny: limit-aud-not-single` | `deny at issuance or at first RP: limit-aud-not-single` | simulated | **PASS** |
| **P4** | `single-accounting-rp` | 6 | 5× `allow: ok` (`ts=1000000..1000004`) $\rightarrow$ 6th call `deny: limit-exceeded` (`ts=1000005`) | `allow N, deny call N + 1: limit-exceeded` | simulated | **PASS** |
| **P4** | `child-limit-wider` | 1 | `deny: attenuation:max_calls` | `deny: attenuation:max_calls` | simulated | **PASS** |
| **P5** | `rewrite-authority` | 1 | `deny: signature-invalid` | `deny: signature-invalid` | simulated | **PASS** |
| **P5** | `rewrite-path` | 1 | `deny: signature-invalid` | `deny: signature-invalid` | simulated | **PASS** |
| **P5** | `authenticated-proxy-verifies` | 1 | `allow: ok` (`bound_s=120`) | `allow: ok` | simulated | **PASS** |
| **P5** | `forwarded-headers-unauthenticated` | 1 | `deny: forwarded-target-uri-unauthenticated` | `deny: forwarded-target-uri-unauthenticated` | simulated | **PASS** |
| **P6** | `build-changed` | 1 | `deny: build-mismatch` (`verifier_reason="dlg-build-mismatch"`) | `deny: build-mismatch` | simulated | **PASS** |
| **P6** | `tool-swapped` | 1 | `deny: tool-digest-mismatch` | `deny: tool-digest-mismatch` | simulated | **PASS** |
