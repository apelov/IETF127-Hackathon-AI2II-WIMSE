# WP09 (Future TODO) — Live `emilia-protocol` (Redthread) + `mintid-testnet-3` Integration

Tier: mini-code / live-testnet
Status: **Planned / Future TODO**
Inputs: `scenarios/p1_p8/run_local.py`, `scenarios/p1_p8/run_mintid_sandbox.py`, `scenarios/p1_p8/mintid_outside.py`, `scenarios/p1_p8/protected_op.py`, `scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.manifest.json`, `peers/domain_b.py`, `interop.yaml`

---

## 1. Objective & Motivation

In the baseline `chain` cell (`WP01–WP08`), Suite 3 (`P1–P8`) verifies:
- Redthread Security's `P1–P6` (`22/22` cases) and MintID's `mintid-testnet-3` revocation trace (`92` JSONL records) against their signed SHA-256 manifests, and
- Live loopback HTTP execution on `:5064` (`peers/p2_p7_p8_executor.py`) for `P2`, `P7`, and `P8`, including the two **negative** outside-verifier controls (`outside-made-up-proof` $\rightarrow$ `proof_invalid` and `outside-no-agent-answer` $\rightarrow$ `no-agent-answer`).

When a developer clones both external partner repositories alongside this repository and connects to MintID's live `testnet` profile (`deploy/networks.json`), **WP09** upgrades Suite 3 from *recorded partner traces + negative sandbox controls* to **100% live end-to-end execution**, including the **positive** MintID zero-knowledge non-revocation proof and live on-chain revocation enforcement inside the WIMSE 3-agent call chain.

---

## 2. External Repositories & Live Testnet Endpoints

### 2.1 Redthread Security (`emilia-protocol`)
- **Repository:** `https://github.com/emiliaprotocol/emilia-protocol` (release `v0.7.586`+, commits `a09a616`, `ac4d088`, `39f7531`, `358c1ad`)
- **Provided Modules (`app/` & `tests/`):**
  - `rp_policy` (`rp.LOW`, `rp.HIGH`)
  - `atpp_world` (`GOOD_TRANSPORT`, simulated & real clock modes, status-list cache/TTL, tool-digest registry)
  - `test_atpp_delegation` (`_signed`, `two_hop`, Ed25519 Agent Passport chain minting)
  - `docs/hackathon/ietf127/run_local.py` & `docs/hackathon/ietf127/run_mintid_sandbox.py`

### 2.2 MintID (`mintid-testnet-3`)
- **Website / SDK:** `https://mintid.net` (release tag `public-v2026-11-13.1`, source revision `82c455ed09f8a99142117378a345a392d031f7dc`, verifier engine `proof-core 0.6.0`, SDK `0.9.0`, `SPEC-1 v3.7`)
- **Network Configuration (`deploy/networks.json`, profile `testnet`, chain `mintid-testnet-3`):**

| Service Role | Testnet Endpoint (`deploy/networks.json`) | Protocol / Contract Responsibility |
|---|---|---|
| **Issuer** | `https://issuer.testnet.mintid.net` | Mints BBS+ / accumulator agent credentials (`issuer_id = 7bf0b103ee565ba9...`), serves holder witness refreshes, and publishes status roots every `H = 30 s` heartbeat. |
| **Verifier** | `https://verifier.testnet.mintid.net` | `GET /v1/build-info`, `GET /v1/status`, `POST /v1/challenges` (issues 10 s presentation challenge `session_id`), and `POST /v1/presentations` (verifies ZK non-revocation proof against newest provable finalized root via ICS-23 proof). |
| **Relay** | `https://relay.testnet.mintid.net` | Accepts holder kill-switch nullifier transactions and broadcasts them to `mintid-testnet-3`. |
| **Node RPC** | `https://rpc.testnet.mintid.net:443` | CometBFT RPC endpoint serving finalized block heights, `app_hash`, and ICS-23 Merkle proofs (`max_root_age_seconds = 180`, `max_height_lag = 100`, `K = 5 s`). |

---

## 3. Architecture & Call Flow (`live-partners` Cell)

```text
Agent 3: RICH Research Sub-Agent (:5062, Domain B)
  │
  │ 1. POST :5063/files/read (WIT + WPT + narrowed Txn-Token T_B2)
  ▼
File Tool (:5063) wrapped in Redthread ProtectedOperation (protected_op.py)
  │
  ├──▶ [Gate 1: authorize] Verifies WIMSE WIT + WPT (tth) + Txn-Token + Agent Passport chain
  │
  ├──▶ [Gate 2: before-effect + mintid_outside.py]
  │      │
  │      ├─▶ 2a. POST https://verifier.testnet.mintid.net/v1/challenges
  │      │       ◄── {"session_id": "<id>", "policy": [...], "expires_in": 10}
  │      │
  │      ├─▶ 2b. MintID Agent Prover (answer_fn):
  │      │       • Refreshes witness from https://issuer.testnet.mintid.net
  │      │         and https://rpc.testnet.mintid.net:443
  │      │       • Generates 10s ZK non-revocation presentation proof_hex
  │      │
  │      └─▶ 2c. POST https://verifier.testnet.mintid.net/v1/presentations
  │              ◄── {"accepted": true, "reason_code": "accepted"} (or "status_root_stale" if revoked)
  │
  └──▶ [Effect: File Read] Executes ONLY if both Gate 1 and Gate 2 return allow
```

---

## 4. Implementation Deliverables

1. **Workspace Checkout Helper (`setup/clone_partners.sh`):**
   - Clones `https://github.com/emiliaprotocol/emilia-protocol` into `external/emilia-protocol` (pinned to `v0.7.586`+) and links/validates the MintID checkout + `deploy/networks.json` (`profile: testnet`).
   - Verifies live reachability of all 4 MintID testnet endpoints:
     - `https://issuer.testnet.mintid.net`
     - `https://verifier.testnet.mintid.net/v1/build-info` & `/v1/status`
     - `https://relay.testnet.mintid.net`
     - `https://rpc.testnet.mintid.net:443/status`

2. **Live `P1–P6` Regeneration via `emilia-protocol` (`scenarios/p1_p8/run_local.py`):**
   - Adds `PYTHONPATH=external/emilia-protocol/app:external/emilia-protocol/tests` so `python3 scenarios/p1_p8/run_local.py` executes Redthread's native verifier and regenerates `redthread-P1..P6-local.jsonl` and `redthread-local.manifest.json` live.

3. **Positive & Negative Live `P2` + MintID Testnet Execution (`scenarios/p1_p8/run_mintid_sandbox.py` & `peers/p2_p7_p8_executor.py`):**
   - Implements `mintid_live_answer(challenge)` in `scenarios/p1_p8/mintid_outside.py` using the MintID SDK (`deploy/networks.json`, profile `testnet`) to replace the placeholder `answer` in `run_mintid_sandbox.py`.
   - Executes all 4 live `P2` outside-verifier cases against `https://verifier.testnet.mintid.net`:
     - **`P2_outside-positive-unrevoked` (`200 OK`):** Fresh witness + valid 10 s ZK proof $\rightarrow$ `accepted: true`, `effect: "ran"`.
     - **`P2_outside-positive-revoked` (`403 Forbidden`):** Revoke via `issuer.testnet.mintid.net` (or `relay.testnet.mintid.net` kill-switch), wait for next root epoch on `rpc.testnet.mintid.net:443` ($\le 30\text{ s}$ heartbeat), verify witness refresh fails with `credential_revoked` and verifier refuses with `status_root_stale` within the `185 s` / `245 s` bound (`effect: "none"`).
     - **`P2_outside-made-up-proof` (`403 Forbidden`):** Rejected by `verifier.testnet.mintid.net` with `proof_invalid` (`effect: "none"`).
     - **`P2_outside-no-agent-answer` (`403 Forbidden`):** Rejected locally when prover returns `None` (`no-agent-answer`, `effect: "none"`).

4. **End-to-End Hook on Domain B File Tool (`peers/domain_b.py` `:5063`):**
   - Adds an optional `--mintid-outside https://verifier.testnet.mintid.net` flag to `peers/domain_b.py` so the File Tool (`POST /files/read`) invokes `ProtectedOperation(..., outside=mintid_outside.outside(...))` before serving `Q3.pdf`.

5. **Optional `live-partners` Cell in `interop.yaml` & `reproduce.sh --live-testnet`:**
   - Adds a `live-partners` cell to `interop.yaml` (gated on `envcheck` confirming `external/emilia-protocol` and `https://verifier.testnet.mintid.net/v1/status` are reachable) and an independent checker `checkers/observes_live_partners.py`.

---

## 5. Verification Criteria (`Verify:`)

```sh
# 1. Verify live MintID testnet reachability:
curl -fsS https://verifier.testnet.mintid.net/v1/build-info | jq .
curl -fsS https://verifier.testnet.mintid.net/v1/status | jq .

# 2. Run Redthread P1-P6 + MintID live sandbox (negative + positive cases):
PYTHONPATH=external/emilia-protocol/app:external/emilia-protocol/tests \
  .venv/bin/python scenarios/p1_p8/run_mintid_sandbox.py https://verifier.testnet.mintid.net
```
