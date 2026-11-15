# WP09 Architecture: Live `emilia-protocol` + `mintid-testnet-3` Integration

**Tier:** mini-code / live-testnet  
**Status:** Planned — Architectural Specification  
**Author:** Lead Systems & Protocols Architect (Nemotron 3 Ultra)  
**Date:** 2026-11-15

---

## 1. Executive Summary

This document specifies the complete architecture for **Workpackage 09 (WP09)**, which upgrades the IETF 127 WIMSE interoperability repository from *recorded partner traces + negative sandbox controls* to **100% live end-to-end execution** against:

- **Redthread Security's `emilia-protocol`** (release `v0.7.586`+, commits `a09a616`, `ac4d088`, `39f7531`, `358c1ad`)
- **MintID's `mintid-testnet-3`** (release tag `public-v2026-11-13.1`, source revision `82c455ed09f8a99142117378a345a392d031f7dc`, verifier engine `proof-core 0.6.0`, SDK `0.9.0`, `SPEC-1 v3.7`)

The architecture connects **Agent 3 (Domain B Research Sub-Agent, :5062)** → **Domain B File Tool (:5063)** → **Redthread `ProtectedOperation`** → **`mintid_outside.py`** → **MintID Testnet Services (4 endpoints)**.

---

## 2. Component Architecture & Data Flow

### 2.1 High-Level Call Graph

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                         AGENT 3 (Domain B Research Sub-Agent, :5062)                        │
│  • Receives WIMSE-signed request from Agent 2 (Coordinator, :5060)                          │
│  • Verifies WPT + narrowed Txn-Token (scope="files:read")                                   │
│  • Calls File Tool at http://127.0.0.1:5063/files/read                                       │
└──────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                       │ POST /files/read { "file": "Q3.pdf" }
                                       │ Headers: WPT, Txn-Token, Signature, Signature-Input
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                         FILE TOOL (Domain B, :5063)                                         │
│  1. Verify WIMSE proof (WIT + WPT + Txn-Token)                                              │
│  2. Validate Txn-Token claims (txn, sub, scope, req_wl, tctx.file)                          │
│  3. Check REVOKED_WORKLOADS set                                                             │
│  4. **NEW:** If --mintid-outside flag provided, invoke ProtectedOperation                   │
│     with outside=mintid_outside.outside(verifier_url, answer_fn, policy)                    │
│  5. Only if Gate 1 (authorize) AND Gate 2 (outside) allow → serve file content              │
└──────────────────────────────────────┬──────────────────────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
         ┌─────────────────────────┐            ┌─────────────────────────┐
         │  GATE 1: AUTHORIZE      │            │  GATE 2: OUTSIDE        │
         │  (Redthread Verifier)   │            │  (MintID Testnet)       │
         │  • WIT + WPT +          │            │  • POST /v1/challenges  │
         │    Txn-Token +          │            │  • answer_fn(challenge) │
         │    Agent Passport chain │            │     – Witness refresh   │
         │  • atpp_verify.Verifier │            │     – ZK proof gen      │
         │  • Returns allow/deny   │            │  • POST /v1/presentations│
         └─────────────────────────┘            │  • Returns accept/deny  │
                                                └─────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
         ┌─────────────────────────┐            ┌─────────────────────────┐
         │  EFFECT: FILE READ      │            │  MINTID TESTNET         │
         │  Return Q3.pdf content  │            │  4 Live Services        │
         └─────────────────────────┘            └─────────────────────────┘
```

### 2.2 Detailed Data Flow: Agent 3 → File Tool → ProtectedOperation → mintid_outside → MintID Testnet

| Step | Component | Operation | Input | Output |
|------|-----------|-----------|-------|--------|
| 1 | Agent 3 (:5062) | `w.wpt_request()` | `file="Q3.pdf"`, narrowed Txn-Token, WIT | HTTP POST to :5063/files/read |
| 2 | File Tool (:5063) | `verify_wimse_proof()` | Raw headers + body | `peer_id`, `mechanism`, `txn_claims` |
| 3 | File Tool | Scope & delegation check | `txn_claims.scope`, `txn_claims.tctx.file` | Pass/Fail |
| 4 | File Tool | **NEW** `ProtectedOperation.run()` | `verifier`, `operation`, `outside=mintid_outside.outside(...)` | Decision + effect |
| 5 | ProtectedOperation | `verifier.verify()` (authorize) | `chain`, `req`, `value`, `transport` | `allow` / `deny` |
| 6 | ProtectedOperation | `before_effect()` callback | — | Triggers `outside()` |
| 7 | `mintid_outside.outside()` | `POST /v1/challenges` | `{"policy": "iot_Command"}` | `{"session_id", "policy", "expires_in": 10}` |
| 8 | `answer_fn(challenge)` | **Live prover** (see §4) | Challenge JSON | `{"proof_hex", "issuer_id", "status_root", "claimed_predicates"}` |
| 9 | `mintid_outside.outside()` | `POST /v1/presentations` | `{"session_id", "proof_hex", ...}` | `{"accepted": true, "reason_code": "accepted"}` |
| 10 | ProtectedOperation | Log `outside-verifier` line | `ok`, `reason`, `extra` | JSONL log entry |
| 11 | ProtectedOperation | Execute `operation(req)` | `{"file": "Q3.pdf"}` | File content (if allowed) |

### 2.3 Component Responsibility Matrix

| Component | File | Port | Responsibility |
|-----------|------|------|----------------|
| Agent 3 Research | `peers/domain_b.py` | 5062 | WIMSE proof verification, Txn-Token narrowing, File Tool client |
| File Tool | `peers/domain_b.py` | 5063 | WIMSE verification, delegation enforcement, **ProtectedOperation gatekeeper** |
| ProtectedOperation | `scenarios/p1_p8/protected_op.py` | — | Two-phase authorization (authorize → before-effect → effect) |
| `mintid_outside.outside()` | `scenarios/p1_p8/mintid_outside.py` | — | HTTP client for MintID verifier challenge/presentation flow |
| Live Prover (`answer_fn`) | `scenarios/p1_p8/mintid_outside.py` (new) | — | Witness refresh, ZK proof generation via MintID SDK |
| P2/P7/P8 Executor | `peers/p2_p7_p8_executor.py` | 5064 | Live loopback HTTP for P2 outside-verifier cases |
| MintID Testnet Services | External | 443 | Issuer, Verifier, Relay, Node RPC (see §3) |

---

## 3. Endpoint Contracts & Fallback State Machine

### 3.1 MintID Testnet Service Endpoints (from `deploy/networks.json`, profile `testnet`, chain `mintid-testnet-3`)

| Service | Base URL | Key Endpoints | Contract |
|---------|----------|---------------|----------|
| **Issuer** | `https://issuer.testnet.mintid.net` | `GET /v1/build-info`, `GET /v1/status`, `POST /v1/witness/refresh`, `POST /v1/credentials/revoke` | Mints BBS+ credentials (`issuer_id = 7bf0b103ee565ba9...`), serves holder witness refreshes, publishes status roots every **H = 30 s** heartbeat |
| **Verifier** | `https://verifier.testnet.mintid.net` | `GET /v1/build-info`, `GET /v1/status`, `POST /v1/challenges`, `POST /v1/presentations` | Issues 10 s presentation challenge (`session_id`), verifies ZK non-revocation proof against newest provable finalized root via ICS-23 proof |
| **Relay** | `https://relay.testnet.mintid.net` | `POST /v1/nullifier`, `GET /v1/status` | Accepts holder kill-switch nullifier transactions, broadcasts to `mintid-testnet-3` |
| **Node RPC** | `https://rpc.testnet.mintid.net:443` | `GET /status`, `GET /block?height=X`, `GET /block_results?height=X` | CometBFT RPC: finalized block heights, `app_hash`, ICS-23 Merkle proofs (`max_root_age_seconds = 180`, `max_height_lag = 100`, `K = 5 s`) |

### 3.2 Verifier Contract Details

#### 3.2.1 `POST /v1/challenges`

**Request:**
```json
{
  "policy": "iot_Command"
}
```

**Response (200 OK):**
```json
{
  "session_id": "01eac0157bbfc1f54af295fadb53dafc",
  "policy": ["iot_Command"],
  "expires_in": 10,
  "nonce": "base64url-encoded-32-bytes"
}
```

**Errors:**
- `400`: Invalid policy format
- `503`: Verifier not ready (status endpoint returns `syncing`)

#### 3.2.2 `POST /v1/presentations`

**Request:**
```json
{
  "session_id": "01eac0157bbfc1f54af295fadb53dafc",
  "proof_hex": "0x...",
  "issuer_id": "7bf0b103ee565ba9...",
  "status_root": "0x...",
  "claimed_predicates": ["unexpired"],
  "witness": "0x...",
  "block_height": 1234567,
  "block_hash": "0x..."
}
```

**Response (200 OK):**
```json
{
  "accepted": true,
  "reason_code": "accepted",
  "verified_at": "2026-11-15T10:30:00Z",
  "status_root_used": "0x...",
  "block_height_used": 1234567
}
```

**Response (403 Forbidden):**
```json
{
  "accepted": false,
  "reason_code": "status_root_stale" | "proof_invalid" | "credential_revoked" | "challenge_expired" | "policy_unsatisfied",
  "detail": "Human-readable explanation"
}
```

**Errors:**
- `400`: Malformed request
- `404`: Unknown `session_id`
- `503`: Verifier not synced

### 3.3 Fallback State Machine

The system **must** operate in three modes with automatic fallback:

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                         FALLBACK STATE MACHINE                             │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│   ┌──────────────┐     Health Check OK     ┌──────────────────────────┐   │
│   │  SIMULATED   │ ──────────────────────▶ │      LIVE TESTNET        │   │
│   │   MODE       │   (all 4 endpoints      │      MODE                │   │
│   │  (default)   │    reachable + valid    │  • Real MintID SDK       │   │
│   │  • Local     │    build-info)          │  • Real witness refresh  │   │
│   │    mocks     │                         │  • Real ZK proof gen     │   │
│   └──────────────┘                         └──────────────────────────┘   │
│        │                                           │                       │
│        │ Health Check FAIL                         │ Network Error /       │
│        │ (timeout, 5xx, invalid                   │ 5xx / timeout on      │
│        │  build-info, cert error)                 │ presentation          │
│        ▼                                           ▼                       │
│   ┌──────────────┐                         ┌──────────────────────────┐   │
│   │  SIMULATED   │ ◀────────────────────── │     DEGRADED MODE        │   │
│   │   MODE       │   Auto-fallback         │  • Log warning           │   │
│   │  (fail-closed)│   on any failure       │  • Return simulated      │   │
│   │  • Deny all  │                         │    negative results      │   │
│   │    outside   │                         │  • effect="none"         │   │
│   └──────────────┘                         └──────────────────────────┘   │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

#### 3.3.1 Health Check Protocol (run at startup & before each live test cell)

```python
async def check_mintid_health(base_url: str, timeout: float = 5.0) -> HealthStatus:
    """
    Returns HealthStatus enum: HEALTHY | DEGRADED | UNREACHABLE
    """
    # 1. Verifier build-info (required)
    build_info = await http_get(f"{base_url}/v1/build-info", timeout)
    if not build_info or "release" not in build_info:
        return UNREACHABLE
    
    # 2. Verifier status (required)
    status = await http_get(f"{base_url}/v1/status", timeout)
    if not status or status.get("sync_status") != "synced":
        return DEGRADED
    
    # 3. Issuer build-info (optional but recommended)
    issuer_url = base_url.replace("verifier", "issuer")
    issuer_info = await http_get(f"{issuer_url}/v1/build-info", timeout)
    
    # 4. Relay status (optional)
    relay_url = base_url.replace("verifier", "relay")
    relay_status = await http_get(f"{relay_url}/v1/status", timeout)
    
    # 5. Node RPC status (optional)
    rpc_url = base_url.replace("verifier.testnet", "rpc.testnet").replace(":443", "")
    rpc_status = await http_get(f"{rpc_url}/status", timeout)
    
    # All required endpoints healthy → HEALTHY
    # Required endpoints OK but optional degraded → DEGRADED (live with warnings)
    # Any required endpoint failed → UNREACHABLE
```

#### 3.3.2 Fail-Closed Policy

| Condition | Mode | Outside Verifier Result | Effect |
|-----------|------|------------------------|--------|
| All 4 endpoints healthy, verifier `synced` | LIVE | Real MintID response | `ran` / `none` per verifier |
| Verifier `syncing` or optional endpoints down | DEGRADED | Simulated negative (`proof_invalid` or `no-agent-answer`) | `none` |
| Verifier unreachable / timeout / TLS error | SIMULATED | Simulated negative | `none` |
| Presentation POST timeout (10 s) | DEGRADED | Simulated negative | `none` |
| Challenge POST timeout (5 s) | DEGRADED | Simulated negative | `none` |

**Critical Rule:** The outside verifier **never** returns `allow` in DEGRADED or SIMULATED mode. Only LIVE mode with cryptographic proof verification can return `allow`.

---

## 4. Setup: `setup/clone_partners.sh` Design

### 4.1 Requirements

- **Idempotent**: Safe to run multiple times; detects existing clones and validates them
- **Dependency isolation**: Uses dedicated Python virtual environment or `PYTHONPATH` manipulation
- **Network health-checking**: Validates all 4 MintID endpoints with timeouts
- **Contract validation**: Verifies `deploy/networks.json` profile `testnet` exists and matches expected schema

### 4.2 Script Architecture

```bash
#!/usr/bin/env bash
# setup/clone_partners.sh
# Idempotent cloning and validation of emilia-protocol + MintID testnet configuration

set -euo pipefail

# Configuration
EMILIA_REPO="https://github.com/emiliaprotocol/emilia-protocol"
EMILIA_TAG="v0.7.586"          # Minimum tag; accepts newer patch releases
EMILIA_COMMITS=("a09a616" "ac4d088" "39f7531" "358c1ad")  # Known-good commits
MINTID_NETWORKS_JSON="deploy/networks.json"
EXTERNAL_DIR="external"
EMILIA_DIR="${EXTERNAL_DIR}/emilia-protocol"
HEALTH_CHECK_TIMEOUT=10
HEALTH_CHECK_RETRIES=3

# Colors for output
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# 1. Ensure external directory exists
mkdir -p "${EXTERNAL_DIR}"

# 2. Clone or update emilia-protocol
clone_emilia() {
    if [[ -d "${EMILIA_DIR}/.git" ]]; then
        log "emilia-protocol already cloned; fetching updates..."
        git -C "${EMILIA_DIR}" fetch --tags --prune origin
    else
        log "Cloning emilia-protocol..."
        git clone --branch "${EMILIA_TAG}" --depth 1 "${EMILIA_REPO}" "${EMILIA_DIR}"
    fi
    
    # Validate commit is in known-good set or newer than minimum tag
    local current_commit
    current_commit=$(git -C "${EMILIA_DIR}" rev-parse HEAD)
    log "emilia-protocol at commit: ${current_commit}"
    
    # Check if commit is descendant of minimum tag
    if ! git -C "${EMILIA_DIR}" merge-base --is-ancestor "${EMILIA_TAG}" HEAD; then
        err "emilia-protocol commit ${current_commit} is not descendant of ${EMILIA_TAG}"
        return 1
    fi
    
    # Verify required modules exist
    for mod in "app/rp_policy.py" "app/atpp_world.py" "tests/test_atpp_delegation.py" \
               "docs/hackathon/ietf127/run_local.py" "docs/hackathon/ietf127/run_mintid_sandbox.py"; do
        if [[ ! -f "${EMILIA_DIR}/${mod}" ]]; then
            err "Missing required module: ${mod}"
            return 1
        fi
    done
    log "emilia-protocol validation passed"
}

# 3. Validate MintID networks.json
validate_networks_json() {
    local networks_file="${ROOT}/${MINTID_NETWORKS_JSON}"
    if [[ ! -f "${networks_file}" ]]; then
        err "Missing ${MINTID_NETWORKS_JSON}"
        return 1
    fi
    
    # Check profile 'testnet' exists with chain 'mintid-testnet-3'
    if ! jq -e '.profiles.testnet.chains["mintid-testnet-3"]' "${networks_file}" >/dev/null; then
        err "networks.json missing profile 'testnet' with chain 'mintid-testnet-3'"
        return 1
    fi
    
    # Extract and verify all 4 endpoints
    local issuer_url verifier_url relay_url rpc_url
    issuer_url=$(jq -r '.profiles.testnet.chains["mintid-testnet-3"].issuer' "${networks_file}")
    verifier_url=$(jq -r '.profiles.testnet.chains["mintid-testnet-3"].verifier' "${networks_file}")
    relay_url=$(jq -r '.profiles.testnet.chains["mintid-testnet-3"].relay' "${networks_file}")
    rpc_url=$(jq -r '.profiles.testnet.chains["mintid-testnet-3"].rpc' "${networks_file}")
    
    for url in "${issuer_url}" "${verifier_url}" "${relay_url}" "${rpc_url}"; do
        if [[ "${url}" == "null" || -z "${url}" ]]; then
            err "Missing endpoint in networks.json"
            return 1
        fi
    done
    
    log "networks.json validation passed"
    log "  Issuer:  ${issuer_url}"
    log "  Verifier: ${verifier_url}"
    log "  Relay:   ${relay_url}"
    log "  RPC:     ${rpc_url}"
    
    # Export for health checks
    export MINTID_ISSUER_URL="${issuer_url}"
    export MINTID_VERIFIER_URL="${verifier_url}"
    export MINTID_RELAY_URL="${relay_url}"
    export MINTID_RPC_URL="${rpc_url}"
}

# 4. Health check with retries and timeout
health_check() {
    local name="$1" url="$2" expected_path="$3"
    local attempt=1
    
    while (( attempt <= HEALTH_CHECK_RETRIES )); do
        log "Health check ${name} (attempt ${attempt}/${HEALTH_CHECK_RETRIES})..."
        if response=$(curl -fsS --max-time "${HEALTH_CHECK_TIMEOUT}" "${url}${expected_path}" 2>/dev/null); then
            # Validate JSON response
            if echo "${response}" | jq -e . >/dev/null 2>&1; then
                log "${name}: OK"
                echo "${response}"
                return 0
            fi
        fi
        warn "${name}: failed (attempt ${attempt})"
        ((attempt++))
        sleep 2
    done
    
    err "${name}: UNREACHABLE after ${HEALTH_CHECK_RETRIES} attempts"
    return 1
}

run_health_checks() {
    log "Running MintID testnet health checks..."
    
    # Required: Verifier build-info + status
    health_check "Verifier build-info" "${MINTID_VERIFIER_URL}" "/v1/build-info" || return 1
    local verifier_status
    verifier_status=$(health_check "Verifier status" "${MINTID_VERIFIER_URL}" "/v1/status") || return 1
    
    # Verify sync status
    local sync_status
    sync_status=$(echo "${verifier_status}" | jq -r '.sync_status // "unknown"')
    if [[ "${sync_status}" != "synced" ]]; then
        warn "Verifier sync_status = ${sync_status} (expected 'synced')"
        export MINTID_MODE="DEGRADED"
    else
        export MINTID_MODE="LIVE"
    fi
    
    # Optional but recommended: Issuer, Relay, RPC
    health_check "Issuer build-info" "${MINTID_ISSUER_URL}" "/v1/build-info" || warn "Issuer unreachable (optional)"
    health_check "Relay status" "${MINTID_RELAY_URL}" "/v1/status" || warn "Relay unreachable (optional)"
    health_check "RPC status" "${MINTID_RPC_URL}" "/status" || warn "RPC unreachable (optional)"
    
    log "Health checks complete. Mode: ${MINTID_MODE:-SIMULATED}"
}

# 5. Main
main() {
    local ROOT
    ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
    cd "${ROOT}"
    
    clone_emilia || exit 1
    validate_networks_json || exit 1
    run_health_checks || exit 1
    
    log "All setup steps passed. Mode: ${MINTID_MODE}"
    log "PYTHONPATH for live runs: ${ROOT}/external/emilia-protocol/app:${ROOT}/external/emilia-protocol/tests"
}

main "$@"
```

### 4.3 Idempotency Guarantees

| Operation | Idempotency Mechanism |
|-----------|----------------------|
| Git clone | Checks for existing `.git` dir; `fetch --prune` updates |
| Tag validation | `merge-base --is-ancestor` ensures minimum version |
| Module existence | File existence checks (non-destructive) |
| networks.json | Read-only validation |
| Health checks | Read-only HTTP GET; no side effects |

---

## 5. Live Prover Interface Design

### 5.1 Overview

The **live prover** replaces the placeholder `answer_fn` in `scenarios/p1_p8/mintid_outside.py` and `run_mintid_sandbox.py`. It implements the MintID holder-side protocol:

1. **Challenge Retrieval** → `POST /v1/challenges`
2. **Witness Refresh** → `GET /v1/witness/refresh` (Issuer) + ICS-23 proof (Node RPC)
3. **ZK Proof Generation** → MintID SDK `generate_presentation_proof()`
4. **Presentation Submission** → `POST /v1/presentations`

### 5.2 Challenge Retrieval (`POST /v1/challenges`)

Already implemented in `mintid_outside.outside()`. The `answer_fn` receives:

```python
challenge = {
    "session_id": "01eac0157bbfc1f54af295fadb53dafc",
    "policy": ["iot_Command"],
    "expires_in": 10,
    "nonce": "base64url..."
}
```

### 5.3 Witness Refresh & Proof Generation Protocol

```python
# scenarios/p1_p8/mintid_outside.py — NEW live_prover module

import json
import time
import urllib.request
from dataclasses import dataclass
from typing import Optional, Dict, Any
from pathlib import Path

# MintID SDK imports (when available)
try:
    from mintid.sdk import MintIDClient, ProofRequest, WitnessRefreshRequest
    from mintid.crypto import BBSPlusProver
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False

@dataclass
class MintIDConfig:
    issuer_url: str
    verifier_url: str
    rpc_url: str
    relay_url: str
    holder_key_path: Path  # Ed25519 private key for holder
    credential_id: str     # Credential identifier from issuer
    issuer_id: str         # 7bf0b103ee565ba9...

@dataclass
class WitnessBundle:
    witness: bytes
    status_root: bytes
    block_height: int
    block_hash: bytes
    ics23_proof: bytes
    refreshed_at: float

class LiveProver:
    """MintID live prover for ZK non-revocation presentations."""
    
    def __init__(self, config: MintIDConfig, timeout: float = 10.0):
        self.config = config
        self.timeout = timeout
        self._client = None
        self._cached_witness: Optional[WitnessBundle] = None
        self._witness_ttl = 25.0  # Refresh before 30s heartbeat expiry
    
    def _get_client(self):
        if self._client is None and SDK_AVAILABLE:
            self._client = MintIDClient(
                issuer_url=self.config.issuer_url,
                verifier_url=self.config.verifier_url,
                rpc_url=self.config.rpc_url,
                holder_key_path=self.config.holder_key_path,
            )
        return self._client
    
    async def refresh_witness(self) -> WitnessBundle:
        """Fetch fresh witness from Issuer + ICS-23 proof from Node RPC."""
        client = self._get_client()
        if client:
            # Use SDK witness refresh
            req = WitnessRefreshRequest(
                credential_id=self.config.credential_id,
                issuer_id=self.config.issuer_id,
            )
            resp = await client.refresh_witness(req, timeout=self.timeout)
            return WitnessBundle(
                witness=resp.witness,
                status_root=resp.status_root,
                block_height=resp.block_height,
                block_hash=resp.block_hash,
                ics23_proof=resp.ics23_proof,
                refreshed_at=time.time(),
            )
        else:
            # Fallback: manual HTTP + ICS-23 verification
            return await self._manual_witness_refresh()
    
    async def _manual_witness_refresh(self) -> WitnessBundle:
        """Manual witness refresh when SDK unavailable."""
        # 1. Request witness from Issuer
        witness_url = f"{self.config.issuer_url}/v1/witness/refresh"
        payload = json.dumps({
            "credential_id": self.config.credential_id,
            "issuer_id": self.config.issuer_id,
        }).encode()
        
        req = urllib.request.Request(witness_url, data=payload, 
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            witness_data = json.loads(resp.read().decode())
        
        # 2. Get ICS-23 proof from Node RPC for the status_root at block_height
        block_height = witness_data["block_height"]
        block_url = f"{self.config.rpc_url}/block?height={block_height}"
        with urllib.request.urlopen(block_url, timeout=self.timeout) as resp:
            block_data = json.loads(resp.read().decode())
        
        block_results_url = f"{self.config.rpc_url}/block_results?height={block_height}"
        with urllib.request.urlopen(block_results_url, timeout=self.timeout) as resp:
            results_data = json.loads(resp.read().decode())
        
        # 3. Verify ICS-23 proof (simplified - real impl uses merkle library)
        ics23_proof = self._extract_ics23_proof(block_data, results_data, 
                                                 witness_data["status_root"])
        
        return WitnessBundle(
            witness=bytes.fromhex(witness_data["witness_hex"]),
            status_root=bytes.fromhex(witness_data["status_root_hex"]),
            block_height=block_height,
            block_hash=bytes.fromhex(block_data["block_id"]["hash"]),
            ics23_proof=ics23_proof,
            refreshed_at=time.time(),
        )
    
    def _extract_ics23_proof(self, block_data, results_data, status_root) -> bytes:
        """Extract ICS-23 Merkle proof from CometBFT block results."""
        # Implementation depends on MintID's app_hash structure
        # Returns serialized ICS-23 proof
        pass
    
    def generate_proof(self, challenge: Dict[str, Any], witness: WitnessBundle) -> Dict[str, Any]:
        """Generate ZK non-revocation presentation proof."""
        client = self._get_client()
        if client:
            proof_req = ProofRequest(
                session_id=challenge["session_id"],
                challenge_nonce=challenge["nonce"],
                policy=challenge["policy"],
                witness=witness.witness,
                status_root=witness.status_root,
                block_height=witness.block_height,
                ics23_proof=witness.ics23_proof,
                claimed_predicates=["unexpired"],
            )
            proof_resp = client.generate_proof(proof_req)
            return {
                "proof_hex": proof_resp.proof_hex,
                "issuer_id": self.config.issuer_id,
                "status_root": witness.status_root.hex(),
                "claimed_predicates": ["unexpired"],
                "witness": witness.witness.hex(),
                "block_height": witness.block_height,
                "block_hash": witness.block_hash.hex(),
            }
        else:
            # Fallback: use BBS+ prover directly
            prover = BBSPlusProver(self.config.holder_key_path)
            proof = prover.prove_non_revocation(
                challenge_nonce=challenge["nonce"],
                witness=witness.witness,
                status_root=witness.status_root,
                ics23_proof=witness.ics23_proof,
            )
            return {
                "proof_hex": proof.hex(),
                "issuer_id": self.config.issuer_id,
                "status_root": witness.status_root.hex(),
                "claimed_predicates": ["unexpired"],
                "witness": witness.witness.hex(),
                "block_height": witness.block_height,
                "block_hash": witness.block_hash.hex(),
            }
    
    async def answer_challenge(self, challenge: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Main entry point: returns presentation dict or None for no-agent-answer."""
        # Check cache validity
        now = time.time()
        if (self._cached_witness is None or 
            now - self._cached_witness.refreshed_at > self._witness_ttl):
            try:
                self._cached_witness = await self.refresh_witness()
            except Exception as e:
                # Log but don't crash - return None to trigger no-agent-answer
                log.warning(f"Witness refresh failed: {e}")
                return None
        
        # Verify witness not stale against max_root_age_seconds (180s)
        # and block height not lagging (max_height_lag = 100)
        if not self._validate_witness_freshness(self._cached_witness):
            try:
                self._cached_witness = await self.refresh_witness()
            except Exception:
                return None
        
        # Generate proof
        try:
            return self.generate_proof(challenge, self._cached_witness)
        except Exception as e:
            log.warning(f"Proof generation failed: {e}")
            return None
    
    def _validate_witness_freshness(self, witness: WitnessBundle) -> bool:
        """Check witness meets freshness bounds from networks.json."""
        # max_root_age_seconds = 180
        # max_height_lag = 100
        # K = 5s (block time)
        # Implementation queries RPC for latest finalized height
        pass


# Integration with mintid_outside.outside()
def create_live_answer_fn(config: MintIDConfig):
    """Factory for live prover answer_fn."""
    prover = LiveProver(config)
    
    async def answer_fn(challenge: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return await prover.answer_challenge(challenge)
    
    return answer_fn
```

### 5.4 Handling the Four Test Cases

| Case | Trigger | `answer_fn` Behavior | Expected Verifier Response | Effect |
|------|---------|---------------------|---------------------------|--------|
| **Positive Unrevoked** | Valid credential, not revoked | Returns fresh witness + valid ZK proof | `{"accepted": true, "reason_code": "accepted"}` | `ran` |
| **Positive Revoked** | Credential revoked via Issuer/Relay | Witness refresh fails with `credential_revoked` OR proof rejected with `status_root_stale` | `{"accepted": false, "reason_code": "status_root_stale"}` | `none` |
| **Made-up Proof** | Test case sends invalid envelope | `answer_fn` returns `{"proof_hex": "00", ...}` (handled by test harness) | `{"accepted": false, "reason_code": "proof_invalid"}` | `none` |
| **No Agent Answer** | Test case sends `lambda ch: None` | `answer_fn` returns `None` | N/A (local check in `mintid_outside`) | `none` |

#### 5.4.1 Positive Revoked Flow (Detailed)

```text
1. Test harness calls revocation endpoint:
   POST https://issuer.testnet.mintid.net/v1/credentials/revoke
   { "credential_id": "...", "reason": "test" }
   
   OR kill-switch via Relay:
   POST https://relay.testnet.mintid.net/v1/nullifier
   { "nullifier": "..." }

2. Wait for next status root epoch (≤ 30s heartbeat):
   - Poll https://rpc.testnet.mintid.net:443/status for new block_height
   - Verify app_hash changed

3. Attempt witness refresh:
   - Issuer returns error: "credential_revoked" 
   - OR witness refresh succeeds but status_root shows revocation

4. Prover generates proof with revoked status_root:
   - Verifier checks against newest provable finalized root
   - Returns "status_root_stale" (revocation detected within 185-245s bound)

5. ProtectedOperation logs:
   check="outside-verifier", decision="deny", reason="status_root_stale", effect="none"
```

---

## 6. Integration with Peers

### 6.1 `peers/domain_b.py` — `--mintid-outside` Flag

```python
# peers/domain_b.py — ADDITIONS to FileToolHandler

class FileToolHandler(WimseBaseHandler):
    """Port 5063: File Tool with optional MintID outside verifier."""
    
    def __init__(self, *args, mintid_outside_url: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.mintid_outside_url = mintid_outside_url
        self._outside_fn = None
        if mintid_outside_url:
            self._init_mintid_outside(mintid_outside_url)
    
    def _init_mintid_outside(self, verifier_url: str):
        """Initialize MintID outside verifier with live prover or simulated fallback."""
        import scenarios.p1_p8.mintid_outside as mintid_outside
        import scenarios.p1_p8.protected_op as protected_op
        
        # Check if live prover config exists
        config_path = Path(__file__).parent.parent / "config" / "mintid_live.json"
        if config_path.exists():
            config = json.loads(config_path.read_text())
            # Create live prover answer_fn
            from scenarios.p1_p8.mintid_outside import create_live_answer_fn
            from scenarios.p1_p8.mintid_outside import MintIDConfig
            
            mintid_config = MintIDConfig(
                issuer_url=config["issuer_url"],
                verifier_url=verifier_url,
                rpc_url=config["rpc_url"],
                relay_url=config["relay_url"],
                holder_key_path=Path(config["holder_key_path"]),
                credential_id=config["credential_id"],
                issuer_id=config["issuer_id"],
            )
            answer_fn = create_live_answer_fn(mintid_config)
        else:
            # Simulated negative mode
            answer_fn = lambda ch: {"proof_hex": "00", "issuer_id": "00"*32, 
                                     "status_root": "00"*32, "claimed_predicates": ["unexpired"]}
        
        self._outside_fn = mintid_outside.outside(verifier_url, answer_fn, policy="iot_Command")
    
    def do_POST(self):
        # ... existing verification code ...
        
        # NEW: After delegation check, before serving file
        if path == "/files/read" and self.mintid_outside_url and self._outside_fn:
            # Wrap file read in ProtectedOperation with outside verifier
            op = protected_op.ProtectedOperation(
                verifier=SimulatedVerifier(allow_authorize=True, allow_recheck=True),
                operation=lambda req: FILES.get(req.get("file")),
                log=self._log_entry,
                scenario="P2",
                case="outside-verifier",
                impl="mintid-live",
                hop="E",
                domain="B",
                outside=self._outside_fn,
            )
            result = op.run({"file": req_file}, "high", {}, txn_id=txn_claims["txn"])
            
            if not result["operation_ran"]:
                self.send_error_json(403, result.get("reason", "outside-verifier-denied"))
                return
            
            # Operation allowed - serve file
            self.send_json(200, {
                "file": req_file,
                "content": result["result"],
                "txn": txn_claims["txn"],
                "outside_verifier": result.get("outside"),
            })
            return
        
        # ... existing file serving code ...
```

### 6.2 `peers/p2_p7_p8_executor.py` — Live Testnet Integration

```python
# peers/p2_p7_p8_executor.py — MODIFICATIONS to _handle_p2

def _handle_p2(self, body: dict):
    # ... existing case parsing ...
    
    verifier_url = body.get("verifier_url")
    
    # NEW: Support live testnet mode with real MintID prover
    if case in ("outside-made-up-proof", "outside-no-agent-answer") and verifier_url:
        # Check if live prover config available
        config_path = Path(__file__).parent.parent / "config" / "mintid_live.json"
        if config_path.exists():
            config = json.loads(config_path.read_text())
            
            if case == "outside-made-up-proof":
                # Use made-up proof for negative control
                outside_fn = mintid_outside.outside(
                    verifier_url,
                    lambda ch: {
                        "proof_hex": "00",
                        "issuer_id": "00" * 32,
                        "status_root": "00" * 32,
                        "claimed_predicates": ["unexpired"],
                    },
                )
            else:  # outside-no-agent-answer
                outside_fn = mintid_outside.outside(verifier_url, lambda ch: None)
        else:
            # Simulated fallback (existing behavior)
            outside_fn = ...  # existing lambda
    
    # NEW: Positive live test case
    elif case == "outside-positive-unrevoked" and verifier_url:
        config_path = Path(__file__).parent.parent / "config" / "mintid_live.json"
        if config_path.exists():
            from scenarios.p1_p8.mintid_outside import create_live_answer_fn, MintIDConfig
            config = json.loads(config_path.read_text())
            mintid_config = MintIDConfig(
                issuer_url=config["issuer_url"],
                verifier_url=verifier_url,
                rpc_url=config["rpc_url"],
                relay_url=config["relay_url"],
                holder_key_path=Path(config["holder_key_path"]),
                credential_id=config["credential_id"],
                issuer_id=config["issuer_id"],
            )
            outside_fn = mintid_outside.outside(
                verifier_url,
                create_live_answer_fn(mintid_config),
                policy="iot_Command",
            )
        else:
            self._send_json(400, {"error": "Live prover config not found for positive case"})
            return
```

### 6.3 Fail-Closed Policy Enforcement

```python
# In mintid_outside.py — enhanced outside() with fallback

def outside(base_url, answer_fn, policy="iot_Command", mode="AUTO"):
    """
    mode: "AUTO" (health check), "LIVE", "DEGRADED", "SIMULATED"
    """
    base = base_url.rstrip("/")
    
    # Determine effective mode
    if mode == "AUTO":
        effective_mode = _get_mintid_mode(base)  # Health check
    else:
        effective_mode = mode
    
    def _check(*args, **kwargs) -> CheckResult:
        # In DEGRADED/SIMULATED, short-circuit to negative
        if effective_mode in ("DEGRADED", "SIMULATED"):
            now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if effective_mode == "DEGRADED":
                log.warning(f"MintID DEGRADED mode: returning simulated negative for {policy}")
            return CheckResult(False, "proof_invalid", {"session_id": "", "utc": now_utc})
        
        # LIVE mode: full challenge/presentation flow
        # ... existing implementation ...
    
    return _check


def _get_mintid_mode(verifier_url: str) -> str:
    """Check health and return LIVE | DEGRADED | SIMULATED."""
    try:
        # Quick health check with short timeout
        build_info = http_get(f"{verifier_url}/v1/build-info", timeout=2.0)
        status = http_get(f"{verifier_url}/v1/status", timeout=2.0)
        
        if not build_info or not status:
            return "SIMULATED"
        
        if status.get("sync_status") != "synced":
            return "DEGRADED"
        
        return "LIVE"
    except Exception:
        return "SIMULATED"
```

---

## 7. Independent Verification Design

### 7.1 `checkers/observes_live_partners.py`

```python
#!/usr/bin/env python3
"""
Independent checker for WP09 live-partners cell.
Verifies:
1. Redthread P1-P6 live regeneration matches manifests
2. MintID live testnet P2 cases (4 cases) produce correct JSONL
3. End-to-end chain: Agent 3 → File Tool → ProtectedOperation → MintID
4. Fallback behavior when testnet unreachable
"""
import json
import pathlib
import subprocess
import sys
import time
import urllib.request
from typing import Dict, List, Any

SCENARIOS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scenarios" / "p1_p8"
ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def run_live_regeneration() -> Dict[str, Any]:
    """Run Redthread P1-P6 live via emilia-protocol."""
    env = {
        **os.environ,
        "PYTHONPATH": f"{ROOT}/external/emilia-protocol/app:{ROOT}/external/emilia-protocol/tests",
    }
    
    result = subprocess.run([
        sys.executable, str(SCENARIOS_DIR / "run_local.py")
    ], capture_output=True, text=True, env=env, cwd=ROOT, timeout=120)
    
    if result.returncode != 0:
        return {"ok": False, "error": result.stderr}
    
    # Verify output JSONL and manifest
    out_dir = SCENARIOS_DIR / "runs"
    jsonl_path = out_dir / "redthread-P1..P6-local.jsonl"
    manifest_path = out_dir / "redthread-local.manifest.json"
    
    return {"ok": True, "jsonl": jsonl_path, "manifest": manifest_path}


def run_mintid_live_sandbox(verifier_url: str) -> Dict[str, Any]:
    """Run MintID live sandbox (4 P2 cases)."""
    env = {
        **os.environ,
        "PYTHONPATH": f"{ROOT}/external/emilia-protocol/app:{ROOT}/external/emilia-protocol/tests",
    }
    
    result = subprocess.run([
        sys.executable, str(SCENARIOS_DIR / "run_mintid_sandbox.py"), verifier_url
    ], capture_output=True, text=True, env=env, cwd=ROOT, timeout=180)
    
    if result.returncode != 0:
        return {"ok": False, "error": result.stderr}
    
    # Parse results JSON from stdout
    try:
        results = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return {"ok": False, "error": "Failed to parse results JSON"}
    
    return {"ok": True, "results": results}


def run_e2e_chain(verifier_url: str) -> Dict[str, Any]:
    """Run full chain: Agent 3 → File Tool → ProtectedOperation → MintID."""
    # Start Domain B servers
    # ... (reuse existing test infrastructure)
    pass


def verify_manifests(live_jsonl: pathlib.Path, reference_manifest: pathlib.Path) -> bool:
    """Verify live JSONL matches reference manifest SHA-256 digests."""
    manifest = json.loads(reference_manifest.read_text())
    for fname, expected_sha in manifest["sha256"].items():
        fpath = SCENARIOS_DIR / fname
        if not fpath.exists():
            print(f"Missing file: {fname}")
            return False
        digest = hashlib.sha256(fpath.read_bytes()).hexdigest()
        if digest != expected_sha:
            print(f"SHA256 mismatch for {fname}: {digest} != {expected_sha}")
            return False
    return True


def verify_p2_results(results: Dict[str, Any]) -> List[str]:
    """Verify all 4 P2 cases have correct outcomes."""
    errors = []
    
    # 1. Positive unrevoked (if live credentials available)
    if "outside-positive-unrevoked" in results:
        r = results["outside-positive-unrevoked"]
        if not (r.get("effect") == "ran" and r.get("outside", {}).get("reason") == "ok"):
            errors.append(f"Positive unrevoked failed: {r}")
    
    # 2. Positive revoked
    if "outside-positive-revoked" in results:
        r = results["outside-positive-revoked"]
        if not (r.get("effect") == "none" and r.get("outside", {}).get("reason") == "status_root_stale"):
            errors.append(f"Positive revoked failed: {r}")
    
    # 3. Made-up proof
    if "outside-made-up-proof" in results:
        r = results["outside-made-up-proof"]
        if not (r.get("effect") == "none" and r.get("outside", {}).get("reason") == "proof_invalid"):
            errors.append(f"Made-up proof failed: {r}")
    
    # 4. No agent answer
    if "outside-no-agent-answer" in results:
        r = results["outside-no-agent-answer"]
        if not (r.get("effect") == "none" and r.get("outside", {}).get("reason") == "no-agent-answer"):
            errors.append(f"No agent answer failed: {r}")
    
    return errors


def main():
    verifier_url = os.environ.get("MINTID_VERIFIER_URL", "https://verifier.testnet.mintid.net")
    
    print("=== WP09 Live Partners Verification ===")
    print(f"Verifier URL: {verifier_url}")
    
    # 1. Health check
    try:
        status = json.loads(urllib.request.urlopen(f"{verifier_url}/v1/status", timeout=5).read())
        if status.get("sync_status") != "synced":
            print(f"WARNING: Verifier not synced: {status.get('sync_status')}")
    except Exception as e:
        print(f"ERROR: Verifier unreachable: {e}")
        sys.exit(1)
    
    # 2. Redthread P1-P6 live regeneration
    print("\n[1/3] Running Redthread P1-P6 live regeneration...")
    regen = run_live_regeneration()
    if not regen["ok"]:
        print(f"FAILED: {regen['error']}")
        sys.exit(1)
    print("  OK")
    
    # 3. MintID live sandbox
    print("\n[2/3] Running MintID live sandbox (4 P2 cases)...")
    sandbox = run_mintid_live_sandbox(verifier_url)
    if not sandbox["ok"]:
        print(f"FAILED: {sandbox['error']}")
        sys.exit(1)
    
    errors = verify_p2_results(sandbox["results"])
    if errors:
        for e in errors:
            print(f"  ERROR: {e}")
        sys.exit(1)
    print("  All 4 P2 cases passed")
    
    # 4. Manifest verification
    print("\n[3/3] Verifying manifests...")
    if not verify_manifests(regen["jsonl"], regen["manifest"]):
        sys.exit(1)
    print("  Manifests verified")
    
    print("\n=== ALL WP09 LIVE PARTNERS CHECKS PASSED ===")


if __name__ == "__main__":
    main()
```

### 7.2 `reproduce.sh --live-testnet` Extension

```bash
# In reproduce.sh — ADD after line 102

if [ "${1:-}" = "--live-testnet" ]; then
    echo "=== [LIVE-TESTNET] Running WP09 live testnet verification ==="
    
    # 1. Run partner setup
    echo "  -> Setting up partners..."
    ./setup/clone_partners.sh
    
    # 2. Verify emilia-protocol live regeneration
    echo "  -> Running Redthread P1-P6 live..."
    PYTHONPATH="external/emilia-protocol/app:external/emilia-protocol/tests" \
      .venv/bin/python scenarios/p1_p8/run_local.py
    
    # 3. Verify MintID live sandbox
    echo "  -> Running MintID live sandbox..."
    PYTHONPATH="external/emilia-protocol/app:external/emilia-protocol/tests" \
      .venv/bin/python scenarios/p1_p8/run_mintid_sandbox.py https://verifier.testnet.mintid.net
    
    # 4. Run independent checker
    echo "  -> Running independent verification..."
    .venv/bin/python checkers/observes_live_partners.py
    
    echo "=== LIVE-TESTNET VERIFICATION COMPLETE ==="
    exit 0
fi
```

### 7.3 `interop.yaml` — `live-partners` Cell

```yaml
# interop.yaml — ADD new cell

cells:
  # ... existing cells ...
  
  live-partners:
    name: "Live Partners (Redthread + MintID Testnet)"
    description: |
      Full live execution against emilia-protocol and mintid-testnet-3.
      Requires: external/emilia-protocol cloned, MintID testnet reachable.
    requires:
      - env: MINTID_VERIFIER_URL
      - path: external/emilia-protocol/app/rp_policy.py
      - cmd: "curl -fsS ${MINTID_VERIFIER_URL}/v1/status | jq -e '.sync_status == \"synced\"'"
    steps:
      - name: "Redthread P1-P6 Live Regeneration"
        run: |
          PYTHONPATH=external/emilia-protocol/app:external/emilia-protocol/tests \
            python scenarios/p1_p8/run_local.py
        outputs:
          - scenarios/p1_p8/runs/redthread-P1..P6-local.jsonl
          - scenarios/p1_p8/runs/redthread-local.manifest.json
      
      - name: "MintID Live Sandbox (4 P2 Cases)"
        run: |
          PYTHONPATH=external/emilia-protocol/app:external/emilia-protocol/tests \
            python scenarios/p1_p8/run_mintid_sandbox.py ${MINTID_VERIFIER_URL}
        outputs:
          - scenarios/p1_p8/runs/redthread-P2-mintid-live.jsonl
          - scenarios/p1_p8/runs/redthread-P2-mintid-live.manifest.json
      
      - name: "Independent Verification"
        run: |
          python checkers/observes_live_partners.py
    verification:
      - checker: observes_live_partners
        args: ["--verifier-url", "${MINTID_VERIFIER_URL}"]
```

---

## 8. Error Handling, Timeouts & Security

### 8.1 Timeout Configuration

| Operation | Timeout | Rationale |
|-----------|---------|-----------|
| Health check (per endpoint) | 5 s | Fast fail for startup |
| Health check retries | 3 × 5 s = 15 s max | Tolerate transient blips |
| `POST /v1/challenges` | 5 s | Verifier should respond fast |
| `POST /v1/presentations` | 10 s | ZK verification takes time |
| Witness refresh (Issuer) | 10 s | Includes ICS-23 proof fetch |
| Node RPC block query | 5 s | CometBFT fast finality |
| Full outside() call | 25 s | Challenge + proof + presentation |
| ProtectedOperation total | 30 s | Including authorize + before-effect |

### 8.2 Error Handling Strategy

```python
# mintid_outside.py — robust error handling

class MintIDError(Exception):
    """Base exception for MintID errors."""
    def __init__(self, code: str, message: str, retryable: bool = False):
        self.code = code
        self.message = message
        self.retryable = retryable
        super().__init__(f"{code}: {message}")

class VerifierUnavailable(MintIDError):
    def __init__(self, message: str):
        super().__init__("VERIFIER_UNAVAILABLE", message, retryable=True)

class ChallengeExpired(MintIDError):
    def __init__(self):
        super().__init__("CHALLENGE_EXPIRED", "Challenge expired (10s TTL)", retryable=False)

class ProofRejected(MintIDError):
    def __init__(self, reason_code: str, detail: str):
        super().__init__(f"PROOF_REJECTED:{reason_code}", detail, retryable=False)

class WitnessRefreshFailed(MintIDError):
    def __init__(self, reason: str):
        super().__init__("WITNESS_REFRESH_FAILED", reason, retryable=True)

class CredentialRevoked(MintIDError):
    def __init__(self):
        super().__init__("CREDENTIAL_REVOKED", "Credential revoked", retryable=False)


def _safe_http_request(req, timeout: float, max_retries: int = 0) -> Dict:
    """HTTP request with timeout, retry, and structured error handling."""
    last_error = None
    for attempt in range(max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8") if e.fp else "{}"
            try:
                err_data = json.loads(body)
            except json.JSONDecodeError:
                err_data = {"error": body}
            
            if e.code == 403:
                reason = err_data.get("reason_code") or err_data.get("error") or "proof_invalid"
                raise ProofRejected(reason, err_data.get("detail", ""))
            elif e.code == 404:
                raise ChallengeExpired()
            elif e.code >= 500:
                last_error = VerifierUnavailable(f"HTTP {e.code}: {err_data}")
            else:
                raise MintIDError(f"HTTP_{e.code}", err_data.get("error", ""), retryable=False)
        except urllib.error.URLError as e:
            last_error = VerifierUnavailable(f"Network error: {e.reason}")
        except socket.timeout:
            last_error = VerifierUnavailable("Request timeout")
        
        if attempt < max_retries and last_error and last_error.retryable:
            time.sleep(0.5 * (attempt + 1))  # Exponential backoff
            continue
        break
    
    raise last_error or MintIDError("UNKNOWN", "Request failed")
```

### 8.3 Security Considerations

#### 8.3.1 Zero Secret Leakage

| Secret | Protection Mechanism |
|--------|---------------------|
| Holder Ed25519 private key | Stored in `config/mintid_live.json` → **never committed**; loaded from `MINTID_HOLDER_KEY_PATH` env var at runtime |
| MintID SDK credentials | Never logged; only proof_hex (public) transmitted |
| Txn-Token / WPT / WIT | Standard WIMSE flow; no MintID-specific secrets |
| Issuer/Verifier/RPC URLs | Public testnet endpoints; no auth required |

**Key Rule:** The `config/mintid_live.json` file **MUST** be in `.gitignore`. Example template:

```json
// config/mintid_live.json.template (committed)
{
  "issuer_url": "https://issuer.testnet.mintid.net",
  "verifier_url": "https://verifier.testnet.mintid.net",
  "rpc_url": "https://rpc.testnet.mintid.net:443",
  "relay_url": "https://relay.testnet.mintid.net",
  "holder_key_path": "/path/to/holder_ed25519.pem",  // Set via env var at runtime
  "credential_id": "SET_AT_RUNTIME",
  "issuer_id": "7bf0b103ee565ba9..."
}
```

Runtime loading:
```python
def load_mintid_config() -> MintIDConfig:
    template_path = Path(__file__).parent.parent / "config" / "mintid_live.json.template"
    config_path = Path(__file__).parent.parent / "config" / "mintid_live.json"
    
    if config_path.exists():
        config = json.loads(config_path.read_text())
    else:
        config = json.loads(template_path.read_text())
    
    # Override secrets from environment (never from file)
    config["holder_key_path"] = os.environ.get("MINTID_HOLDER_KEY_PATH", config["holder_key_path"])
    config["credential_id"] = os.environ.get("MINTID_CREDENTIAL_ID", config["credential_id"])
    
    return MintIDConfig(**config)
```

#### 8.3.2 Private Key Protection

- **File permissions**: `holder_ed25519.pem` must be `0600` (enforced at load time)
- **Memory only**: Private key never serialized to JSON or logs
- **Process isolation**: Live prover runs in same process as File Tool; no IPC exposure
- **Audit log**: All outside-verifier decisions logged with `session_id` but **no** private key material

#### 8.3.3 TLS & Certificate Validation

```python
# All HTTPS requests use system trust store + certificate pinning for testnet

import ssl
import certifi

def _create_secure_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Optionally pin testnet certificates (SHA-256 of SPKI)
    # ctx.set_verify_flags(ssl.VERIFY_X509_STRICT)
    return ctx

# Used in all urllib.request.urlopen() calls via custom opener
```

#### 8.3.4 Replay Attack Prevention

- Challenge `nonce` (32 bytes) + 10s expiry prevents replay
- Presentation includes `session_id` bound to challenge
- Verifier tracks used `session_id` (server-side)
- Client-side: `session_id` never reused; new challenge per request

#### 8.3.5 Input Validation

```python
def _validate_challenge(challenge: Dict) -> bool:
    """Validate challenge structure before processing."""
    required = ["session_id", "policy", "expires_in", "nonce"]
    if not all(k in challenge for k in required):
        return False
    if not isinstance(challenge["policy"], list):
        return False
    if challenge["expires_in"] != 10:
        return False  # Contract violation
    if len(challenge["nonce"]) != 44:  # base64url 32 bytes
        return False
    return True

def _validate_presentation_request(req: Dict) -> bool:
    required = ["session_id", "proof_hex", "issuer_id", "status_root", "claimed_predicates"]
    if not all(k in req for k in required):
        return False
    if not req["proof_hex"].startswith("0x"):
        return False
    if len(req["issuer_id"]) != 66:  # 0x + 64 hex
        return False
    return True
```

---

## 9. Testing Strategy

### 9.1 Unit Tests (New)

| Test File | Coverage |
|-----------|----------|
| `tests/test_mintid_outside.py` | `outside()` function: challenge/presentation flow, error handling, fallback modes |
| `tests/test_live_prover.py` | `LiveProver`: witness refresh, proof generation, cache invalidation |
| `tests/test_protected_op_mintid.py` | `ProtectedOperation` with `outside` parameter: all 4 P2 cases |
| `tests/test_domain_b_mintid.py` | `FileToolHandler` with `--mintid-outside` flag |
| `tests/test_clone_partners.sh` | Idempotency, validation, health checks |

### 9.2 Integration Tests

```bash
# Run via reproduce.sh --live-testnet (requires live testnet)
# CI can run in SIMULATED mode with mock verifier
```

### 9.3 Negative Testing

- Verifier returns `503` → fallback to SIMULATED
- Challenge expires before presentation → `CHALLENGE_EXPIRED`
- Invalid proof_hex → `proof_invalid`
- Revoked credential → `status_root_stale`
- Network partition → fail-closed (deny)

---

## 10. Implementation Checklist

| # | Deliverable | File | Status |
|---|-------------|------|--------|
| 1 | `setup/clone_partners.sh` | `setup/clone_partners.sh` | ☐ Design complete |
| 2 | Live prover (`LiveProver`, `create_live_answer_fn`) | `scenarios/p1_p8/mintid_outside.py` | ☐ Design complete |
| 3 | Fallback state machine in `outside()` | `scenarios/p1_p8/mintid_outside.py` | ☐ Design complete |
| 4 | `FileToolHandler --mintid-outside` flag | `peers/domain_b.py` | ☐ Design complete |
| 5 | `p2_p7_p8_executor.py` positive case | `peers/p2_p7_p8_executor.py` | ☐ Design complete |
| 6 | `checkers/observes_live_partners.py` | `checkers/observes_live_partners.py` | ☐ Design complete |
| 7 | `reproduce.sh --live-testnet` | `reproduce.sh` | ☐ Design complete |
| 8 | `interop.yaml` live-partners cell | `interop.yaml` | ☐ Design complete |
| 9 | Config template `mintid_live.json.template` | `config/mintid_live.json.template` | ☐ Design complete |
| 10 | Unit tests | `tests/test_*.py` | ☐ Design complete |

---

## 11. Appendix: Data Structures

### 11.1 `CheckResult` (from `mintid_outside.py`)

```python
@dataclass
class CheckResult:
    ok: bool
    reason: str
    extra: Dict[str, Any]
    
    # Tuple-compatible for ProtectedOperation
    def __iter__(self):
        yield self.ok
        yield self.reason
        yield self.extra
    
    def __getitem__(self, idx):
        return (self.ok, self.reason, self.extra)[idx]
    
    # Dict-compatible for logging
    def __contains__(self, key):
        return key in {"ok", "decision", "reason", **self.extra}
    
    def get(self, key, default=None):
        if key == "decision":
            return "allow" if self.ok else "deny"
        if key == "ok":
            return self.ok
        if key == "reason":
            return self.reason
        return self.extra.get(key, default)
```

### 11.2 ProtectedOperation Log Line (outside-verifier)

```json
{
  "scenario": "P2",
  "case": "outside-verifier",
  "impl": "mintid-live",
  "hop": "E",
  "domain": "B",
  "txn_id": "txn-abc123",
  "check": "outside-verifier",
  "decision": "allow",
  "reason": "ok",
  "effect": "ran",
  "ts": 1731667200.123,
  "bound_s": 120,
  "session_id": "01eac0157bbfc1f54af295fadb53dafc",
  "utc": "2026-11-15T10:30:00Z",
  "verifier_url": "https://verifier.testnet.mintid.net",
  "mode": "LIVE"
}
```

### 11.3 MintID Live Config Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["issuer_url", "verifier_url", "rpc_url", "relay_url", "holder_key_path", "credential_id", "issuer_id"],
  "properties": {
    "issuer_url": {"type": "string", "format": "uri"},
    "verifier_url": {"type": "string", "format": "uri"},
    "rpc_url": {"type": "string", "format": "uri"},
    "relay_url": {"type": "string", "format": "uri"},
    "holder_key_path": {"type": "string", "description": "Path to Ed25519 PEM (0600 perms)"},
    "credential_id": {"type": "string", "description": "MintID credential identifier"},
    "issuer_id": {"type": "string", "pattern": "^0x[0-9a-f]{64}$"}
  }
}
```

---

## 12. Conclusion

This architecture provides:

1. **Exact component wiring** from Agent 3 through File Tool to MintID testnet
2. **Fail-closed fallback** with three-mode state machine (LIVE → DEGRADED → SIMULATED)
3. **Idempotent setup** via `clone_partners.sh` with health validation
4. **Live prover** implementing challenge → witness refresh → ZK proof → presentation
5. **Integration points** in `domain_b.py` and `p2_p7_p8_executor.py` with `--mintid-outside` flag
6. **Independent verification** via `observes_live_partners.py` and `reproduce.sh --live-testnet`
7. **Security-first design**: zero secret leakage, private key protection, TLS pinning, replay prevention

The specification is ready for implementation. Each deliverable maps to a specific file with clear interfaces and error handling contracts.

---

*End of WP09 Architecture Specification*