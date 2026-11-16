#!/usr/bin/env bash
# setup/clone_partners.sh
# Validation of the MintID testnet configuration and endpoint health.
# Redthread Security (Ben Le) is a separate project from EMILIA Protocol. Its code is NOT cloned
# here: no public source location exists yet, so the committed copies in scenarios/p1_p8/ are used.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${ROOT}"

# Configuration
MINTID_NETWORKS_JSON="deploy/networks.json"
EXTERNAL_DIR="external"
HEALTH_CHECK_TIMEOUT=5
HEALTH_CHECK_RETRIES=2

PYTHON_BIN="/usr/bin/python3"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

mkdir -p "${EXTERNAL_DIR}"

validate_networks_json() {
    local networks_file="${ROOT}/${MINTID_NETWORKS_JSON}"
    if [[ ! -f "${networks_file}" ]]; then
        err "Missing ${MINTID_NETWORKS_JSON}"
        return 1
    fi
    
    local parsed
    if ! parsed=$("${PYTHON_BIN}" -c '
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
t = d["profiles"]["testnet"]["chains"]["mintid-testnet-3"]
print(t["issuer"], t["verifier"], t["relay"], t["rpc"])
' "${networks_file}" 2>&1); then
        err "networks.json missing profile 'testnet' with chain 'mintid-testnet-3': ${parsed}"
        return 1
    fi
    
    read -r issuer_url verifier_url relay_url rpc_url <<< "${parsed}"
    
    log "networks.json validation passed:"
    log "  Issuer:   ${issuer_url}"
    log "  Verifier: ${verifier_url}"
    log "  Relay:    ${relay_url}"
    log "  RPC:      ${rpc_url}"
    
    export MINTID_ISSUER_URL="${issuer_url}"
    export MINTID_VERIFIER_URL="${verifier_url}"
    export MINTID_RELAY_URL="${relay_url}"
    export MINTID_RPC_URL="${rpc_url}"
}

health_check() {
    local name="$1" url="$2" expected_path="$3"
    local attempt=1
    
    while (( attempt <= HEALTH_CHECK_RETRIES )); do
        if response=$(curl -fsS --max-time "${HEALTH_CHECK_TIMEOUT}" "${url}${expected_path}" 2>/dev/null); then
            if echo "${response}" | "${PYTHON_BIN}" -c 'import sys, json; json.loads(sys.stdin.read())' >/dev/null 2>&1; then
                log "${name}: OK (${url}${expected_path})"
                return 0
            fi
        fi
        ((attempt++))
    done
    
    warn "${name}: unreachable (${url}${expected_path})"
    return 1
}

run_health_checks() {
    log "Checking MintID testnet endpoints reachability..."
    local verifier_ok=false
    
    if health_check "Verifier build-info" "${MINTID_VERIFIER_URL}" "/v1/build-info"; then
        verifier_ok=true
        health_check "Verifier status" "${MINTID_VERIFIER_URL}" "/v1/status" || true
    fi
    
    health_check "Issuer build-info" "${MINTID_ISSUER_URL}" "/v1/build-info" || true
    health_check "Relay status" "${MINTID_RELAY_URL}" "/v1/status" || true
    health_check "RPC status" "${MINTID_RPC_URL}" "/status" || true
    
    if [[ "${verifier_ok}" == "true" ]]; then
        export MINTID_MODE="LIVE"
        log "MintID Verifier reachable. MINTID_MODE=LIVE"
    else
        export MINTID_MODE="SIMULATED"
        log "MintID Verifier unreachable. MINTID_MODE=SIMULATED (falling back to recorded/mock engine)"
    fi
}

main() {
    log "=== WP09 Partner Setup & Testnet Health Check ==="
    validate_networks_json
    run_health_checks
    log "Partner setup complete. Mode: ${MINTID_MODE}"
}

main "$@"
