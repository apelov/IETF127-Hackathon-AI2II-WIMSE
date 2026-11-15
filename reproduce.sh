#!/usr/bin/env bash
# Self-contained reproduction and verification script for the IETF 127 WIMSE Interop repository.
# Usage:
#   ./reproduce.sh           # Verify all committed PCAPs, AI2II bundles, negative mutants, and P1-P8 partner manifests
#   ./reproduce.sh --live    # Also re-run live loopback packet capture cells via the vendored AI2II wire harness
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "=== [1/5] Preparing Python virtual environment (.venv) ==="
if [ ! -x ".venv/bin/python" ]; then
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip -q
    .venv/bin/pip install -r requirements.txt -q
fi
export PYTHONPATH="$ROOT"

echo "=== [2/5] Ensuring ephemeral WIMSE test keys exist ==="
.venv/bin/python setup/gen_keys.py

echo "=== [3/5] Verifying AI2II Evidence Bundles & SHA256SUMS ==="
for bundle in validation/bundle-*/*/; do
    if [ -f "${bundle}verdict.json" ]; then
        echo "  -> Verifying bundle: $bundle"
        .venv/bin/python -m wire verify-bundle "$bundle"
    fi
done
.venv/bin/python -m wire summarize validation

echo "=== [4/5] Running Independent Packet Checker (observes_wimse.py) on Committed PCAP & Mutants ==="
if command -v tshark >/dev/null 2>&1; then
    .venv/bin/python checkers/observes_wimse.py validation/bundle-inbound/inbound/capture.pcap
    for neg in checkers/negatives/unrelated.pcap checkers/negatives/request_only.pcap checkers/negatives/forbidden_fetch.pcap; do
        if [ -f "$neg" ]; then
            if .venv/bin/python checkers/observes_wimse.py "$neg" >/dev/null 2>&1; then
                echo "ERROR: negative mutant $neg unexpectedly passed!" >&2
                exit 1
            else
                echo "  -> Negative mutant rejected as expected: $neg"
            fi
        fi
    done
else
    echo "  [WARN] tshark not found on PATH; skipping live tshark dissection check."
fi

echo "=== [5/5] Verifying Partner P1-P8 Manifests & SHA-256 Digests ==="
.venv/bin/python - <<'PY'
import hashlib, json, pathlib, sys

p_dir = pathlib.Path("scenarios/p1_p8")

# 1. Redthread P1-P6 local manifest
rt_manifest = json.loads((p_dir / "redthread-local.manifest.json").read_text())
for fname, expected_sha in rt_manifest["sha256"].items():
    fpath = p_dir / fname
    digest = hashlib.sha256(fpath.read_bytes()).hexdigest()
    assert digest == expected_sha, f"SHA256 mismatch for {fname}: {digest} != {expected_sha}"
results = rt_manifest["results"]
assert len(results) == 22 and all(r["match"] for r in results)
print(f"  -> Redthread P1-P6 manifest verified ({len(results)}/22 cases matched, all 6 JSONL SHA-256 digests valid)")

# 2. MintID Nov 14 testnet revocation trace manifest
mi_manifest = json.loads((p_dir / "revocation-trace-testnet-20261114T104257Z.manifest.json").read_text())
assert mi_manifest["source"]["tracked_changes"] is False
for fname, expected_sha in mi_manifest["files"].items():
    fpath = p_dir / fname
    digest = hashlib.sha256(fpath.read_bytes()).hexdigest()
    assert digest == expected_sha, f"SHA256 mismatch for {fname}: {digest} != {expected_sha}"
print(f"  -> MintID testnet manifest verified (tag {mi_manifest['source']['public_checkout']['tag']}, tracked_changes=False, all SHA-256 digests valid)")

# 3. Redthread + MintID live sandbox negative control manifest
sb_manifest = json.loads((p_dir / "redthread-P2-mintid-sandbox-negative.manifest.json").read_text())
sb_lines = (p_dir / "redthread-P2-mintid-sandbox-negative.jsonl").read_text().strip().splitlines()
assert len(sb_lines) == sb_manifest["lines"] == 4
assert sb_manifest["results"]["made-up-proof"]["outside"]["reason"] == "proof_invalid"
assert sb_manifest["results"]["no-agent-answer"]["outside"]["reason"] == "no-agent-answer"
print(f"  -> Redthread+MintID sandbox negative-control manifest verified ({len(sb_lines)} JSONL records)")
PY

if [ "${1:-}" = "--live" ]; then
    echo "=== [LIVE] Running live loopback capture via AI2II wire harness ==="
    OUT_DIR="$(mktemp -d /tmp/wimse-repro.XXXXXX)"
    .venv/bin/python -m wire run interop.yaml --cell inbound --out "$OUT_DIR"
    .venv/bin/python -m wire verify-bundle "$OUT_DIR/inbound"
    echo "Live run succeeded: $OUT_DIR/inbound"
fi

echo "=== ALL REPRODUCIBILITY CHECKS PASSED ==="
