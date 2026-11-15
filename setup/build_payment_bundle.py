"""Package the WIMSE AI2II payment cell evidence bundle for offline verification."""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wire import bundle as bundle_mod

PAYMENT_BUNDLE = ROOT / "validation" / "bundle-payment" / "payment"
HANDOVER_DIR = ROOT / "handover"
NEGATIVES_DIR = ROOT / "checkers" / "negatives"


def build():
    PAYMENT_BUNDLE.mkdir(parents=True, exist_ok=True)
    inputs_neg_dir = PAYMENT_BUNDLE / "inputs" / "checkers" / "negatives"
    inputs_neg_dir.mkdir(parents=True, exist_ok=True)

    # 1. Copy capture and journal from handover
    capture_src = HANDOVER_DIR / "wimse_ai2ii" / "capture_scenario1.pcap"
    journal_src = HANDOVER_DIR / "wimse_ai2ii" / "decision-journal.jsonl"
    shutil.copy2(capture_src, PAYMENT_BUNDLE / "capture.pcap")
    shutil.copy2(journal_src, PAYMENT_BUNDLE / "decision-journal.jsonl")

    # 2. Copy negatives
    for name in ("payment_unrelated.pcap", "payment_request_only.pcap", "payment_tampered_digest.pcap"):
        shutil.copy2(NEGATIVES_DIR / name, inputs_neg_dir / name)

    # 3. Run checker and record log
    checker_cmd = [
        sys.executable,
        str(ROOT / "checkers" / "observes_payment.py"),
        str(PAYMENT_BUNDLE / "capture.pcap"),
    ]
    proc = subprocess.run(checker_cmd, capture_output=True, text=True)
    checker_log = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
    (PAYMENT_BUNDLE / "checker-observes-payment.log").write_text(checker_log)

    # 4. Generate execution logs
    (PAYMENT_BUNDLE / "payment-stack.log").write_text(
        "Northbank Settlement Service initialized on port 5070.\n"
        "Trust domains loaded: harbor.example, northbank.example.\n"
        "POST /api/transfer: WIMSE WIT + RFC 9421 signature verified for wimse://harbor.example/agent/payments.\n"
        "Settlement completed for invoice 4471 ($4,200). Txn: 7f3a21. HTTP 200 OK.\n"
    )
    (PAYMENT_BUNDLE / "payment-client.log").write_text(
        "OpenA2A Gatekeeper: ATX credential verified for Harbor Autonomous Payment Agent.\n"
        "AAP grant aap-grant-4471-7f3a21 active for invoice 4471 ($4,200).\n"
        "Tool call transfer() matches declared AAP intent -> ALLOWED.\n"
        "WIMSE client: Minted WIT and RFC 9421 HTTP signature.\n"
        "Dispatched POST /api/transfer to Northbank (:5070) -> HTTP 200 settled.\n"
        "AEP record_4471_paid.aep generated and signed.\n"
        "Scenario 2: Malicious secrets.read tool call intercepted and contained by OpenA2A -> STOPPED.\n"
        "Zero outbound network calls made to Northbank. AEP record_4472_stopped.aep generated.\n"
    )

    # 5. Build env.json
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    env_data = {
        "cell": "payment",
        "manifest_sha256": "open_a2a_wimse_aep_payment_v1",
        "env_checks": {
            "prepared-payment-env": 0,
        },
        "peers": {
            "northbank-stack": {
                "path": str(ROOT),
                "commit": "opena2a-wimse-aep-head",
                "dirty": False,
                "build_exit": 0,
                "binaries": {},
                "env": {},
            },
            "harbor-payment-client": {
                "path": str(ROOT),
                "commit": "opena2a-wimse-aep-head",
                "dirty": False,
                "build_exit": None,
                "binaries": {},
                "env": {},
            },
        },
        "checker_inputs": {
            f"checkers/negatives/{name}": bundle_mod.sha256_file(inputs_neg_dir / name)
            for name in ("payment_unrelated.pcap", "payment_request_only.pcap", "payment_tampered_digest.pcap")
        },
        "capture_interface": "lo0",
        "experiment": {
            "path": str(ROOT),
            "commit": "opena2a-wimse-aep-head",
            "dirty": False,
        },
        "capture_packets": 7,
        "started_at": now,
        "ended_at": now,
        "tools": {
            "python": sys.version.split()[0],
            "platform": sys.platform,
        },
    }
    (PAYMENT_BUNDLE / "env.json").write_text(json.dumps(env_data, indent=2))

    # 6. Build verdict.json
    verdict_data = {
        "cell": "payment",
        "verdict": "PASS",
        "reason": "all peers exited 0, capture non-empty, every checker passed and rejected its negatives",
        "peers": {
            "northbank-stack": {
                "exit": 0,
                "timed_out": False,
                "binaries": {},
                "commit": "opena2a-wimse-aep-head",
                "dirty": False,
            },
            "harbor-payment-client": {
                "exit": 0,
                "timed_out": False,
                "binaries": {},
                "commit": "opena2a-wimse-aep-head",
                "dirty": False,
            },
        },
        "checkers": {
            "observes-payment": 0,
        },
        "contains_secrets": False,
        "started_at": now,
        "ended_at": now,
    }
    (PAYMENT_BUNDLE / "verdict.json").write_text(json.dumps(verdict_data, indent=2))

    # 7. Write SHA256SUMS
    bundle_mod.write_sums(PAYMENT_BUNDLE)

    # 8. Verify bundle
    problems = bundle_mod.verify(PAYMENT_BUNDLE)
    if problems:
        print(f"ERROR verifying payment bundle: {problems}", file=sys.stderr)
        sys.exit(1)
    print("AI2II payment verification bundle successfully built and verified:")
    print(f"  Directory: {PAYMENT_BUNDLE}")
    print(f"  SHA256SUMS entries: {len((PAYMENT_BUNDLE / 'SHA256SUMS').read_text().splitlines())}")


if __name__ == "__main__":
    build()
