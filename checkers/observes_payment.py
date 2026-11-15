#!/usr/bin/env python3
"""Independent packet checker for WIMSE AI2II cross-domain payment bridge.

AI2II Rule L4: Authored independently to inspect raw .pcap captures via tshark
without reading driver or server logs. Verifies the Harbor -> Northbank cross-domain
payment wire traffic on TCP port 5070 and rejects negative mutants.

Usage:
    python3 checkers/observes_payment.py <capture.pcap>
"""
import argparse
import json
import pathlib
import subprocess
import sys


def parse_pcap(pcap_path: pathlib.Path) -> list[dict]:
    cmd = [
        "tshark",
        "-r", str(pcap_path),
        "-Y", "http",
        "-T", "json",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"tshark error: {exc.stderr}")

    try:
        return json.loads(proc.stdout) if proc.stdout.strip() else []
    except json.JSONDecodeError:
        return []


def get_raw_tcp_payload(tcp_layer: dict) -> str:
    hex_payload = tcp_layer.get("tcp.payload", "")
    if not hex_payload:
        return ""
    try:
        return bytes.fromhex(hex_payload.replace(":", "")).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def main():
    parser = argparse.ArgumentParser(description="Check WIMSE payment cross-domain capture")
    parser.add_argument("capture", type=pathlib.Path, help="Path to pcap capture file")
    args = parser.parse_args()

    if not args.capture.is_file():
        print(f"Error: capture file not found: {args.capture}", file=sys.stderr)
        sys.exit(1)

    packets = parse_pcap(args.capture)
    if not packets:
        print(f"FAIL: No HTTP packets found in {args.capture}", file=sys.stderr)
        sys.exit(1)

    found_request = False
    found_response = False
    valid_wit = False
    valid_sig = False
    valid_txn = False
    valid_payload = False
    valid_status = False

    for item in packets:
        layers = item.get("_source", {}).get("layers", {})
        http = layers.get("http", {})
        tcp = layers.get("tcp", {})

        src_port = tcp.get("tcp.srcport")
        dst_port = tcp.get("tcp.dstport")

        # Must involve port 5070
        if "5070" not in (src_port, dst_port):
            continue

        raw_payload = get_raw_tcp_payload(tcp)
        http_str = json.dumps(http) + " " + raw_payload

        # Check HTTP request
        is_req = (
            "http.request" in http
            or "http.request.method" in http
            or any("POST " in k for k in http)
            or raw_payload.startswith("POST /api/transfer")
        )
        if is_req and "/api/transfer" in http_str:
            found_request = True
            raw_lower = http_str.lower()

            if "workload-identity-token:" in raw_lower:
                valid_wit = True

            if 'tag="wimse-workload-to-workload"' in http_str and 'wimse-aud="wimse://northbank.example/api/transfer"' in http_str:
                valid_sig = True

            if "txn-token:" in raw_lower and "7f3a21" in http_str:
                valid_txn = True

            if "4471" in http_str and "4200" in http_str:
                valid_payload = True

        # Check HTTP response
        is_resp = (
            "http.response" in http
            or "http.response.code" in http
            or any("200 OK" in k for k in http)
            or raw_payload.startswith("HTTP/1.1 200")
        )
        if is_resp and ("200" in http_str or "200 OK" in raw_payload):
            found_response = True
            if "paid" in http_str:
                valid_status = True

    print(f"Checker observes_payment: pcap={args.capture.name}")
    print(f"  found_request  : {found_request}")
    print(f"  valid_wit      : {valid_wit}")
    print(f"  valid_sig      : {valid_sig}")
    print(f"  valid_txn      : {valid_txn}")
    print(f"  valid_payload  : {valid_payload}")
    print(f"  found_response : {found_response}")
    print(f"  valid_status   : {valid_status}")

    if not (found_request and valid_wit and valid_sig and valid_txn and valid_payload and found_response and valid_status):
        print("FAIL: One or more WIMSE payment criteria failed", file=sys.stderr)
        sys.exit(1)

    print("PASS: Cross-domain WIMSE payment wire exchange verified under AI2II Rule L4")
    sys.exit(0)


if __name__ == "__main__":
    main()
