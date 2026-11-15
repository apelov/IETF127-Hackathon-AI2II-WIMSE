#!/usr/bin/env python3
"""Independent multi-hop wire-evidence checker for WIMSE 3-agent cross-domain call chain.

Decodes HTTP on TCP ports 5050, 5051, 5060, 5061, 5062, 5063 via tshark, groups
request/response pairs per tcp.stream, maps them to chain_cases.json via X-Test-Case,
verifies cross-domain Txn-Token isolation (no Domain A Txn-Token on ports 5060..5063),
and verifies end-to-end txn ID correlation in B_CHAIN.

Usage:
    python3 checkers/observes_chain.py <capture.pcap>
"""
import argparse
import base64
import json
import pathlib
import subprocess
import sys
from collections import defaultdict
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHAIN_CASES_PATH = ROOT / "chain_cases.json"
CHAIN_PORTS = (5050, 5051, 5060, 5061, 5062, 5063)
DOMAIN_B_PORTS = {5060, 5061, 5062, 5063}


def _collect_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            existing = result[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                result[key] = [existing, value]
        else:
            result[key] = value
    return result


def _first_str(val: Any) -> str:
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val) if val is not None else ""


def _extract_status(http_layer: dict) -> int:
    if "http.response.code" in http_layer:
        try:
            return int(_first_str(http_layer["http.response.code"]))
        except ValueError:
            pass
    for v in http_layer.values():
        if isinstance(v, dict) and "http.response.code" in v:
            try:
                return int(_first_str(v["http.response.code"]))
            except ValueError:
                pass
    return 0


def _is_request(http_layer: dict) -> bool:
    if "http.request" in http_layer or "http.request.method" in http_layer:
        return True
    return any(isinstance(v, dict) and "http.request.method" in v for v in http_layer.values())


def _extract_lines(http_layer: dict, key: str) -> list[str]:
    raw = http_layer.get(key, [])
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        out = []
        for item in raw:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, list):
                out.extend(str(x) for x in item)
        return out
    return []


def _decode_body(http_layer: dict) -> dict:
    raw = _first_str(http_layer.get("http.file_data", ""))
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        try:
            cleaned = raw.replace(":", "")
            return json.loads(bytes.fromhex(cleaned).decode("utf-8", errors="replace"))
        except Exception:
            return {}


def _jwt_payload(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {}
    b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))
    except Exception:
        return {}


def verify_capture(capture_path: pathlib.Path) -> None:
    cases = {c["id"]: c for c in json.loads(CHAIN_CASES_PATH.read_text())}
    cmd = ["tshark", "-r", str(capture_path)]
    for p in CHAIN_PORTS:
        cmd.extend(["-d", f"tcp.port=={p},http"])
    cmd.extend(["-Y", "http", "-T", "json", "-o", "tcp.relative_sequence_numbers:FALSE"])

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        print("FAIL: no HTTP packets decoded from capture", file=sys.stderr)
        raise SystemExit(1)

    packets = json.loads(proc.stdout, object_pairs_hook=_collect_duplicates)
    streams: dict[str, dict[str, list[tuple[int, int, dict]]]] = defaultdict(
        lambda: {"reqs": [], "resps": []}
    )

    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        tcp = layers.get("tcp", {})
        if isinstance(tcp, list):
            tcp = tcp[0] if tcp else {}
        http = layers.get("http", {})
        if isinstance(http, list):
            http = http[-1]
        if not isinstance(http, dict):
            continue
        sid = _first_str(tcp.get("tcp.stream", ""))
        srcport = int(_first_str(tcp.get("tcp.srcport", "0")) or 0)
        dstport = int(_first_str(tcp.get("tcp.dstport", "0")) or 0)
        if not sid:
            continue
        if _is_request(http):
            streams[sid]["reqs"].append((srcport, dstport, http))
        elif _extract_status(http) > 0:
            streams[sid]["resps"].append((srcport, dstport, http))

    case_statuses: dict[str, list[int]] = defaultdict(list)
    b_chain_txns: set[str] = set()
    b_chain_ports: set[int] = set()
    errors = 0

    for sid, sr in streams.items():
        for idx, (srcport, dstport, req) in enumerate(sr["reqs"]):
            req_lines = _extract_lines(req, "http.request.line")
            uri = _first_str(req.get("http.request.uri", ""))
            case_id = None
            txn_headers = []
            for line in req_lines:
                ll = line.lower()
                if ll.startswith("x-test-case:"):
                    case_id = line.split(":", 1)[1].strip()
                elif ll.startswith("txn-token:"):
                    txn_headers.append(line.split(":", 1)[1].strip())

            # Cross-domain isolation check on all requests to Domain B ports
            if dstport in DOMAIN_B_PORTS:
                for tok in txn_headers:
                    payload = _jwt_payload(tok)
                    if payload.get("aud") == "maurice.ietf127.example":
                        print(
                            f"FAIL: Domain A Txn-Token leaked to Domain B port {dstport} on stream {sid}",
                            file=sys.stderr,
                        )
                        raise SystemExit(1)

            # Skip untagged readiness probes
            if not case_id:
                if "/.well-known/wimse/jwks.json" in uri or "/health" in uri:
                    continue
                continue

            if idx >= len(sr["resps"]):
                print(
                    f"FAIL {case_id}: request on stream {sid} (dstport {dstport}) has no response",
                    file=sys.stderr,
                )
                errors += 1
                continue

            _, _, resp = sr["resps"][idx]
            status = _extract_status(resp)
            case_statuses[case_id].append(status)

            if case_id == "B_CHAIN":
                b_chain_ports.add(dstport)
                resp_body = _decode_body(resp)
                if isinstance(resp_body, dict) and resp_body.get("txn"):
                    b_chain_txns.add(str(resp_body["txn"]))

    for cid, spec in cases.items():
        observed = case_statuses.get(cid, [])
        if not observed:
            print(f"FAIL {cid}: missing from capture", file=sys.stderr)
            errors += 1
            continue
        exp_set = set(spec["expected_statuses"])
        if not exp_set.issubset(set(observed)):
            print(
                f"FAIL {cid}: expected statuses {sorted(exp_set)} not all in observed {observed}",
                file=sys.stderr,
            )
            errors += 1
            continue
        print(f"CHECK {cid} ref={spec['ref']} statuses={observed}")

    # Verify B_CHAIN 3-agent ports and unified txn UUID
    required_b_ports = {5051, 5060, 5061, 5062, 5063}
    if not required_b_ports.issubset(b_chain_ports):
        print(
            f"FAIL B_CHAIN: missing expected multi-agent hop ports {required_b_ports - b_chain_ports}",
            file=sys.stderr,
        )
        errors += 1
    if len(b_chain_txns) != 1:
        print(
            f"FAIL B_CHAIN: expected exactly 1 unified txn UUID across hops, got {b_chain_txns}",
            file=sys.stderr,
        )
        errors += 1

    print(f"SUMMARY cases={len(cases)} errors={errors}")
    if errors > 0:
        raise SystemExit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=pathlib.Path)
    args = ap.parse_args()
    verify_capture(args.capture)


if __name__ == "__main__":
    main()
