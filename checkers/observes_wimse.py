#!/usr/bin/env python3
"""
Independent wire-evidence checker for WIMSE interoperability experiment.

Reads a pcap, decodes HTTP on TCP port 5050 via tshark, maps requests to cases.json
via X-Test-Case header, and verifies exact case expectations.

Usage:
    python3 checkers/observes_wimse.py <capture.pcap> [--cases ID1,ID2,...]
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys
from collections import defaultdict
from typing import Any, Optional

ROOT = pathlib.Path(__file__).resolve().parent.parent
CASES_PATH = ROOT / "cases.json"
PTYPE_PREFIX = "https://iana.org/assignments/http-problem-types#"

ROUTE_PATTERN = re.compile(r"^/api/v2/agents/[^/]+/workflows/[^/]+/executions$")

NO_FETCH_PORT = 47999


def load_cases() -> dict[str, dict]:
    """Load and index cases from cases.json."""
    data = json.loads(CASES_PATH.read_text())
    return {c["id"]: c for c in data["cases"]}


def parse_tshark_json(capture_path: pathlib.Path) -> list[dict]:
    """Run tshark and parse JSON output for HTTP on port 5050."""
    cmd = [
        "tshark",
        "-r", str(capture_path),
        "-d", "tcp.port==5050,http",
        "-Y", "http",
        "-T", "json",
        "-o", "tcp.relative_sequence_numbers:FALSE",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise ValueError(f"tshark failed: {proc.stderr.strip() or 'unknown error'}")
    if not proc.stdout.strip():
        raise ValueError("tshark produced no output (empty capture or no HTTP on port 5050)")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ValueError(f"tshark output is not valid JSON: {e}")


def parse_tshark_all_tcp(capture_path: pathlib.Path) -> list[dict]:
    """Run tshark and parse JSON output for ALL TCP packets (for no-fetch port check)."""
    cmd = [
        "tshark",
        "-r", str(capture_path),
        "-Y", "tcp",
        "-T", "json",
        "-o", "tcp.relative_sequence_numbers:FALSE",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise ValueError(f"tshark (all TCP) failed: {proc.stderr.strip() or 'unknown error'}")
    if not proc.stdout.strip():
        return []
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ValueError(f"tshark all-TCP output is not valid JSON: {e}")


def get_http_layer(layers: dict) -> Optional[dict]:
    """Extract HTTP layer from tshark packet layers, handling duplicate keys."""
    http = layers.get("http")
    if isinstance(http, list):
        for h in http:
            if isinstance(h, dict):
                return h
        return None
    return http if isinstance(http, dict) else None


def get_tcp_stream(layers: dict) -> Optional[str]:
    """Extract TCP stream index, handling duplicate keys."""
    tcp = layers.get("tcp")
    if isinstance(tcp, list):
        for t in tcp:
            if isinstance(t, dict) and "tcp.stream" in t:
                return t["tcp.stream"]
        return None
    if isinstance(tcp, dict):
        return tcp.get("tcp.stream")
    return None


def get_tcp_dstport(layers: dict) -> Optional[int]:
    """Extract TCP destination port, handling duplicate keys."""
    tcp = layers.get("tcp")
    if isinstance(tcp, list):
        for t in tcp:
            if isinstance(t, dict) and "tcp.dstport" in t:
                try:
                    return int(t["tcp.dstport"])
                except (ValueError, TypeError):
                    pass
        return None
    if isinstance(tcp, dict):
        try:
            return int(tcp.get("tcp.dstport", 0))
        except (ValueError, TypeError):
            return None
    return None


def extract_header_from_lines(lines: Any, header_name: str) -> Optional[str]:
    """Extract a header value from http.request.line or http.response.line array."""
    prefix = header_name.lower() + ":"
    if isinstance(lines, list):
        for line in lines:
            if isinstance(line, str) and line.lower().startswith(prefix):
                return line.split(":", 1)[1].strip()
    elif isinstance(lines, str) and lines.lower().startswith(prefix):
        return lines.split(":", 1)[1].strip()
    return None


def find_request_dict(http_layer: dict) -> Optional[dict]:
    """Find the nested dict containing http.request.method in HTTP layer."""
    for v in http_layer.values():
        if isinstance(v, dict) and ("http.request.method" in v or any(k.endswith(".http.request.method") for k in v)):
            return v
    return None


def find_response_dict(http_layer: dict) -> Optional[dict]:
    """Find the nested dict containing http.response.code in HTTP layer."""
    for v in http_layer.values():
        if isinstance(v, dict) and ("http.response.code" in v or any(k.endswith(".http.response.code") for k in v)):
            return v
    return None


def extract_header_value(http_layer: dict, header_name: str) -> Optional[str]:
    """Extract a header value from HTTP layer, handling duplicate field keys."""
    # tshark represents headers as http.header_name or in http.request.line / http.response.line
    key = f"http.{header_name.lower()}"
    val = http_layer.get(key)
    if isinstance(val, list):
        return val[-1] if val else None
    if isinstance(val, str):
        return val
    # Fallback: scan request/response lines
    req_lines = http_layer.get("http.request.line")
    resp_lines = http_layer.get("http.response.line")
    result = extract_header_from_lines(req_lines, header_name)
    if result is not None:
        return result
    return extract_header_from_lines(resp_lines, header_name)


def _get_value_from_dict(d: dict, key: str) -> Any:
    """Get value from dict, checking for exact key or key ending with .key."""
    if key in d:
        return d[key]
    for k, v in d.items():
        if k.endswith("." + key):
            return v
    return None


def extract_request_info(http_layer: dict) -> Optional[dict]:
    """Extract request method, URI, X-Test-Case, and body from HTTP layer."""
    req_dict = find_request_dict(http_layer)
    if not req_dict:
        return None

    method = _get_value_from_dict(req_dict, "http.request.method")
    if isinstance(method, list):
        method = method[0] if method else None
    uri = _get_value_from_dict(req_dict, "http.request.uri")
    if isinstance(uri, list):
        uri = uri[0] if uri else None

    if not method or not uri:
        return None

    # Extract X-Test-Case from request lines
    req_lines = http_layer.get("http.request.line")
    case_id = extract_header_from_lines(req_lines, "X-Test-Case")

    # Extract body from http.file_data (hex-encoded)
    body = None
    file_data = http_layer.get("http.file_data")
    if isinstance(file_data, list):
        file_data = file_data[0] if file_data else None
    if isinstance(file_data, str):
        try:
            body = json.loads(bytes.fromhex(file_data.replace(":", "")).decode())
        except (ValueError, UnicodeDecodeError):
            body = None

    return {"method": method, "uri": uri, "case_id": case_id, "body": body}


def extract_response_info(http_layer: dict) -> Optional[dict]:
    """Extract response status, body, and WWW-Authenticate from HTTP layer."""
    resp_dict = find_response_dict(http_layer)
    if not resp_dict:
        return None

    status = _get_value_from_dict(resp_dict, "http.response.code")
    if isinstance(status, list):
        status = status[0] if status else None
    if status is None:
        return None
    try:
        status = int(status)
    except (ValueError, TypeError):
        return None

    # Extract body
    body = None
    file_data = http_layer.get("http.file_data")
    if isinstance(file_data, list):
        file_data = file_data[0] if file_data else None
    if isinstance(file_data, str):
        try:
            body = json.loads(bytes.fromhex(file_data.replace(":", "")).decode())
        except (ValueError, UnicodeDecodeError):
            body = None

    # Extract WWW-Authenticate - try direct field first, then response lines
    www_auth = None
    # tshark may provide www_authenticate as direct field http.www_authenticate
    www_auth_direct = http_layer.get("http.www_authenticate")
    if isinstance(www_auth_direct, list):
        www_auth = www_auth_direct[-1] if www_auth_direct else None
    elif isinstance(www_auth_direct, str):
        www_auth = www_auth_direct

    # Fallback: scan response lines
    if not www_auth:
        resp_lines = http_layer.get("http.response.line")
        www_auth = extract_header_from_lines(resp_lines, "WWW-Authenticate")

    return {"status": status, "body": body, "www_authenticate": www_auth}


def is_request(http_layer: dict) -> bool:
    """Check if HTTP layer is a request."""
    return find_request_dict(http_layer) is not None


def is_response(http_layer: dict) -> bool:
    """Check if HTTP layer is a response."""
    return find_response_dict(http_layer) is not None


def build_exchanges(packets: list[dict]) -> tuple[dict[str, list[tuple[dict, dict]]], list[str]]:
    """
    Build request/response pairs per TCP stream.
    Returns (exchanges, errors) where exchanges is dict: stream_id -> list of (request_info, response_info)
    and errors contains unpaired request/response errors per stream.
    """
    streams: dict[str, list[dict]] = defaultdict(list)
    errors = []

    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        http = get_http_layer(layers)
        if not http:
            continue

        stream = get_tcp_stream(layers)
        if stream is None:
            continue

        if is_request(http):
            req = extract_request_info(http)
            if req:
                streams[stream].append(("request", req))
        elif is_response(http):
            resp = extract_response_info(http)
            if resp:
                streams[stream].append(("response", resp))

    # Pair up requests and responses in order, track unpaired
    exchanges = {}
    for stream, items in streams.items():
        pairs = []
        pending_req = None
        for kind, info in items:
            if kind == "request":
                if pending_req is not None:
                    # Previous request had no response - unpaired request
                    case_id = pending_req.get("case_id", "unknown")
                    errors.append(f"FAIL stream {stream}: unpaired request for case {case_id!r} (no response)")
                pending_req = info
            elif kind == "response":
                if pending_req is not None:
                    pairs.append((pending_req, info))
                    pending_req = None
                else:
                    # Response without request - unpaired response
                    errors.append(f"FAIL stream {stream}: unpaired response (no matching request)")
        if pending_req is not None:
            # Request without response - unpaired request
            case_id = pending_req.get("case_id", "unknown")
            errors.append(f"FAIL stream {stream}: unpaired request for case {case_id!r} (no response)")
        if pairs:
            exchanges[stream] = pairs

    return exchanges, errors


def check_no_fetch_port(capture_path: pathlib.Path, case_ids: set[str]) -> list[str]:
    """Check for TCP traffic to port 47999 for C12/C12b cases.

    Uses a separate tshark query over ALL TCP packets (not just HTTP)
    to detect connections to the forbidden port.
    """
    errors = []
    if "C12" in case_ids or "C12b" in case_ids:
        try:
            all_tcp_packets = parse_tshark_all_tcp(capture_path)
        except ValueError as e:
            errors.append(f"FAIL: could not analyze TCP traffic for no-fetch check: {e}")
            return errors

        for packet in all_tcp_packets:
            layers = packet.get("_source", {}).get("layers", {})
            dstport = get_tcp_dstport(layers)
            if dstport == NO_FETCH_PORT:
                errors.append(f"FAIL: capture contains TCP traffic to forbidden port {NO_FETCH_PORT} (violates C12/C12b no-fetch requirement)")
                break
    return errors


def validate_capture(packets: list[dict], exchanges: dict) -> list[str]:
    """Validate capture is not empty or unrelated."""
    errors = []

    if not packets:
        errors.append("FAIL: empty capture (no packets)")
        return errors

    if not exchanges:
        errors.append("FAIL: no complete HTTP request/response exchanges found on port 5050")
        return errors

    return errors


def check_case(case_id: str, case: dict, responses: list[dict], errors: list[str]) -> None:
    """Verify a single case's responses match expectations."""
    expected_steps = case.get("steps", [])
    actual_responses = responses

    if len(actual_responses) != len(expected_steps):
        errors.append(f"FAIL {case_id}: expected {len(expected_steps)} step(s), got {len(actual_responses)}")
        return

    ref = case.get("ref", "")
    title = case.get("title", "")

    for step_idx, (resp, exp) in enumerate(zip(actual_responses, expected_steps), 1):
        # Check status
        expected_statuses = exp.get("status", [])
        if resp["status"] not in expected_statuses:
            errors.append(
                f"FAIL {case_id} (ref={ref}) step {step_idx}: status {resp['status']} not in expected {expected_statuses}"
            )

        # Check problem type
        if "type" in exp:
            expected_type = PTYPE_PREFIX + exp["type"]
            actual_type = (resp.get("body") or {}).get("type")
            if actual_type != expected_type:
                errors.append(
                    f"FAIL {case_id} (ref={ref}) step {step_idx}: problem type '{actual_type}' != expected '{expected_type}'"
                )

        # Check WWW-Authenticate
        if "www_authenticate" in exp:
            expected_auth = exp["www_authenticate"]
            actual_auth = resp.get("www_authenticate") or ""
            if expected_auth.lower() not in actual_auth.lower():
                errors.append(
                    f"FAIL {case_id} (ref={ref}) step {step_idx}: missing WWW-Authenticate '{expected_auth}' (got '{actual_auth}')"
                )

        # Print draft/test reference per case per step
        print(f"CHECK {case_id} ref={ref} title={title!r} step={step_idx} status={resp['status']} expected={expected_statuses}")


def main() -> int:
    ap = argparse.ArgumentParser(description="WIMSE wire-evidence checker")
    ap.add_argument("capture", type=pathlib.Path, help="Path to pcap file")
    ap.add_argument("--cases", default="all", help="Comma-separated case IDs, or 'all'")
    args = ap.parse_args()

    if not args.capture.exists():
        print(f"FAIL: capture file not found: {args.capture}", file=sys.stderr)
        return 1

    all_cases = load_cases()

    if args.cases == "all":
        case_ids = list(all_cases.keys())
    else:
        case_ids = [c.strip() for c in args.cases.split(",") if c.strip()]

    unknown = set(case_ids) - set(all_cases.keys())
    if unknown:
        print(f"FAIL: unknown case IDs: {sorted(unknown)}", file=sys.stderr)
        return 1

    try:
        packets = parse_tshark_json(args.capture)
    except ValueError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1

    # Check for forbidden port traffic (C12/C12b) - uses separate tshark query over ALL TCP
    errors = check_no_fetch_port(args.capture, set(case_ids))

    # Build exchanges (also returns unpaired request/response errors)
    exchanges, exchange_errors = build_exchanges(packets)
    errors.extend(exchange_errors)

    # Validate capture quality (basic checks only)
    errors.extend(validate_capture(packets, exchanges))

    # Map responses by case_id
    seen: dict[str, list[dict]] = defaultdict(list)
    for stream, pairs in exchanges.items():
        for req, resp in pairs:
            case_id = req.get("case_id")
            if not case_id:
                errors.append(f"FAIL stream {stream}: request missing X-Test-Case header")
                continue
            if case_id not in case_ids:
                errors.append(f"FAIL stream {stream}: unexpected case ID {case_id!r} (not in requested set)")
                continue
            # Verify POST route
            if req["method"] != "POST":
                errors.append(f"FAIL {case_id}: expected POST, got {req['method']}")
                continue
            if not ROUTE_PATTERN.match(req["uri"] or ""):
                errors.append(f"FAIL {case_id}: unexpected route {req['uri']!r} (expected /api/v2/agents/{{agent}}/workflows/{{workflow}}/executions)")
                continue
            seen[case_id].append(resp)

    # Check each requested case
    for case_id in case_ids:
        case = all_cases[case_id]
        responses = seen.get(case_id, [])
        check_case(case_id, case, responses, errors)

    # Check for missing cases (no requests seen)
    for case_id in case_ids:
        if case_id not in seen:
            errors.append(f"FAIL {case_id}: no requests found in capture")

    for error in errors:
        print(error, file=sys.stderr)

    print(f"SUMMARY cases={len(case_ids)} errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())