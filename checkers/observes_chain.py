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
import hashlib
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


def _jwt_header(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) < 2:
        return {}
    b64 = parts[0] + "=" * (-len(parts[0]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))
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


def _b64url_sha256(token: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(token.strip().encode("ascii")).digest()).rstrip(b"=").decode("ascii")


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
    case_reasons: dict[str, set[str]] = defaultdict(set)
    b_chain_txns: set[str] = set()
    b_chain_ports: set[int] = set()
    b_chain_wpt_bound = False
    d2_www_auth_ok = False
    errors = 0

    for sid, sr in streams.items():
        for idx, (srcport, dstport, req) in enumerate(sr["reqs"]):
            req_lines = _extract_lines(req, "http.request.line")
            uri = _first_str(req.get("http.request.uri", ""))
            case_id = None
            txn_headers = []
            wit_header = None
            wpt_header = None
            for line in req_lines:
                ll = line.lower()
                if ll.startswith("x-test-case:"):
                    case_id = line.split(":", 1)[1].strip()
                elif ll.startswith("txn-token:"):
                    txn_headers.append(line.split(":", 1)[1].strip())
                elif ll.startswith("workload-identity-token:"):
                    wit_header = line.split(":", 1)[1].strip()
                elif ll.startswith("workload-proof-token:"):
                    wpt_header = line.split(":", 1)[1].strip()
                elif ll.startswith("authorization:"):
                    auth_val = line.split(":", 1)[1].strip()
                    if auth_val.upper().startswith("WPT "):
                        wpt_header = auth_val[4:].strip()

            # Cross-domain isolation check on all requests to Domain B ports
            if dstport in DOMAIN_B_PORTS:
                for tok in txn_headers:
                    hdr = _jwt_header(tok)
                    payload = _jwt_payload(tok)
                    is_domain_a_tok = (
                        payload.get("aud") == "maurice.ietf127.example"
                        or (
                            case_id != "C6"
                            and (
                                hdr.get("kid") == "tts_a-1"
                                or "maurice.ietf127.example" in str(payload.get("iss", ""))
                            )
                        )
                    )
                    if is_domain_a_tok:
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
            resp_body = _decode_body(resp)
            if isinstance(resp_body, dict):
                body_reason = resp_body.get("reason") or resp_body.get("error")
                if body_reason:
                    case_reasons[case_id].add(str(body_reason))
                elif status == 200:
                    case_reasons[case_id].add("accept")
            elif status == 200:
                case_reasons[case_id].add("accept")

            if case_id == "B_CHAIN":
                b_chain_ports.add(dstport)
                if isinstance(resp_body, dict) and resp_body.get("txn"):
                    b_chain_txns.add(str(resp_body["txn"]))
                for tok in txn_headers:
                    tp = _jwt_payload(tok)
                    if tp.get("txn"):
                        b_chain_txns.add(str(tp["txn"]))
                if dstport == 5063 and wit_header and wpt_header and txn_headers:
                    wpt_p = _jwt_payload(wpt_header)
                    if (
                        wpt_p.get("wth") == _b64url_sha256(wit_header)
                        and wpt_p.get("tth") == _b64url_sha256(txn_headers[0])
                    ):
                        b_chain_wpt_bound = True
                    else:
                        print(
                            f"FAIL B_CHAIN: WPT wth/tth SHA-256 binding mismatch on stream {sid}",
                            file=sys.stderr,
                        )
                        errors += 1

            elif case_id == "D2" and status == 401:
                www_auth = _first_str(resp.get("http.www_authenticate", ""))
                if not www_auth:
                    for line in _extract_lines(resp, "http.response.line"):
                        if line.lower().startswith("www-authenticate:"):
                            www_auth = line.split(":", 1)[1].strip()
                            break
                if "WPT" in www_auth:
                    d2_www_auth_ok = True

            elif case_id in ("C7", "C8"):
                if isinstance(resp_body, dict) and resp_body.get("leaked_credentials") is True:
                    print(f"FAIL {case_id}: leaked_credentials=True on stream {sid}", file=sys.stderr)
                    errors += 1
                if dstport == 5062 and "eyJ" in json.dumps(resp_body):
                    print(f"FAIL {case_id}: compact JWS leaked in response body on stream {sid}", file=sys.stderr)
                    errors += 1

    c10_seq = case_statuses.get("C10", [])
    if c10_seq and (200 not in c10_seq or 403 not in c10_seq or c10_seq.index(200) > c10_seq.index(403)):
        print(f"FAIL C10: expected 200 accept before 403 revoked, got {c10_seq}", file=sys.stderr)
        errors += 1

    for cid, spec in cases.items():
        observed = case_statuses.get(cid, [])
        if not observed:
            print(f"FAIL {cid}: missing from capture", file=sys.stderr)
            errors += 1
            continue
        if cid == "B_CHAIN" and set(observed) != {200}:
            print(
                f"FAIL B_CHAIN: expected all hops to return 200, observed non-200 in {observed}",
                file=sys.stderr,
            )
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
        exp_reason = spec.get("expected_reason")
        obs_reasons = case_reasons.get(cid, set())
        if exp_reason and exp_reason not in obs_reasons:
            print(
                f"FAIL {cid}: expected_reason {exp_reason!r} not in observed reasons {sorted(obs_reasons)}",
                file=sys.stderr,
            )
            errors += 1
            continue
        print(f"CHECK {cid} ref={spec['ref']} statuses={observed} reason={exp_reason}")

    # Verify B_CHAIN 3-agent ports, WPT binding, and unified txn UUID
    required_b_ports = {5050, 5051, 5060, 5061, 5062, 5063}
    if not required_b_ports.issubset(b_chain_ports):
        print(
            f"FAIL B_CHAIN: missing expected multi-agent hop ports {required_b_ports - b_chain_ports}",
            file=sys.stderr,
        )
        errors += 1
    if not b_chain_wpt_bound:
        print("FAIL B_CHAIN: missing verified WPT wth/tth SHA-256 binding on :5063", file=sys.stderr)
        errors += 1
    if not d2_www_auth_ok:
        print("FAIL D2: missing WWW-Authenticate: WPT challenge on 401 response", file=sys.stderr)
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
