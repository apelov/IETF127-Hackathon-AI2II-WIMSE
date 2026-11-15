#!/usr/bin/env python3
"""Independent wire & manifest checker for extended WIMSE scenarios P1-P8 (ietf127-wimse-scenario/1).

Usage:
    python3 checkers/observes_p1_p8.py --verify-manifests scenarios/p1_p8
    python3 checkers/observes_p1_p8.py <capture.pcap>
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCENARIOS_DIR = ROOT / "scenarios" / "p1_p8"

REQUIRED_FIELDS = {"scenario", "case", "impl", "hop", "domain", "txn_id", "decision", "reason", "ts"}

EXPECTED_LIVE_CASES = {
    "P2_revoke-upstream": {"status": 403, "decision": "deny", "reason": "status-revoked", "bound_s": 120},
    "P2_before-effect": {"status": 403, "decision": "deny", "reason": "status-revoked", "effect": "none", "bound_s": 120},
    "P2_outside-made-up-proof": {"status": 403, "decision": "deny", "reason": "proof_invalid", "effect": "none"},
    "P2_outside-no-agent-answer": {"status": 403, "decision": "deny", "reason": "no-agent-answer", "effect": "none"},
    "P7_display-match": {"status": 200, "decision": "allow", "reason": "ok", "effect": "ran", "ts": 1800000000},
    "P7_display-mismatch": {"status": 403, "decision": "deny", "reason": "display-mismatch", "effect": "none", "ts": 1800000000},
    "P8_no-delegation": {"status": 403, "decision": "deny", "reason": "no-delegation", "token_released": False},
    "P8_write-under-read": {"status": 403, "decision": "deny", "reason": "scope-exceeded", "token_released": False},
    "P8_revoked-between-authz-and-use": {"status": 403, "decision": "deny", "reason": "status-revoked", "token_released": False},
    "P8_revoked-after-token-released": {"status": 200, "reason": "token-released", "token_released": True},
}


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


def _parse_iso(ts_str: str) -> float:
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()


def verify_manifests(sdir: pathlib.Path) -> None:
    # 1. Verify Redthread P1-P6 local manifest & 22 cases
    rt_manifest = json.loads((sdir / "redthread-local.manifest.json").read_text())
    assert rt_manifest.get("clock") == "simulated", "Redthread clock must be labeled simulated"
    for fname, expected_sha in rt_manifest["sha256"].items():
        actual = hashlib.sha256((sdir / fname).read_bytes()).hexdigest()
        if actual != expected_sha:
            raise ValueError(f"SHA256 mismatch on {fname}: {actual} != {expected_sha}")

    results = rt_manifest.get("results", [])
    if len(results) != 22 or not all(r.get("match") is True for r in results):
        raise ValueError(f"Expected 22/22 matching Redthread cases, got {len(results)}")

    p1_reasons = set()
    p2_rows = []
    for scn, fname in rt_manifest["files"].items():
        for line in (sdir / fname).read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            missing = REQUIRED_FIELDS - set(row.keys())
            if missing:
                raise ValueError(f"{fname} missing required fields {missing}")
            if scn == "P1":
                p1_reasons.add(row["reason"])
                for rec_item in row.get("record", []) or []:
                    p1_reasons.add(rec_item)
            elif scn == "P2":
                p2_rows.append(row)

    for req_reason in ("status-revoked", "status-stale", "status-unavailable", "status-grace"):
        if req_reason not in p1_reasons:
            raise ValueError(f"P1 missing distinct reason {req_reason}")

    # P2 checks: bound_s == 120, revoke-upstream 50s allow -> 51s deny, before-effect authorize(pending) -> before-effect(deny, 0ms)
    if not any(r.get("bound_s") == 120 for r in p2_rows):
        raise ValueError("P2 missing bound_s == 120")
    up_allow = [r for r in p2_rows if r["case"] == "revoke-upstream" and r["decision"] == "allow"]
    up_deny = [r for r in p2_rows if r["case"] == "revoke-upstream" and r["decision"] == "deny"]
    if not up_allow or not up_deny:
        raise ValueError("P2 revoke-upstream missing allow/deny transition")
    be_auth = [r for r in p2_rows if r["case"] == "before-effect" and r.get("check") == "authorize" and r.get("effect") == "pending"]
    be_recheck = [
        r for r in p2_rows
        if r["case"] == "before-effect" and r.get("check") == "before-effect"
        and r.get("decision") == "deny" and r.get("reason") == "status-revoked"
        and r.get("effect") == "none" and r.get("t_since_revocation_ms") == 0
    ]
    if not be_auth or not be_recheck:
        raise ValueError("P2 before-effect missing authorize(pending) -> before-effect(deny, 0ms)")

    # 2. Verify MintID Nov 14 testnet manifest, dual time origins, and witness-refresh control
    p2_spec = json.loads((sdir / "P2-revocation-after-delegation-before-effect.json").read_text())
    mintid_spec = next(x for x in p2_spec["implementations_offered"] if "MintID" in x["impl"])
    if mintid_spec.get("proof_lifetime_s") != 10:
        raise ValueError("MintID proof_lifetime_s must be 10")
    if mintid_spec["bounds_s"]["issuer_revocation"] != 185 or mintid_spec["bounds_s"]["holder_self_revocation"] != 245:
        raise ValueError("MintID bounds must be 185s issuer / 245s holder")

    mi_manifest = json.loads((sdir / "revocation-trace-testnet-20261114T104257Z.manifest.json").read_text())
    if mi_manifest["source"]["tracked_changes"] is not False:
        raise ValueError("MintID manifest tracked_changes must be False")
    for fname, expected_sha in mi_manifest["files"].items():
        actual = hashlib.sha256((sdir / fname).read_bytes()).hexdigest()
        if actual != expected_sha:
            raise ValueError(f"MintID SHA256 mismatch on {fname}")

    mi_events = [json.loads(l) for l in (sdir / "revocation-trace-testnet-20261114T104257Z.jsonl").read_text().splitlines() if l.strip()]
    # Check witness-refresh control: holder_refresh refused for revoked agent while sibling_control is accepted
    revoked_refresh = [
        e for e in mi_events
        if e.get("kind") == "holder_refresh" and e.get("outcome") == "credential_revoked"
    ]
    sibling_accepted = [
        e for e in mi_events
        if e.get("agent") == "sibling_control" and (e.get("accepted") is True or e.get("outcome") == "refreshed")
    ]
    if not revoked_refresh or not sibling_accepted:
        raise ValueError("MintID witness-refresh attribution control missing")

    # Verify cascade dual time origins (issuer revoke response 10:44:27.096Z vs trigger root 10:44:41Z, ~13.9s delta)
    summary_ev = next(e for e in mi_events if e.get("kind") == "summary")
    cascade_res = next(r for r in summary_ev["results"] if r.get("path") == "cascade")
    t_revoke = float(cascade_res["trigger_request_unix"])
    t_root = float(cascade_res["t0"])
    delta = round(t_root - t_revoke, 1)
    if not (13.5 <= delta <= 14.5):
        raise ValueError(f"Expected ~13.9s delta between cascade revoke response and trigger root, got {delta}s")

    # 3. Verify Redthread + MintID live sandbox negative control manifest & JSONL
    sb_manifest = json.loads((sdir / "redthread-P2-mintid-sandbox-negative.manifest.json").read_text())
    sb_rows = [json.loads(l) for l in (sdir / "redthread-P2-mintid-sandbox-negative.jsonl").read_text().splitlines() if l.strip()]
    if len(sb_rows) != sb_manifest["lines"] or len(sb_rows) != 4:
        raise ValueError("Sandbox negative control line count mismatch")
    res_made_up = sb_manifest["results"]["made-up-proof"]
    res_no_ans = sb_manifest["results"]["no-agent-answer"]
    if res_made_up["outside"]["reason"] != "proof_invalid" or res_made_up["outside"]["session_id"] != "01eac0157bbfc1f54af295fadb53dafc" or res_made_up["effect"] != "none":
        raise ValueError("outside-made-up-proof verification failed")
    if res_no_ans["outside"]["reason"] != "no-agent-answer" or res_no_ans["outside"]["session_id"] != "ea27daa1d8be8f59a1c5e43963facc2d" or res_no_ans["effect"] != "none":
        raise ValueError("outside-no-agent-answer verification failed")


def _first_str(val: Any) -> str:
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val) if val is not None else ""


def _extract_status(http_layer: dict) -> int:
    if "http.response.code" in http_layer:
        return int(_first_str(http_layer["http.response.code"]))
    for v in http_layer.values():
        if isinstance(v, dict) and "http.response.code" in v:
            return int(_first_str(v["http.response.code"]))
    return 0


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


def verify_capture(capture_path: pathlib.Path) -> None:
    verify_manifests(SCENARIOS_DIR)
    cmd = [
        "tshark",
        "-r", str(capture_path),
        "-d", "tcp.port==5064,http",
        "-Y", "http",
        "-T", "json",
        "-o", "tcp.relative_sequence_numbers:FALSE",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise ValueError("No HTTP traffic decoded on port 5064")
    packets = json.loads(proc.stdout, object_pairs_hook=_collect_duplicates)

    streams: dict[str, dict[str, list[dict]]] = defaultdict(lambda: {"reqs": [], "resps": []})
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
        if not sid:
            continue
        if "http.request" in http or any(isinstance(v, dict) and "http.request.method" in v for v in http.values()):
            streams[sid]["reqs"].append(http)
        elif "http.response" in http or _extract_status(http) > 0:
            streams[sid]["resps"].append(http)

    observed: dict[str, tuple[int, dict]] = {}
    errors = 0
    for sid, sr in streams.items():
        for idx, req in enumerate(sr["reqs"]):
            case_id = None
            for line in _extract_lines(req, "http.request.line"):
                if line.lower().startswith("x-test-case:"):
                    case_id = line.split(":", 1)[1].strip()
                    break
            if not case_id or case_id not in EXPECTED_LIVE_CASES:
                continue
            if case_id in observed:
                print(f"FAIL {case_id}: duplicate X-Test-Case on stream {sid}", file=sys.stderr)
                errors += 1
                continue
            if idx >= len(sr["resps"]):
                print(f"FAIL {case_id}: request on stream {sid} has no response", file=sys.stderr)
                errors += 1
                continue
            resp = sr["resps"][idx]
            status = _extract_status(resp)
            body = _decode_body(resp)
            observed[case_id] = (status, body)

    for case_id, exp in EXPECTED_LIVE_CASES.items():
        if case_id not in observed:
            print(f"FAIL {case_id}: missing from capture", file=sys.stderr)
            errors += 1
            continue
        status, body = observed[case_id]
        if status != exp["status"]:
            print(f"FAIL {case_id}: status {status} != {exp['status']}", file=sys.stderr)
            errors += 1
            continue
        for k, v in exp.items():
            if k == "status":
                continue
            if body.get(k) != v:
                print(f"FAIL {case_id}: body[{k!r}]={body.get(k)!r} != {v!r}", file=sys.stderr)
                errors += 1
                break
        else:
            print(f"CHECK {case_id} status={status} reason={body.get('reason')}")

    print(f"SUMMARY cases={len(EXPECTED_LIVE_CASES)} errors={errors}")
    if errors > 0:
        raise SystemExit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify-manifests", type=pathlib.Path, help="Verify P1-P8 scenario manifests directory")
    ap.add_argument("capture", nargs="?", type=pathlib.Path, help="PCAP capture file to verify")
    args = ap.parse_args()
    try:
        if args.verify_manifests:
            verify_manifests(args.verify_manifests)
            print("P1-P8 manifests and traces verified (22/22 Redthread, MintID dual origins + witness-refresh, 2/2 sandbox negative controls)")
        elif args.capture:
            verify_capture(args.capture)
        else:
            ap.error("provide either --verify-manifests <dir> or <capture.pcap>")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
