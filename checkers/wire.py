"""Check WIMSE case outcomes from an HTTP packet capture, without importing the peer.

This is a same-family development checker. AI2II's independent-checker requirement
still needs a separate author from a different model family.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CASES = {c["id"]: c for c in json.loads((ROOT / "cases.json").read_text())["cases"]}
PTYPE = "https://iana.org/assignments/http-problem-types#"


def values(value):
    return value if isinstance(value, list) else [value] if value is not None else []


def header(lines, name):
    prefix = name.lower() + ":"
    matches = [line.split(":", 1)[1].strip() for line in lines if line.lower().startswith(prefix)]
    return matches[-1] if len(matches) == 1 else None


def payload(http):
    raw = http.get("http.file_data")
    if not isinstance(raw, str):
        return None
    try:
        return json.loads(bytes.fromhex(raw.replace(":", "")).decode())
    except (ValueError, UnicodeDecodeError):
        return None


def packets(capture):
    proc = subprocess.run(
        ["tshark", "-r", str(capture), "-d", "tcp.port==5050,http", "-Y", "http", "-T", "json"],
        capture_output=True, text=True,
    )
    if proc.returncode:
        raise ValueError(proc.stderr.strip() or "tshark could not read capture")
    return json.loads(proc.stdout)


def exchanges(capture):
    streams = {}
    for packet in packets(capture):
        layers = packet["_source"]["layers"]
        http = layers.get("http")
        if not http:
            continue
        stream = layers["tcp"]["tcp.stream"]
        entry = streams.setdefault(stream, {"requests": [], "responses": []})
        start = next((v for v in http.values() if isinstance(v, dict) and
                      ("http.request.method" in v or "http.response.code" in v)), None)
        if not start:
            continue
        if "http.request.method" in start:
            lines = values(http.get("http.request.line"))
            cid = header(lines, "X-Test-Case")
            entry["requests"].append({"case": cid, "method": start["http.request.method"],
                                      "uri": start.get("http.request.uri"), "body": payload(http)})
        else:
            entry["responses"].append({"status": int(start["http.response.code"]),
                                       "body": payload(http),
                                       "headers": values(http.get("http.response.line")),
                                       "www_authenticate": http.get("http.www_authenticate")})
    return streams


def check(capture, ids):
    seen = {cid: [] for cid in ids}
    errors = []
    for stream, exchange in exchanges(capture).items():
        reqs, resps = exchange["requests"], exchange["responses"]
        if not reqs or not resps:
            errors.append(f"stream {stream}: missing request or response")
            continue
        if len(reqs) != len(resps):
            errors.append(f"stream {stream}: {len(reqs)} requests, {len(resps)} responses")
            continue
        for req, resp in zip(reqs, resps):
            cid = req["case"]
            if cid not in seen:
                errors.append(f"stream {stream}: unknown or absent case {cid!r}")
                continue
            if req["method"] != "POST" or not re.fullmatch(
                r"/api/v2/agents/[^/]+/workflows/[^/]+/executions", req["uri"] or ""
            ):
                errors.append(f"{cid}: unexpected method or route")
            seen[cid].append(resp)
    for cid in ids:
        expected = CASES[cid]["steps"]
        actual = seen[cid]
        if len(actual) != len(expected):
            errors.append(f"{cid}: saw {len(actual)} responses, expected {len(expected)}")
            continue
        for step, (resp, exp) in enumerate(zip(actual, expected), 1):
            if resp["status"] not in exp["status"]:
                errors.append(f"{cid} step {step}: status {resp['status']} expected {exp['status']}")
            if "type" in exp and (resp["body"] or {}).get("type") != PTYPE + exp["type"]:
                errors.append(f"{cid} step {step}: wrong problem type")
            if "www_authenticate" in exp:
                auth = resp["www_authenticate"] or header(resp["headers"], "WWW-Authenticate") or ""
                if exp["www_authenticate"].lower() not in auth.lower():
                    errors.append(f"{cid} step {step}: missing WWW-Authenticate {exp['www_authenticate']}")
            print(f"CHECK {cid} step={step} status={resp['status']} expected={exp['status']}")
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=pathlib.Path)
    ap.add_argument("--cases", default="all", help="comma-separated IDs, or all")
    args = ap.parse_args()
    ids = list(CASES) if args.cases == "all" else args.cases.split(",")
    unknown = set(ids) - set(CASES)
    if unknown:
        ap.error(f"unknown case IDs: {sorted(unknown)}")
    try:
        errors = check(args.capture, ids)
    except (OSError, ValueError, KeyError) as exc:
        errors = [str(exc)]
    for error in errors:
        print("FAIL", error, file=sys.stderr)
    print(f"SUMMARY cases={len(ids)} errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
