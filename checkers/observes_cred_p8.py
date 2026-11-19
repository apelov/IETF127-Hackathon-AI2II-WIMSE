#!/usr/bin/env python3
"""Check the six WP10 Cred P8 assertions against an HTTP packet capture."""

import argparse
import json
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios" / "p1_p8"
A, B, PROVIDER = 5065, 5066, 5067
REVOKED = "revoked-between-authz-and-use"
RELEASED = "revoked-after-token-released"


def case_id(case, step):
    return f"P8CRED_{case}_{step}"


def fields(element, name):
    return element.findall(f".//field[@name='{name}']")


def field(element, name, default=""):
    match = element.find(f".//field[@name='{name}']")
    return default if match is None else match.get("show", default)


@dataclass
class Message:
    frame: int
    stream: int
    source: int
    destination: int
    method: str
    path: str
    status: int
    request_frame: int
    headers: tuple[str, ...]
    payload: bytes

    def header(self, name):
        values = []
        for line in self.headers:
            key, _, value = line.partition(":")
            if key.lower() == name:
                values.append(value.strip())
        return values[0] if len(values) == 1 else ""

    def token(self, scheme):
        parts = self.header("authorization").split()
        if len(parts) == 2 and parts[0].lower() == scheme.lower():
            return parts[1]
        return ""

    def body(self):
        try:
            value = json.loads(self.payload)
        except (ValueError, UnicodeError):
            return {}
        return value if isinstance(value, dict) else {}


def read_capture(path):
    result = subprocess.run(
        ["tshark", "-2", "-r", str(path), "-d", "tcp.port==5065-5067,http",
         "-Y", "http || (tcp.srcport == 5065 && tcp.len > 0)", "-T", "pdml"],
        capture_output=True,
    )
    if result.returncode:
        raise ValueError("tshark could not read or decode the capture")

    messages = []
    a_payloads = []
    for packet in ET.fromstring(result.stdout).findall("packet"):
        tcp = packet.find("proto[@name='tcp']")
        if tcp is None:
            continue
        source = int(field(tcp, "tcp.srcport"))
        destination = int(field(tcp, "tcp.dstport"))
        if not {source, destination}.intersection((A, B, PROVIDER)):
            continue
        if source == A:
            for name in ("tcp.payload", "tcp.reassembled.data"):
                a_payloads.extend(bytes.fromhex(f.get("value", "")) for f in fields(tcp, name))

        frame = int(field(packet, "frame.number"))
        stream = int(field(tcp, "tcp.stream"))
        for http in packet.findall("proto[@name='http']"):
            method = field(http, "http.request.method")
            status = int(field(http, "http.response.code", "0"))
            if not (method or status):
                continue
            prefix = "request" if method else "response"
            headers = tuple(f.get("show", "").strip() for f in fields(http, f"http.{prefix}.line"))
            payload = b"".join(bytes.fromhex(f.get("value", "")) for f in fields(http, "http.file_data"))
            messages.append(Message(
                frame, stream, source, destination, method, field(http, "http.request.uri"),
                status, int(field(http, "http.request_in", "0")), headers, payload,
            ))
    return messages, a_payloads


class Capture:
    def __init__(self, messages, a_payloads):
        self.requests = [m for m in messages if m.method]
        self.responses = [m for m in messages if m.status >= 200]
        self.a_payloads = a_payloads
        self.by_tag = defaultdict(list)
        self.by_request = defaultdict(list)
        for request in self.requests:
            tag = request.header("x-test-case")
            if tag.startswith("P8CRED_"):
                self.by_tag[tag].append(request)
        for response in self.responses:
            key = response.stream, response.request_frame, response.destination, response.source
            self.by_request[key].append(response)

    def answer(self, request):
        key = request.stream, request.frame, request.source, request.destination
        responses = self.by_request[key]
        if len(responses) == 1 and responses[0].frame > request.frame:
            return responses[0]
        return None

    def exchange(self, case, step, port):
        requests = self.by_tag.get(case_id(case, step), [])
        if len(requests) == 1 and requests[0].destination == port:
            request = requests[0]
            return request, self.answer(request)
        return None, None


def permissions(wire):
    first_step = min((r.frame for group in wire.by_tag.values() for r in group), default=float("inf"))
    for port in (A, B):
        grants = [
            r for r in wire.requests
            if r.destination == port and r.method == "POST"
            and urlsplit(r.path).path.rstrip("/") == "/admin/permissions"
            and r.frame < first_step
        ]
        if len(grants) != 1:
            return f"port {port} has {len(grants)} pre-step permission grants, expected one"
        grant = grants[0]
        if grant.body().get("allowedScopes") != ["calendar.readonly"]:
            return f"port {port} permission request does not grant exactly calendar.readonly"
        response = wire.answer(grant)
        if response is None:
            return f"port {port} permission grant has no matched response"
        if response.status != 201 or response.frame >= first_step:
            return f"port {port} permission grant did not complete with HTTP 201 before the steps"
        permission = response.body().get("permission")
        if not isinstance(permission, dict) or permission.get("allowedScopes") != ["calendar.readonly"]:
            return f"port {port} permission response does not confirm exactly calendar.readonly"
    return None


def steps_on_wire(wire, steps):
    if not wire.by_tag:
        return "no P8 step requests in capture"
    if wire.by_tag.keys() - {step["id"] for step in steps}:
        return "unexpected P8 step tag in capture"
    for step in steps:
        tag = step["id"]
        requests = wire.by_tag.get(tag, [])
        if len(requests) != 1:
            return f"{tag} occurs {len(requests)} times, expected once"
        request = requests[0]
        path = step["path"]
        route_matches = request.path == path
        if step["method"] == "DELETE":
            target = urlsplit(request.path).path
            identifier = target.removeprefix(path)
            route_matches = target.startswith(path) and bool(identifier) and "/" not in identifier
        if request.destination != step["port"] or request.method != step["method"] or not route_matches:
            return f"{tag} uses the wrong port, method or path"
        response = wire.answer(request)
        if response is None:
            return f"{tag} has no matched final HTTP response"
        if response.status != step["status"]:
            return f"{tag} returned HTTP {response.status}, expected {step['status']}"
        body = response.body()
        if not body or body.get("error") != step["cred_error"]:
            return f"{tag} did not return a JSON object with the expected error outcome"
    return None


def scenario_reasons(wire, steps, mapping, scenario):
    expectations = {case["name"]: case["expect"] for case in scenario["cases"]}
    mapped_cases = set()
    for step in steps:
        expected_error = step["cred_error"]
        if expected_error is None:
            continue
        case = step["case"]
        _, response = wire.exchange(case, step["step"], step["port"])
        if response is None:
            return f"{step['id']} has no response for reason mapping"
        error = response.body().get("error")
        if not isinstance(error, str) or error != expected_error:
            return f"{step['id']} has no matching Cred error for reason mapping"
        if error == "raw_token_disabled":
            if response.status != 403 or step["reason"] != "token-not-released" or error in mapping:
                return "raw_token_disabled does not match the documented runner reason"
            continue
        expected = expectations[case]
        if mapping.get(error) != expected["reason"] or step["reason"] != expected["reason"]:
            return f"{step['id']} does not map to the P8 scenario reason"
        if step["decision"] != expected["decision"] or not 400 <= response.status < 500:
            return f"{step['id']} does not support the P8 denial decision"
        mapped_cases.add(case)

    grant, release = wire.exchange(RELEASED, "release-bearer-token", B)
    revoke, revoked = wire.exchange(RELEASED, "revoke", B)
    release_expectation = expectations[RELEASED]
    if (release_expectation["reason"] != "token-released"
            or release_expectation["decision"] != "revocation recorded, token already released"
            or not released_token(release)
            or not revocation_matches(grant, release, revoke, revoked)):
        return "the B release and revocation do not support the P8 token-released reason"
    mapped_cases.add(RELEASED)
    if mapped_cases != expectations.keys():
        return "observed reasons do not cover the P8 scenario cases"
    return None


def revocation_matches(grant, issued, revoke, revoked):
    if not all((grant, issued, revoke, revoked)):
        return False
    delegation_id = issued.body().get("delegation_id")
    confirmation = revoked.body()
    return (
        issued.status == revoked.status == 200
        and grant.frame < issued.frame < revoke.frame < revoked.frame
        and isinstance(delegation_id, str) and bool(delegation_id)
        and revoke.method == "DELETE"
        and urlsplit(revoke.path).path == f"/api/v1/delegations/{delegation_id}"
        and confirmation.get("delegation_id") == delegation_id
        and isinstance(confirmation.get("revoked_ids"), list)
        and delegation_id in confirmation["revoked_ids"]
    )


def revoke_before_use(wire):
    grant, issued = wire.exchange(REVOKED, "delegate-read", A)
    revoke, revoked = wire.exchange(REVOKED, "revoke", A)
    use, refused = wire.exchange(REVOKED, "use-after-revoke", A)
    if not revocation_matches(grant, issued, revoke, revoked):
        return "A did not confirm revocation of the granted delegation"
    if use is None or refused is None or not revoked.frame < use.frame < refused.frame:
        return "A revocation response does not precede a matched use exchange"
    if refused.status != 401:
        return f"A use after revocation returned HTTP {refused.status}, expected 401"
    if refused.body().get("error") != "delegation_revoked":
        return "A did not refuse the use with delegation_revoked"
    body = issued.body()
    scheme = body.get("token_type")
    token = body.get("access_token")
    if not isinstance(scheme, str) or not isinstance(token, str) or not token or use.token(scheme) != token:
        return "refused use did not present the granted Delegation Token"
    return None


def control_provider_call(wire):
    control, answer = wire.exchange("write-under-read", "read-allowed", A)
    if control is None or answer is None or answer.status != 200:
        return None
    body = control.body()
    url = body.get("url")
    if not isinstance(url, str):
        return None
    target = urlsplit(url)
    path = target.path + (f"?{target.query}" if target.query else "")
    calls = []
    for request in wire.requests:
        if (request.destination != PROVIDER or request.header("x-test-case")
                or not control.frame < request.frame < answer.frame
                or request.method != body.get("method") or request.path != path):
            continue
        response = wire.answer(request)
        if response is not None and response.frame < answer.frame and response.status == 200:
            calls.append(request)
    return calls[0] if len(calls) == 1 else None


def no_bearer_from_a(wire):
    control = control_provider_call(wire)
    token = control.token("bearer") if control is not None else ""
    if not token:
        return "no provider bearer on a matched call within the allowed read"
    if any(token.encode() in payload for payload in wire.a_payloads):
        return "configuration A sent the provider bearer toward its client"
    for response in wire.responses:
        if response.source == A and (
            token in "\n".join(response.headers)
            or token.encode() in response.payload
            or token in json.dumps(response.body(), ensure_ascii=False)
        ):
            return "configuration A sent the provider bearer toward its client"
    return None


def released_token(response):
    if response is not None and response.status == 200:
        body = response.body()
        scheme = body.get("token_type")
        token = body.get("access_token")
        if isinstance(scheme, str) and scheme.lower() == "bearer" and isinstance(token, str):
            return token
    return ""


def provider_path(wire):
    requests = [request for request in wire.requests if request.destination == PROVIDER]
    if len(requests) != 2:
        return f"provider saw {len(requests)} requests, expected 2"
    control = control_provider_call(wire)
    direct, answer = wire.exchange(RELEASED, "direct-provider-call", PROVIDER)
    if control is None or direct is None or control is direct or not control.token("bearer"):
        return "provider requests do not match the brokered read and tagged direct call"
    grant, release = wire.exchange(RELEASED, "release-bearer-token", B)
    revoke, revoked = wire.exchange(RELEASED, "revoke", B)
    token = released_token(release)
    if not token or not revocation_matches(grant, release, revoke, revoked):
        return "B did not release a bearer and then confirm revocation of its delegation"
    if not control.frame < direct.frame or not revoked.frame < direct.frame:
        return "direct provider call did not follow the control read and B revocation"
    if answer is None or answer.status != 200:
        return "direct provider call did not receive HTTP 200"
    if direct.token("bearer") != token:
        return "direct provider bearer differs from the bearer released by configuration B"
    return None


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    checks = (
        ("read-only permission grants", permissions),
        ("tagged HTTP steps", steps_on_wire),
        ("P8 scenario reasons", scenario_reasons),
        ("A revocation before use", revoke_before_use),
        ("A withholds the provider bearer", no_bearer_from_a),
        ("provider requests and released bearer", provider_path),
    )

    try:
        messages, a_payloads = read_capture(args.capture)
        wire = Capture(messages, a_payloads)
        load_failure = None
    except (OSError, ValueError, ET.ParseError):
        load_failure = "capture unreadable or tshark failed to decode it"

    if load_failure is None:
        steps = read_json(ROOT / "cred_p8_cases.json")["steps"]
        mapping = read_json(SCENARIOS / "cred-P8.manifest.json")["reason_mapping"]
        scenario = read_json(SCENARIOS / "P8-final-hop-to-a-bearer-only-third-party-api.json")
        arguments = ((), (steps,), (steps, mapping, scenario), (), (), ())

    failed = False
    for index, (label, check) in enumerate(checks):
        issue = load_failure
        if issue is None:
            try:
                issue = check(wire, *arguments[index])
            except ValueError:
                issue = "malformed HTTP evidence"
        if issue:
            print(f"FAIL {index + 1} {label} — {issue}")
            failed = True
        else:
            print(f"PASS {index + 1} {label}")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
