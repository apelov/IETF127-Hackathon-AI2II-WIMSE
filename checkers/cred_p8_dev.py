#!/usr/bin/env python3
"""Capture checker for scenario P8 answered by real Cred (ietf127-wimse-scenario/1).

Reads a loopback capture of the cred-p8 cell and checks, from the packets alone, the steps listed in
cred_p8_cases.json: Cred configuration A on :5065, configuration B on :5066 and the bearer-only
provider mock on :5067. It does not import the peer and does not read the peer's journal.

What it asserts:
- the only permission each Cred server is given, before any step, is calendar.readonly;
- every step is on the wire once, on its port, with Cred's own HTTP status and {error} code;
- Cred's codes map to the scenario's reasons through the reason_mapping of
  scenarios/p1_p8/cred-P8.manifest.json, and those are the reasons P8 expects;
- revoked-between-authz-and-use: the revocation of that same Delegation Token is answered 200 before
  the use that Cred then refuses;
- configuration A never puts the provider bearer token on the wire towards the agent;
- the provider sees exactly two requests: Cred's own call during the allowed read, and the agent's
  direct call, after revocation, with the bearer token configuration B released.

AUTHORSHIP (rule L4): this file was written by Anthropic Claude, the same model family that wrote
peers/cred_p8/serve.mjs and driver.mjs. It is a development checker. An independent checker from
another family (or person) has to replace or re-derive it before the cell counts as observed-on-wire.

The capture is parsed here with the standard library (no tshark), unlike the other checkers.

Usage:
    python3 checkers/observes_cred_p8.py <capture.pcap>
"""
import argparse
import base64
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = json.loads((ROOT / "cred_p8_cases.json").read_text())
PORT_A = SPEC["ports"]["cred_a"]
PORT_B = SPEC["ports"]["cred_b"]
PORT_PROVIDER = SPEC["ports"]["provider"]
SERVER_PORTS = {PORT_A, PORT_B, PORT_PROVIDER}
P8_SCENARIO = ROOT / "scenarios" / "p1_p8" / "P8-final-hop-to-a-bearer-only-third-party-api.json"
CRED_MANIFEST = ROOT / "scenarios" / "p1_p8" / "cred-P8.manifest.json"

# ── pcap and TCP ───────────────────────────────────────────────────────────

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


def read_pcap(path):
    """Return (global header bytes, linktype, endianness, [(record header bytes, packet bytes)])."""
    data = pathlib.Path(path).read_bytes()
    if len(data) < 24 or data[:4] not in PCAP_MAGICS:
        raise ValueError("not a classic pcap file")
    endian, _ = PCAP_MAGICS[data[:4]]
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    records, off = [], 24
    while off + 16 <= len(data):
        incl = struct.unpack(endian + "I", data[off + 8:off + 12])[0]
        if off + 16 + incl > len(data):
            break
        records.append((data[off:off + 16], data[off + 16:off + 16 + incl]))
        off += 16 + incl
    return data[:24], linktype, endian, records


def decode_tcp(linktype, pkt):
    """Return (src, sport, dst, dport, seq, flags, payload offset, payload) or None if not TCP."""
    if linktype == 1:  # Ethernet
        if len(pkt) < 14:
            return None
        proto, off = struct.unpack("!H", pkt[12:14])[0], 14
    elif linktype == 0:  # BSD loopback
        if len(pkt) < 4:
            return None
        fam = struct.unpack("<I", pkt[:4])[0]
        if fam > 0xFFFF:
            fam = struct.unpack(">I", pkt[:4])[0]
        proto, off = (0x0800 if fam == 2 else 0x86DD if fam in (24, 28, 30) else 0), 4
    elif linktype == 113:  # Linux cooked v1
        if len(pkt) < 16:
            return None
        proto, off = struct.unpack("!H", pkt[14:16])[0], 16
    elif linktype == 276:  # Linux cooked v2
        if len(pkt) < 20:
            return None
        proto, off = struct.unpack("!H", pkt[0:2])[0], 20
    else:
        raise ValueError(f"unsupported pcap link type {linktype}")
    if proto == 0x0800:
        if len(pkt) < off + 20 or pkt[off + 9] != 6:
            return None
        ihl = (pkt[off] & 0x0F) * 4
        end = off + struct.unpack("!H", pkt[off + 2:off + 4])[0]
        src, dst = pkt[off + 12:off + 16], pkt[off + 16:off + 20]
        tcp = off + ihl
    elif proto == 0x86DD:
        if len(pkt) < off + 40 or pkt[off + 6] != 6:
            return None
        end = off + 40 + struct.unpack("!H", pkt[off + 4:off + 6])[0]
        src, dst = pkt[off + 8:off + 24], pkt[off + 24:off + 40]
        tcp = off + 40
    else:
        return None
    if len(pkt) < tcp + 20:
        return None
    sport, dport, seq = struct.unpack("!HHI", pkt[tcp:tcp + 8])
    doff = (pkt[tcp + 12] >> 4) * 4
    flags = pkt[tcp + 13]
    start = tcp + doff
    return src, sport, dst, dport, seq, flags, start, pkt[start:min(end, len(pkt))]


class Conn:
    def __init__(self, port):
        self.port = port
        self.seg = {"c": {}, "s": {}}  # direction -> {seq: (packet index, payload)}
        self.isn = {"c": None, "s": None}

    def stream(self, direction):
        """Reassembled bytes of one direction and [(offset, packet index)] for each segment used."""
        segs = self.seg[direction]
        if not segs:
            return b"", []
        isn = self.isn[direction]
        base = (isn + 1) & 0xFFFFFFFF if isn is not None else min(segs)
        ordered = sorted(((seq - base) & 0xFFFFFFFF, idx, data) for seq, (idx, data) in segs.items())
        out, marks = bytearray(), []
        for rel, idx, data in ordered:
            if rel > len(out):
                break  # a gap: bytes are missing from the capture
            if rel + len(data) <= len(out):
                continue  # retransmission
            marks.append((len(out), idx))
            out += data[len(out) - rel:]
        return bytes(out), marks


def connections(path):
    _, linktype, _, records = read_pcap(path)
    conns, current = [], {}
    for idx, (_, pkt) in enumerate(records):
        d = decode_tcp(linktype, pkt)
        if d is None:
            continue
        src, sport, dst, dport, seq, flags, _, payload = d
        if dport in SERVER_PORTS:
            key, direction, port = (src, sport, dst, dport), "c", dport
        elif sport in SERVER_PORTS:
            key, direction, port = (dst, dport, src, sport), "s", sport
        else:
            continue
        syn, ack = flags & 0x02, flags & 0x10
        conn = current.get(key)
        if conn is None or (syn and not ack and direction == "c" and conn.isn["c"] not in (None, seq)):
            conn = Conn(port)
            current[key] = conn
            conns.append(conn)
        if syn:
            if conn.isn[direction] is None:
                conn.isn[direction] = seq
            continue
        if payload and seq not in conn.seg[direction]:
            conn.seg[direction][seq] = (idx, payload)
    return conns


# ── HTTP/1.1 ───────────────────────────────────────────────────────────────

def parse_http(stream, marks):
    """Split a reassembled byte stream into complete HTTP messages."""
    def index_at(offset):
        found = marks[0][1] if marks else -1
        for start, idx in marks:
            if start > offset:
                break
            found = idx
        return found

    msgs, pos = [], 0
    while pos < len(stream):
        head_end = stream.find(b"\r\n\r\n", pos)
        if head_end < 0:
            break
        head = stream[pos:head_end].decode("latin-1").split("\r\n")
        headers = [(h.split(":", 1)[0].strip().lower(), h.split(":", 1)[1].strip()) for h in head[1:] if ":" in h]
        hmap = dict(headers)
        body_start = head_end + 4
        if "chunked" in hmap.get("transfer-encoding", "").lower():
            body, p, complete = bytearray(), body_start, False
            while True:
                eol = stream.find(b"\r\n", p)
                if eol < 0:
                    break
                try:
                    size = int(stream[p:eol].split(b";")[0], 16)
                except ValueError:
                    break
                if size == 0:
                    end = stream.find(b"\r\n", eol + 2)
                    if end >= 0:
                        complete, p = True, end + 2
                    break
                if eol + 2 + size + 2 > len(stream):
                    break
                body += stream[eol + 2:eol + 2 + size]
                p = eol + 2 + size + 2
            if not complete:
                break
            body, nxt = bytes(body), p
        else:
            length = int(hmap.get("content-length", "0") or 0)
            if body_start + length > len(stream):
                break
            body, nxt = stream[body_start:body_start + length], body_start + length
        msgs.append({"line": head[0], "headers": headers, "h": hmap, "body": body,
                     "first": index_at(pos), "last": index_at(max(pos, nxt - 1))})
        pos = nxt
    return msgs


def exchanges(path):
    """Every request on the three ports with its response (None when the capture has none)."""
    out, raw_server = [], {p: b"" for p in SERVER_PORTS}
    for conn in connections(path):
        c_stream, c_marks = conn.stream("c")
        s_stream, s_marks = conn.stream("s")
        raw_server[conn.port] += s_stream
        reqs = [m for m in parse_http(c_stream, c_marks) if not m["line"].startswith("HTTP/")]
        resps = [m for m in parse_http(s_stream, s_marks) if m["line"].startswith("HTTP/")]
        for i, req in enumerate(reqs):
            parts = req["line"].split(" ")
            out.append({
                "port": conn.port, "method": parts[0], "target": parts[1] if len(parts) > 1 else "",
                "tag": req["h"].get("x-test-case"), "req": req, "resp": resps[i] if i < len(resps) else None,
            })
    out.sort(key=lambda e: e["req"]["first"])
    return out, raw_server


# ── checks ─────────────────────────────────────────────────────────────────

def _json(msg):
    try:
        val = json.loads(msg["body"].decode("utf-8"))
        return val if isinstance(val, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def _status(msg):
    parts = msg["line"].split(" ")
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


def _jti(token):
    try:
        seg = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))).get("jti")
    except (IndexError, ValueError, AttributeError):
        return None


def _auth(ex, scheme):
    value = ex["req"]["h"].get("authorization", "")
    return value[len(scheme) + 1:] if value.lower().startswith(scheme.lower() + " ") else None


def check(path):
    errors = []
    err = errors.append
    exs, raw_server = exchanges(path)
    steps = {s["id"]: s for s in SPEC["steps"]}
    mapping = json.loads(CRED_MANIFEST.read_text())["reason_mapping"]
    scenario = {c["name"]: c["expect"] for c in json.loads(P8_SCENARIO.read_text())["cases"]}

    seen, grants = {}, set()
    for ex in exs:
        tag = ex["tag"]
        if tag is None:
            if ex["port"] != PORT_PROVIDER:
                # The only untagged traffic to Cred is its start-up provisioning of the read-only
                # permission (Cred's hackathon helper calls its own admin API), before any step.
                scopes = _json(ex["req"]).get("allowedScopes")
                if (ex["method"], ex["target"]) != ("POST", "/admin/permissions") or seen:
                    err(f"untagged request to port {ex['port']}: {ex['method']} {ex['target']}")
                elif ex["resp"] is None or not 200 <= _status(ex["resp"]) < 300 or scopes != ["calendar.readonly"]:
                    err(f"permission set-up on :{ex['port']} is not a read-only grant answered 2xx (scopes {scopes})")
                else:
                    grants.add(ex["port"])
                    print(f"CHECK setup port={ex['port']} permission allowedScopes={scopes}")
            continue
        if tag not in steps:
            err(f"unknown X-Test-Case {tag!r} on port {ex['port']}")
        elif tag in seen:
            err(f"{tag}: sent more than once")
        else:
            seen[tag] = ex

    if grants != {PORT_A, PORT_B}:
        err(f"read-only permission set-up not seen on both Cred ports before the steps (seen on {sorted(grants)})")

    ok = {}
    for sid, step in steps.items():
        ex = seen.get(sid)
        if ex is None:
            err(f"{sid}: missing from capture")
            continue
        path_only = ex["target"].split("?", 1)[0]
        path_ok = path_only.startswith(step["path"]) if step["path"].endswith("/") else path_only == step["path"]
        if ex["port"] != step["port"] or ex["method"] != step["method"] or not path_ok:
            err(f"{sid}: sent as {ex['method']} {path_only} on :{ex['port']}, expected {step['method']} {step['path']} on :{step['port']}")
            continue
        if ex["resp"] is None:
            err(f"{sid}: request has no response in the capture")
            continue
        status, body = _status(ex["resp"]), _json(ex["resp"])
        if status != step["status"]:
            err(f"{sid}: status {status} != {step['status']}")
            continue
        if step["port"] != PORT_PROVIDER and body.get("error") != step["cred_error"]:
            err(f"{sid}: Cred error {body.get('error')!r} != {step['cred_error']!r}")
            continue
        code = step["cred_error"]
        if code in mapping:
            if mapping[code] != step["reason"]:
                err(f"{sid}: reason_mapping gives {mapping[code]!r} for {code!r}, cases file says {step['reason']!r}")
                continue
            if scenario[step["case"]]["reason"] != step["reason"]:
                err(f"{sid}: scenario P8 expects reason {scenario[step['case']]['reason']!r}, not {step['reason']!r}")
                continue
        ok[sid] = (ex, body)
        print(f"CHECK {sid} port={ex['port']} status={status} cred_error={body.get('error')} reason={step['reason']}")

    def got(*names):
        return all(f"P8CRED_{n}" in ok for n in names)

    def before(a, b, what):
        """Response of a is on the wire before the request of b."""
        if not ok[a][0]["resp"]["last"] < ok[b][0]["req"]["first"]:
            err(f"{what}: {a} was not answered before {b} was sent")

    # write-under-read: the read that is allowed and the write that is refused use the same Delegation Token.
    if got("write-under-read_delegate-read", "write-under-read_read-allowed", "write-under-read_write"):
        token = ok["P8CRED_write-under-read_delegate-read"][1].get("access_token")
        for n in ("read-allowed", "write"):
            if not token or _auth(ok[f"P8CRED_write-under-read_{n}"][0], "DPoP") != token:
                err(f"write-under-read: {n} does not present the Delegation Token that delegate-read returned")

    # revoked-between-authz-and-use: same token, revocation answered 200 before the refused use.
    pre = "P8CRED_revoked-between-authz-and-use_"
    if got("revoked-between-authz-and-use_delegate-read", "revoked-between-authz-and-use_revoke",
           "revoked-between-authz-and-use_use-after-revoke"):
        token = ok[pre + "delegate-read"][1].get("access_token")
        jti = _jti(token)
        if not jti or f"/delegations/{jti}" not in ok[pre + "revoke"][0]["target"]:
            err("revoked-between-authz-and-use: the revocation does not name the delegation that was granted")
        if not token or _auth(ok[pre + "use-after-revoke"][0], "DPoP") != token:
            err("revoked-between-authz-and-use: the refused use does not present the revoked Delegation Token")
        before(pre + "delegate-read", pre + "revoke", "revoked-between-authz-and-use")
        before(pre + "revoke", pre + "use-after-revoke", "revoked-between-authz-and-use")

    # Configuration A does not release a bearer token when asked for one.
    if got("revoked-after-token-released_ask-for-bearer-token"):
        if "access_token" in ok["P8CRED_revoked-after-token-released_ask-for-bearer-token"][1]:
            err("ask-for-bearer-token: configuration A returned an access_token")

    # Provider traffic: Cred's call during the allowed read, and the agent's direct call. Nothing else.
    provider = [e for e in exs if e["port"] == PORT_PROVIDER]
    untagged = [e for e in provider if e["tag"] is None]
    if len(provider) != 2 or len(untagged) != 1:
        err(f"provider :{PORT_PROVIDER} saw {len(provider)} requests ({len(untagged)} from Cred); expected 2 (1 from Cred)")
    elif got("write-under-read_read-allowed"):
        call, read = untagged[0], ok["P8CRED_write-under-read_read-allowed"][0]
        if call["resp"] is None or _status(call["resp"]) != 200:
            err("provider did not answer Cred's call with 200")
        elif not (read["req"]["last"] < call["req"]["first"] and call["resp"]["last"] < read["resp"]["first"]):
            err("Cred's provider call is not inside the allowed read (a refused step reached the provider)")
        provider_token = _auth(call, "Bearer")
        if not provider_token:
            err("Cred's provider call carries no bearer token")
        elif provider_token.encode() in raw_server[PORT_A]:
            err("configuration A put the provider bearer token on the wire towards the agent")
        else:
            print(f"CHECK provider-call-from-cred inside read-allowed; provider token absent from all :{PORT_A} responses")

    # revoked-after-token-released: released, then revoked, then used directly at the provider.
    post = "P8CRED_revoked-after-token-released_"
    if got("revoked-after-token-released_release-bearer-token", "revoked-after-token-released_revoke",
           "revoked-after-token-released_direct-provider-call"):
        body = ok[post + "release-bearer-token"][1]
        bearer = body.get("access_token")
        delegation = body.get("delegation_id") or body.get("jti")
        if not isinstance(bearer, str) or not bearer:
            err("release-bearer-token: configuration B returned no access_token")
        elif _auth(ok[post + "direct-provider-call"][0], "Bearer") != bearer:
            err("direct-provider-call: the bearer token is not the one configuration B released")
        if not delegation or f"/delegations/{delegation}" not in ok[post + "revoke"][0]["target"]:
            err("revoked-after-token-released: the revocation does not name the delegation that released the token")
        before(post + "release-bearer-token", post + "revoke", "revoked-after-token-released")
        before(post + "revoke", post + "direct-provider-call", "revoked-after-token-released")

    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=pathlib.Path)
    args = ap.parse_args()
    try:
        errors = check(args.capture)
    except (OSError, ValueError, KeyError, struct.error) as exc:
        errors = [f"{type(exc).__name__}: {exc}"]
    for e in errors:
        print(f"FAIL {e}", file=sys.stderr)
    print(f"SUMMARY steps={len(SPEC['steps'])} errors={len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
