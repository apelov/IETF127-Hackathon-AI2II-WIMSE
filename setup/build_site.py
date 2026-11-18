"""Build the data for the scenario explorer (site/data/*.json).

Every scenario is generated from committed evidence:
  - wire cases: frames of validation/bundle-*/*/capture.pcap, read with tshark and checked against
    cases.json / chain_cases.json (the build fails if they disagree);
  - :5064 cases: frames of the chain capture;
  - partner scenarios: the committed records in scenarios/p1_p8/ (and, for reports with no record,
    the figures in TEST_RESULTS_SUMMARY.md, badged as reports);
  - "break it": the negative captures in checkers/negatives/, with the real checker output.
Only the narration and the draft mapping are written here.

Usage: .venv/bin/python setup/build_site.py        (needs tshark)
"""
import base64
import datetime
import json
import pathlib
import re
import subprocess
import sys
import urllib.parse
from collections import defaultdict

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "checkers"))
sys.path.insert(0, str(HERE))
import observes_chain as oc
from generate_test_catalog import CASES, CLASSES, GROUPS
from pending_rerecord import PENDING_RERECORD, classify

SITE = ROOT / "site"
DATA = SITE / "data"
REPO = "https://github.com/apelov/IETF127-Hackathon-AI2II-WIMSE"
RAW = REPO + "/raw/main/"
P1P8 = ROOT / "scenarios" / "p1_p8"
INBOUND = "validation/bundle-inbound/inbound/capture.pcap"
CHAIN = "validation/bundle-chain/chain/capture.pcap"

# ------------------------------------------------------------------ entities and layout (1100 x 400)
ENT = {
    "client": ("Client workload", "wimse://peer.../client", 20, 40, 170, 64),
    "ttsa": ("TTS-A / AS-A", ":5051", 290, 40, 150, 64),
    "maurice": ("Maurice (agent 1)", ":5050", 20, 290, 170, 64),
    "attacker": ("Attacker URL", ":47999", 290, 420, 150, 64),
    "asb": ("AS-B / TTS-B", ":5061", 500, 165, 190, 64),
    "coord": ("Coordinator (agent 2)", ":5060", 500, 290, 190, 64),
    "research": ("Research (agent 3)", ":5062", 720, 290, 180, 64),
    "filetool": ("File Tool", ":5063", 920, 290, 150, 64),
    "executor": ("Loopback executor", ":5064", 860, 40, 210, 64),
}
FRAMES = [
    {"zone": "a", "label": "Domain A (maurice.ietf127.example)", "x": 10, "y": 10, "w": 440, "h": 380},
    {"zone": "b", "label": "Domain B (rich.ietf127.example)", "x": 470, "y": 10, "w": 620, "h": 380},
]
PORT_ENT = {5050: "maurice", 5051: "ttsa", 5060: "coord", 5061: "asb", 5062: "research", 5063: "filetool",
            5064: "executor", 47999: "attacker"}

ZONE = {"client": "a", "ttsa": "a", "maurice": "a", "attacker": "x", "asb": "b", "coord": "b", "research": "b",
        "filetool": "b", "executor": "b"}


def ent(eid):
    label, sub, x, y, w, h = ENT[eid]
    return {"id": eid, "label": label, "sub": sub, "x": x, "y": y, "w": w, "h": h, "zone": ZONE[eid]}


def row_layout(items):
    """Entities in one row for partner scenarios: items = [(id, label, sub)]."""
    n = len(items)
    if n == 3:  # a triangle, so that no arrow passes through a third box
        return [{"id": i, "label": lab, "sub": sub, "x": x, "y": y, "w": 240, "h": 80, "zone": "p"}
                for (i, lab, sub), x, y in zip(items, (30, 430, 830), (200, 30, 200))]
    w = 240 if n == 2 else 190
    gap = (1060 - n * w) // max(n - 1, 1) if n > 1 else 0
    x0 = (1100 - (n * w + (n - 1) * gap)) // 2
    return [{"id": i, "label": lab, "sub": sub, "x": x0 + k * (w + gap), "y": 150, "w": w, "h": 80, "zone": "p"}
            for k, (i, lab, sub) in enumerate(items)]


# ------------------------------------------------------------------ drafts
D = {
    "wit": ("draft-ietf-wimse-workload-creds-03", "WIT: the workload's badge"),
    "wpt": ("draft-ietf-wimse-wpt-02", "WPT: proof the sender holds the badge's key"),
    "sig": ("draft-ietf-wimse-http-signature-08", "HTTP signature profile (RFC 9421, RFC 9530)"),
    "id": ("draft-ietf-wimse-identifier-04", "Workload identifier"),
    "txn": ("draft-ietf-oauth-transaction-tokens-11", "Transaction Tokens"),
    "chain": ("draft-ietf-oauth-identity-chaining-17", "Identity chaining (RFC 8693, RFC 7523)"),
    "passport": ("draft-le-agent-passport-00", "Agent passport: status, revocation, exposure"),
    "oasnt": ("draft-thallapelly-oasnt-02", "OASNT approval tokens (and -enforce-01 section 5.1)"),
    "cred": ("draft-sweeney-wimse-credential-delegation", "Credential delegation to bearer-only APIs"),
    "mintid": ("MintID protocol (own, open source)", "Zero-knowledge non-revocation proof"),
}
GROUP_DRAFTS = {
    "normal": ["wit", "wpt", "sig", "txn", "chain"],
    "identity": ["wit", "id"],
    "proof": ["wit", "wpt", "sig"],
    "authz": ["txn", "wpt"],
    "xdomain": ["txn", "chain"],
    "revocation": ["passport", "mintid"],
    "tricks": ["wit", "sig"],
}
ID_SECTIONS = {  # verified against draft-ietf-wimse-identifier-04
    "A13a": "section 4.1 (a path is required)",
    "A13b": "section 4.1 (no . or .. segments, also after decoding)",
    "A13c": "section 4.1 (no . or .. segments, also after decoding)",
    "A13d": "section 4.1 (no . or .. segments, also after decoding)",
    "A13e": "section 4.1 (no port)", "A13f": "section 4.1 (no query)",
    "A13g": "section 4.1 (no fragment)", "A13h": "section 4.1 (no user information)",
    "A13i": "section 4.3 (normalize per RFC 3986 6.2.2, then compare byte for byte)",
    "A13j": "section 7.1 (%2F stays encoded when comparing)",
}


def drafts_for(sid, group, cls=None):
    out = []
    keys = GROUP_DRAFTS.get(group, [])
    if sid.startswith("P7"):
        keys = ["oasnt"]
    elif sid.startswith("P8"):
        keys = ["cred"]
    elif sid.startswith(("P1", "P2", "P3", "P4", "P5", "P6")):
        keys = ["passport"] + (["mintid"] if sid.startswith("P2") else [])
    for k in keys:
        name, what = D[k]
        out.append({"name": name, "what": what, "section": ID_SECTIONS.get(sid) if k == "id" else None})
    if sid in ID_SECTIONS and not any(d["name"].endswith("identifier-04") for d in out):
        out.append({"name": D["id"][0], "what": D["id"][1], "section": ID_SECTIONS[sid]})
    return out


# ------------------------------------------------------------------ capture extraction
def deep(d, key):
    """First value of a tshark JSON key, searching nested dicts."""
    if isinstance(d, dict):
        if key in d:
            return d[key]
        for v in d.values():
            r = deep(v, key)
            if r is not None:
                return r
    return None


def parse_time(s):
    s = oc._first_str(s)
    if "T" in s:
        s = re.sub(r"(\.\d{6})\d*Z$", r"\1+00:00", s).replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(s).timestamp()
    return float(s)


def lines_of(http, key):
    return [ln.rstrip("\r\n") for ln in oc._extract_lines(http, key)]


def tshark(capture, ports):
    cmd = ["tshark", "-r", str(ROOT / capture)]
    for p in ports:
        cmd += ["-d", f"tcp.port=={p},http"]
    cmd += ["-Y", "http", "-T", "json", "-o", "tcp.relative_sequence_numbers:FALSE"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return json.loads(out, object_pairs_hook=oc._collect_duplicates)


FORM_BODY_RE = re.compile(r"^[\w.-]+=[^\s]*(&[\w.-]+=[^\s]*)*$")


def pretty(body):
    """JSON indented; an application/x-www-form-urlencoded body as one decoded `name = value` line per parameter."""
    try:
        return json.dumps(json.loads(body), indent=2, ensure_ascii=False)
    except (ValueError, TypeError):
        pass
    if body and FORM_BODY_RE.match(body.strip()):
        return "\n".join(f"{k} = {v}" for k, v in urllib.parse.parse_qsl(body.strip(), keep_blank_values=True))
    return body


def exchanges(capture, ports):
    """{case_id: [exchange, ...]} in frame order. Untagged requests are ignored."""
    streams = defaultdict(lambda: {"reqs": [], "resps": []})
    for pkt in tshark(capture, ports):
        layers = pkt.get("_source", {}).get("layers", {})
        tcp = layers.get("tcp", {})
        tcp = tcp[0] if isinstance(tcp, list) and tcp else tcp
        http = layers.get("http", {})
        http = http[-1] if isinstance(http, list) else http
        if not isinstance(http, dict) or not tcp:
            continue
        frame = layers.get("frame", {})
        item = {
            "frame": int(oc._first_str(frame.get("frame.number", "0")) or 0),
            "t": parse_time(frame.get("frame.time_epoch", "0")),
            "stream": int(oc._first_str(tcp.get("tcp.stream", "0")) or 0),
            "dstport": int(oc._first_str(tcp.get("tcp.dstport", "0")) or 0),
            "http": http,
        }
        sid = oc._first_str(tcp.get("tcp.stream", ""))
        if oc._is_request(http):
            streams[sid]["reqs"].append(item)
        elif oc._extract_status(http) > 0:
            streams[sid]["resps"].append(item)
    by_case = defaultdict(list)
    for s in streams.values():
        for i, rq in enumerate(s["reqs"]):
            hdrs = lines_of(rq["http"], "http.request.line")
            case = next((h.split(":", 1)[1].strip() for h in hdrs if h.lower().startswith("x-test-case:")), None)
            if not case or i >= len(s["resps"]):
                continue
            rs = s["resps"][i]
            status = oc._extract_status(rs["http"])
            rbody = oc._body_text(rs["http"])
            try:
                parsed = json.loads(rbody)
            except ValueError:
                parsed = {}
            reason = None
            if isinstance(parsed, dict):
                reason = oc.reason_of(parsed)
            method = oc._first_str(deep(rq["http"], "http.request.method"))
            uri = oc._first_str(deep(rq["http"], "http.request.uri"))
            by_case[case].append({
                "dstport": rq["dstport"], "frame": rq["frame"], "stream": rq["stream"], "t": rq["t"], "t_resp": rs["t"],
                "resp_frame": rs["frame"], "status": status, "reason": reason, "method": method, "uri": uri,
                "req": {"line": f"{method} {uri} HTTP/1.1", "headers": hdrs,
                        "body": pretty(oc._body_text(rq["http"]))},
                "resp": {"line": f"HTTP/1.1 {status} {oc._first_str(deep(rs['http'], 'http.response.phrase'))}".strip(),
                         "headers": lines_of(rs["http"], "http.response.line"), "body": pretty(rbody)},
            })
    for v in by_case.values():
        v.sort(key=lambda e: e["frame"])
    return by_case


# ------------------------------------------------------------------ narration
# Each hop: (from, to, text, drafts). BCHAIN_NEW[i] replaces BCHAIN[i] when the captured request carries a WIT, that is,
# for captures recorded after the peers were brought in line with the drafts (the committed capture predates that).
BCHAIN_NEW = {
    0: ("client", "ttsa", "Alice's request starts. The client asks Domain A's token service for a Transaction Token with an RFC 8693 token exchange form: audience (the trust domain), scope files:read files:list, requested_token_type txn_token, and Alice as an unsigned_json subject_token; request_details carries the file for tctx. The request is signed with the client's WIT and an HTTP signature, because the token service must authenticate who is asking, and it takes the requester (req_wl) from that WIT, not from the body. The reply is an access_token member holding the Transaction Token, with issued_token_type txn_token and token_type N_A.", ["wit", "sig", "txn"]),
    2: ("client", "ttsa", "To cross to Domain B, the client exchanges the Domain A token at AS-A (RFC 8693 form: subject_token with subject_token_type txn_token, resource naming AS-B), signed with its WIT. AS-A answers with a JWT authorization grant in access_token (issued_token_type jwt, token_type N_A, expires_in) for AS-B. The Domain A token stays in Domain A.", ["wit", "sig", "chain"]),
    3: ("client", "asb", "The client redeems the grant at AS-B with an RFC 7523 request (grant_type jwt-bearer, assertion) and receives a Bearer access token for Domain B; its client_id claim names the client workload.", ["chain"]),
    5: ("coord", "asb", "The Coordinator asks TTS-B for a Domain B Transaction Token. It authenticates with its own WIT and an HTTP signature (its own key) and sends the access token as subject_token (subject_token_type access_token).", ["wit", "sig", "txn"]),
    7: ("research", "asb", "The Research agent asks TTS-B to narrow the token to files:read: scope can only get smaller. It authenticates with its own WIT and signature; the Transaction Token it received is only the subject_token, never the credential of the request.", ["wit", "sig", "txn"]),
}
BCHAIN = [
    ("client", "ttsa", "Alice's request starts. The client asks Domain A's token service for a Transaction Token with scope files:read files:list. This first call carries no WIT and no signature; the reply is a Transaction Token, not a WIT.", ["txn"]),
    ("client", "maurice", "The client calls Maurice (agent 1) with its WIT, an HTTP signature and the Domain A token. The WIT is a badge the test harness mints locally; no message on the wire fetches it, so this is where it first appears. Maurice runs a side workflow; it does not forward the call.", ["wit", "sig", "txn"]),
    ("client", "ttsa", "To cross to Domain B, the client exchanges the Domain A token at AS-A for a cross-domain grant. The Domain A token stays in Domain A.", ["chain"]),
    ("client", "asb", "The client redeems the grant at AS-B and receives a Domain B access token.", ["chain"]),
    ("client", "coord", "The client calls Domain B's Coordinator (agent 2) with its WIT, the access token and a signature. The Coordinator cannot answer yet: it first has to get a token (call 6) and have the Research agent do the work (call 7). This reply is the last message of the whole chain.", ["wit", "sig"]),
    ("coord", "asb", "The Coordinator gets a Domain B Transaction Token from TTS-B.", ["txn"]),
    ("coord", "research", "The Coordinator delegates to the Research agent (agent 3), signing the call and carrying the Domain B token. Research in turn needs a narrowed token (call 8) and the file (call 9) before it can reply.", ["wit", "sig", "txn"]),
    ("research", "asb", "The Research agent asks TTS-B to narrow the token to files:read: scope can only get smaller.", ["txn"]),
    ("research", "filetool", "The File Tool checks the WIT, that the WPT binds both the WIT (wth) and the narrowed token (tth), and the scope, then permits exactly one read.", ["wit", "wpt", "txn"]),
]
CALLERS = {  # who calls, when it is not the client (index -> entity), from the recorded hop tables
    "B_CHAIN": {5: "coord", 6: "coord", 7: "research", 8: "research"},
    "C7": {1: "research", 2: "research", 3: "research"},
    "C8": {1: "research", 2: "research", 3: "research"},
}
ROLE = {"ttsa": "the Domain A token service", "maurice": "Maurice", "asb": "Domain B's token service (AS-B / TTS-B)",
        "coord": "the Coordinator", "research": "the Research agent", "filetool": "the File Tool",
        "executor": "the loopback executor"}


JWT_RE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]*")
TOKEN_KIND = {"wit+jwt": "WIT", "wpt+jwt": "WPT", "txntoken+jwt": "Transaction Token", "at+jwt": "Access token",
              "jwt-chg+jwt": "Cross-domain grant"}
KIND_WORDS = {"WIT": "workload identity token", "WPT": "workload proof token", "Transaction Token": "Txn-Token",
              "Access token": "OAuth access token", "Cross-domain grant": "RFC 7523 JWT assertion"}


def decode_jwt(tok):
    try:
        hdr, pl = (json.loads(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))) for x in tok.split(".")[:2])
        return hdr, pl
    except (ValueError, TypeError, IndexError):
        return None


def claim_line(kind, pl):
    aud = pl.get("aud")
    aud = ", ".join(aud) if isinstance(aud, list) else aud
    if kind == "WPT":
        return f"proof for {aud}; binds the WIT (wth)" + (" and the Transaction Token (tth)" if pl.get("tth") else "")
    if kind == "WIT":
        alg = (pl.get("cnf") or {}).get("jwk", {}).get("alg")
        return f"workload {pl.get('sub')}, issued by {pl.get('iss')}" + (f", key {alg}" if alg else "")
    bits = []
    if pl.get("sub"):
        bits.append(f"for {pl['sub']}")
    if pl.get("scope"):
        bits.append(f"scope {pl['scope']}")
    if aud:
        bits.append(f"audience {aud}")
    if pl.get("req_wl"):
        bits.append(f"requester {pl['req_wl']}")
    if pl.get("client_id"):
        bits.append(f"client {pl['client_id']}")
    if pl.get("exp") and pl.get("iat"):
        bits.append(f"valid {pl['exp'] - pl['iat']} s")
    return ", ".join(bits)


def token_info(tok, where):
    d = decode_jwt(tok)
    if not d:
        return None
    hdr, pl = d
    kind = TOKEN_KIND.get(hdr.get("typ", ""), f"JWT ({hdr.get('typ', '?')})")
    note = "Minted locally by the test harness; no message on the wire fetches it." if kind == "WIT" else ""
    return {"kind": kind, "what": KIND_WORDS.get(kind, ""), "where": where, "line": claim_line(kind, pl), "note": note, "header": hdr, "claims": pl}


def tokens_in(headers, body):
    out = []
    for hd in headers:
        name = hd.split(":", 1)[0]
        for m in JWT_RE.finditer(hd):
            scheme = hd.split(":", 1)[1].split()[0] if name.lower() == "authorization" and ":" in hd else ""
            t = token_info(m.group(), f"header {name}" + (f" ({scheme})" if scheme and not scheme.startswith("eyJ") else ""))
            if t:
                out.append(t)
    for m in re.finditer(r'"([\w-]+)":\s*"(eyJ[\w.-]+)"', body or ""):  # JSON member, old and new captures
        t = token_info(m.group(2), f'body field "{m.group(1)}"')
        if t:
            out.append(t)
    for m in re.finditer(r"^([\w.-]+) = (eyJ[\w.-]+)$", body or "", re.M):  # form parameter, as shown by pretty()
        t = token_info(m.group(2), f'form parameter "{m.group(1)}"')
        if t:
            out.append(t)
    return out


def reply_of(h, returned):
    """Short and long plain-language summary of a response."""
    m = re.match(r"HTTP/\S+ (\d{3})\s*(.*)", h["resp"]["line"])
    status, phrase = int(m.group(1)), m.group(2)
    try:
        b = json.loads(h["resp"]["body"])
    except ValueError:
        b = {}
    b = b if isinstance(b, dict) else {}
    head = f"{status} {phrase}".strip()
    if returned:
        kinds = " + ".join(dict.fromkeys(t["kind"] for t in returned))
        oauth = ""
        if b.get("issued_token_type") or b.get("token_type"):  # RFC 8693 / RFC 6749 s5.1 response members
            oauth = " The OAuth response says" + "".join(
                f" {k} {str(b[k]).rsplit(':', 1)[-1]}," for k in ("issued_token_type", "token_type") if b.get(k)).rstrip(",") + (
                f", expires_in {b['expires_in']} s" if b.get("expires_in") else "") + "."
        return {"status": status, "short": f"{status}: returns {kinds}",
                "long": f"{head}. Returns " + "; ".join(f"a {t['kind']} ({t['line']})" for t in returned) + "." + oauth}
    if status >= 400:
        ptype = str(b.get("type", ""))
        ptype = "" if ptype == "about:blank" else ptype.rsplit("#", 1)[-1].rsplit("/", 1)[-1]
        why = b.get("reason") or b.get("error") or ptype or b.get("title")
        return {"status": status, "short": f"{status}: refused" + (f" ({why})" if why else ""),
                "long": f"{head}. The request is refused" + (f": {why}." if why else ".")}
    if "decision" in b:
        why = f" ({b['reason']})" if b.get("reason") else ""
        return {"status": status, "short": f"{status}: {b['decision']}{why}", "long": f"{head}. Decision: {b['decision']}{why}; effect: {b.get('effect', 'n/a')}."}
    if b.get("state"):
        return {"status": status, "short": f"{status}: workflow {b['state']}", "long": f"{head}. Maurice ran the workflow {b.get('workflow_id', '')}: state {b['state']} ({b.get('duration_ms', '?')} ms)."}
    if "file" in b and "content" in b:
        inj = " Its content includes the test's prompt-injection text." if "PROMPT INJECTION" in str(b["content"]) else ""
        return {"status": status, "short": f"{status}: returns file {b['file']}", "long": f"{head}. Returns the file {b['file']}.{inj}"}
    if "summary" in b:
        return {"status": status, "short": f"{status}: result {b['summary']}", "long": f"{head}. The agent's result: {b['summary']} (file status {b.get('file_status')}, credentials leaked: {b.get('leaked_credentials')})."}
    keys = ", ".join(list(b)[:3])
    return {"status": status, "short": f"{status}" + (f": JSON ({keys})" if keys else ""), "long": head + (f". JSON with: {keys}." if keys else ".")}


def enrich(h):
    sent = tokens_in(h["req"]["headers"], h["req"]["body"])
    returned = tokens_in([], h["resp"]["body"])
    return {"sent": sent, "returned": returned}, reply_of(h, returned)


def eli5_for(cid):
    for row in CASES:
        if cid in row["ids"]:
            return row
    return None


def bchain_hop(i, ex):
    """The B_CHAIN narration of hop i: the draft-conformant wording when the captured request carries a WIT or is a form."""
    new_format = any(h.lower().startswith("workload-identity-token:") for h in ex["req"]["headers"]) or ex["req"]["body"].startswith("grant_type = ")
    return BCHAIN_NEW[i] if new_format and i in BCHAIN_NEW else BCHAIN[i]


def step_comment(cid, i, st, cases):
    if cid == "B_CHAIN":
        return bchain_hop(i, st)[2]
    verb = f"{st['method']} {st['uri'].split('?')[0]}"
    res = f"{st['status']}" + (f" {st['reason']}" if st["reason"] else "")
    if st["status"] < 300:
        tail = "Accepted."
    else:
        tail = "Refused, as the test expects." if st["status"] >= 400 else ""
    return f"{verb} to {ROLE.get(PORT_ENT.get(st['dstport']), 'the service')}: {res}. {tail}".strip()


def build_wire(by_case, cases_meta, group_of, kind):
    """kind: 'inbound' or 'chain'. Returns scenario dicts."""
    out = []
    for cid, meta in cases_meta.items():
        exs = by_case.get(cid)
        if not exs and kind == "chain" and cid in PENDING_RERECORD:
            print(f"pending re-record, no scenario built: {cid}")
            continue
        if not exs:
            raise SystemExit(f"{cid}: not in the capture")
        row = eli5_for(cid)
        callers = CALLERS.get(cid, {})
        steps, used = [], []
        for i, ex in enumerate(exs):
            frm = callers.get(i, "client")
            to = PORT_ENT[ex["dstport"]]
            for e in (frm, to):
                if e not in used:
                    used.append(e)
            t0 = exs[0]["t"]
            steps.append({
                "from": frm, "to": to,
                "label": f"{ex['method']} {re.sub(r'/agents/[^/]+', '/agents/...', ex['uri'].split('?')[0])}  ->  {ex['status']}" + (f" {ex['reason']}" if ex["reason"] else ""),
                "result": ex["status"] < 400,
                "comment": step_comment(cid, i, ex, meta),
                "drafts": [D[k][0] for k in bchain_hop(i, ex)[3]] if cid == "B_CHAIN" else None,
                "http": {"frame": ex["frame"], "resp_frame": ex["resp_frame"], "stream": ex["stream"],
                         "req": ex["req"], "resp": ex["resp"]},
                "time": {"rel": round(ex["t"] - t0, 3), "dt": round(ex["t"] - exs[i - 1]["t"], 3) if i else 0.0, "resp_rel": round(ex["t_resp"] - t0, 3)},
                "_ex": ex,
            })
        scen = {
            "id": cid, "title": ("B_CHAIN: the 9-hop, two-domain call chain" if cid == "B_CHAIN" else f"{cid}: {meta['title'].rstrip(':')}"), "group": group_of(cid), "cls": "wire",
            "description": (row["eli5"] if row else meta["title"]),
            "expected": (row["expected"] if row else ""),
            "capture": {"file": INBOUND if kind == "inbound" else CHAIN, "url": RAW + (INBOUND if kind == "inbound" else CHAIN)},
            "checker": "observes_wimse.py" if kind == "inbound" else "observes_chain.py",
            "entities": [ent(e) for e in used] if kind == "chain" else
            [{**e, "zone": ZONE[e["id"]]} for e in row_layout([(i, ENT[i][0], ENT[i][1]) for i in used])],
            "frames": FRAMES if kind == "chain" else [],
            "steps": steps,
        }
        out.append(scen)
    return out


def verdict_inbound(scen, meta):
    exp = meta["steps"]
    exs = [s["_ex"] for s in scen["steps"]]
    if len(exs) != len(exp):
        raise SystemExit(f"{scen['id']}: {len(exs)} exchanges, cases.json has {len(exp)} steps")
    for st, e, ex in zip(scen["steps"], exp, exs):
        ok = ex["status"] in e["status"]
        if not ok:
            raise SystemExit(f"{scen['id']}: status {ex['status']} not in {e['status']}")
        want = " or ".join(str(s) for s in e["status"]) + (f", challenge {e['www_authenticate']}" if e.get("www_authenticate") else "")
        note = "reason " + " / ".join(e["reason"]) + " (checked by the client driver in Maurice's journal; not visible on the wire)" if e.get("reason") else ""
        st["verdict"] = {"expected": want, "observed": f"{ex['status']}", "ok": ok, "note": note}
    scen["result"] = {"verdict": "PASS", "text": "all steps match cases.json; checked by observes_wimse.py"}


def verdict_chain(scen, meta):
    obs = [f"{s['_ex']['dstport']} {s['_ex']['status']} {s['_ex']['reason'] or '-'}" for s in scen["steps"]]
    verdict = classify(scen["id"], obs, meta)
    pending = verdict == "pending"
    if verdict not in ("ok", "pending"):
        raise SystemExit(verdict)
    if not pending and obs != meta["expected_hops"]:
        raise SystemExit(f"{scen['id']}: hops {obs} differ from expected_hops {meta['expected_hops']}")
    for st, o in zip(scen["steps"], obs):
        st["verdict"] = {"expected": o, "observed": o, "ok": True, "note": ""}
    scen["result"] = {"verdict": "PASS", "text": "every hop equals expected_hops in chain_cases.json; checked by observes_chain.py"}
    if pending:
        scen["result"]["text"] = ("every hop equals the legacy_expected_hops in chain_cases.json: this case was recorded before the peers were "
                                  "brought in line with the drafts, and the new expected_hops are not yet recorded (PENDING_RERECORD); checked by observes_chain.py")
    if meta.get("wire_note"):
        scen["result"]["text"] += ". " + meta["wire_note"]


# ------------------------------------------------------------------ :5064 cases
P5064 = {
    "P2_revoke-upstream": ("P2 revoke-upstream", "revocation", "sim", "Boss cancelled after delegating: the helper's next request must be refused within the bound. Redthread's code with a simulated verifier on a fake clock."),
    "P2_before-effect": ("P2 before-effect", "revocation", "sim", "Cancelled between approval and effect: re-check just before acting, so nothing happens. Redthread's code, simulated."),
    "P2_outside-made-up-proof": ("P2 outside-made-up-proof", "revocation", "sim", "An invented zero-knowledge proof is refused. The recorded outcome of the 15 Nov MintID sandbox run is replayed."),
    "P2_outside-no-agent-answer": ("P2 outside-no-agent-answer", "revocation", "sim", "The agent never answers the challenge, so refused. Replayed from the 15 Nov sandbox run."),
    "P7_display-match": ("P7 display-match (:5064)", "normal", "mock", "Fixed answer: a digest string is compared with a constant. No OASNT code runs; says nothing about OmniArx's verifier."),
    "P7_display-mismatch": ("P7 display-mismatch (:5064)", "tricks", "mock", "Fixed answer: a different digest string gets 403. No OASNT code runs."),
    "P8_no-delegation": ("P8 no-delegation (:5064)", "authz", "mock", "Fixed answers per case name. No Cred code runs."),
    "P8_write-under-read": ("P8 write-under-read (:5064)", "authz", "mock", "Fixed answers per case name. No Cred code runs."),
    "P8_revoked-between-authz-and-use": ("P8 revoked-between-authz-and-use (:5064)", "revocation", "mock", "Fixed answers per case name. No Cred code runs."),
    "P8_revoked-after-token-released": ("P8 revoked-after-token-released (:5064)", "revocation", "mock", "Fixed answers per case name; once a token is released, revocation cannot stop the provider call."),
}


def build_5064(by_case):
    out = []
    for cid, (title, group, cls, desc) in P5064.items():
        exs = by_case.get(cid)
        if not exs:
            raise SystemExit(f"{cid}: not in the chain capture")
        ex = exs[0]
        label = f"POST {ex['uri']}  ->  {ex['status']}" + (f" {ex['reason']}" if ex["reason"] else "")
        out.append({
            "id": cid.lower().replace("_", "-"), "title": title, "group": group, "cls": cls, "description": desc,
            "expected": f"{ex['status']} {ex['reason'] or ''}".strip(),
            "capture": {"file": CHAIN, "url": RAW + CHAIN}, "checker": "observes_p1_p8.py",
            "entities": [ent("client"), ent("executor")], "frames": [],
            "steps": [{"from": "client", "to": "executor", "label": label, "result": ex["status"] < 400,
                       "comment": desc, "drafts": None,
                       "http": {"frame": ex["frame"], "resp_frame": ex["resp_frame"], "stream": ex["stream"], "req": ex["req"], "resp": ex["resp"]},
                       "time": {"rel": 0.0, "dt": 0.0, "resp_rel": round(ex["t_resp"] - ex["t"], 3)},
                       "verdict": {"expected": f"{ex['status']} {ex['reason'] or ''}".strip(), "observed": f"{ex['status']} {ex['reason'] or ''}".strip(), "ok": True,
                                   "note": "decision and reason are checked in the response body by observes_p1_p8.py"}}],
            "result": {"verdict": "PASS", "text": "matches EXPECTED_LIVE_CASES in observes_p1_p8.py. Evidence class: " + CLASSES[cls][0]},
        })
    return out


# ------------------------------------------------------------------ partner records
RT_TEXT = {
    "P1": "Is the cancellation list reachable and fresh? If it says revoked, is stale, or cannot be read: refuse (fail closed).",
    "P2": "Revocation after delegation, before the effect (Redthread, simulated clock).",
    "P3": "A delegation may not give a helper more than it received: wider host, more methods, longer life, dropped tool limits.",
    "P4": "A cumulative call limit across services: one service must count, and a delegate cannot raise its own limit.",
    "P5": "A request rewritten in transit: the signature must not match, and only an authenticated proxy may speak for the target.",
    "P6": "The tool or build changed between hops: the approved one must be the one that runs.",
}
RT_GROUP = {"P1": "revocation", "P2": "revocation", "P3": "xdomain", "P4": "xdomain", "P5": "proof", "P6": "tricks"}


def jl(path):
    return [json.loads(x) for x in (P1P8 / path).read_text().splitlines() if x.strip()]


def _decision_key(x):
    return (x["check"], x["decision"], x["reason"], x["effect"])


def build_redthread():
    man = json.loads((P1P8 / "redthread-local.manifest.json").read_text())
    out = []
    for r in man["results"]:
        sc, case = r["scenario"], r["case"]
        lines = [x for x in jl(f"redthread-{sc}-local.jsonl") if x["case"] == case]
        if not lines:
            raise SystemExit(f"redthread {sc} {case}: no lines")
        # time zero is the revocation when the record says when it happened, otherwise the first decision
        anchor = next((x["ts"] for x in lines if x.get("t_since_revocation_ms") == 0), lines[0]["ts"])
        note = "simulated seconds after the revocation (fake clock)" if anchor != lines[0]["ts"] or lines[0].get("t_since_revocation_ms") == 0 else "simulated seconds (fake clock)"
        # a run of identical decisions longer than 3 (P2 logs one per simulated second) becomes first, "... N more", last
        shown, i = [], 0
        while i < len(lines):
            j = i
            while j + 1 < len(lines) and _decision_key(lines[j + 1]) == _decision_key(lines[i]):
                j += 1
            run = lines[i:j + 1]
            if len(run) > 3:
                shown += [(run[0], None), (None, run), (run[-1], None)]
            else:
                shown += [(x, None) for x in run]
            i = j + 1
        steps = [{"from": "agent", "to": "enforcer", "label": f"request ({sc} {case})", "result": True,
                  "comment": "The agent makes a request through the enforcing service.", "drafts": None,
                  "record": None, "time": {"rel": lines[0]["ts"] - anchor, "dt": 0.0, "note": note},
                  "verdict": None}]
        prev = lines[0]["ts"]
        for ln, run in shown:
            verdict = {"expected": r["expected"], "observed": r["observed"], "ok": r["match"], "note": "Redthread's own comparison; observes_p1_p8.py re-checks decisions and reasons"}
            if run:  # the collapsed middle of a long run
                mid = run[1:-1]
                lab = f"\u2026 {len(mid)} more identical decisions ({run[0]['decision']}: {run[0]['reason']}), one per second"
                steps.append({"from": "enforcer", "to": "agent", "dashed": True, "label": lab, "result": run[0]["decision"] == "allow",
                              "comment": f"Between the two decisions shown, the record holds {len(mid)} more identical ones ({run[0]['decision']}, reason {run[0]['reason']}), one per simulated second.",
                              "drafts": None, "record": {"collapsed_decisions": len(mid), "from_ts": mid[0]["ts"], "to_ts": mid[-1]["ts"], "decision": run[0]["decision"], "reason": run[0]["reason"]},
                              "time": {"rel": mid[-1]["ts"] - anchor, "dt": mid[-1]["ts"] - prev, "note": note}, "verdict": verdict})
                prev = mid[-1]["ts"]
                continue
            steps.append({
                "from": "enforcer", "to": "agent", "dashed": True,
                "label": f"{ln['check']}: {ln['decision']} ({ln['reason']})", "result": ln["decision"] == "allow",
                "comment": f"{ln['check']}: {ln['decision']}, reason {ln['reason']}, effect {ln['effect']}.",
                "drafts": None, "record": ln,
                "time": {"rel": ln["ts"] - anchor, "dt": ln["ts"] - prev, "note": note}, "verdict": verdict})
            prev = ln["ts"]
        out.append({
            "id": f"redthread-{sc}-{case}".lower(), "title": f"{sc} {case} (Redthread)", "group": RT_GROUP[sc], "cls": "record",
            "description": RT_TEXT[sc], "expected": r["expected"],
            "capture": None, "record": {"file": f"scenarios/p1_p8/redthread-{sc}-local.jsonl", "url": RAW + f"scenarios/p1_p8/redthread-{sc}-local.jsonl"},
            "checker": "observes_p1_p8.py (manifest and digests)",
            "entities": row_layout([("agent", "Agent", "caller"), ("enforcer", "Enforcing service", f"Redthread runner {man['version']}")]), "frames": [],
            "steps": steps, "result": {"verdict": "PASS" if r["match"] else "FAIL", "text": f"observed {r['observed']}; expected {r['expected']}. Simulated clock; recorded, not executed here."}})
    return out


def build_cred():
    rows = jl("cred-P8.jsonl")
    cases = defaultdict(list)
    for r in rows:
        cases[r["case"]].append(r)
    desc = {"no-delegation": "Use without delegation, then ask for it: refused with 401, then 403 permission_required.",
            "write-under-read": "A read delegation is granted; a write attempt is refused (scope_insufficient).",
            "revoked-between-authz-and-use": "Revoked after approval, before the token is released: refused.",
            "revoked-after-token-released": "Cred refuses to release a raw bearer token by default; if released (deprecated mode), revocation cannot stop the provider call."}
    out = []
    for case, lines in cases.items():
        steps = []
        for i, ln in enumerate(lines):
            st = ln.get("step", ln["decision"])
            ok = ln["decision"] in ("allow", "revocation recorded", "revocation recorded, token already released", "effect occurred at provider")
            frm, to = ("agent", "cred")
            if ln["decision"].startswith("effect"):
                frm, to = "cred", "provider"
            elif ln["decision"] != "allow" or ln.get("http_status"):
                frm, to = "cred", "agent"
            steps.append({"from": frm, "to": to, "dashed": frm == "cred" and to == "agent",
                          "label": f"{st}: {ln['decision']}" + (f" (HTTP {ln['http_status']} {ln['cred_reason']})" if ln.get("http_status") else ""),
                          "result": ok and ln["decision"] != "deny", "comment": f"{st}: {ln['decision']}, reason {ln['reason']}; token released: {ln['token_released']}; effect: {ln['effect']}.",
                          "drafts": [D["cred"][0]], "record": ln, "time": {"rel": round(ln["ts"] - lines[0]["ts"], 3), "dt": round(ln["ts"] - (lines[i - 1]["ts"] if i else ln["ts"]), 3), "note": "wall clock"}, "verdict": None})
        out.append({"id": f"cred-p8-{case}", "title": f"P8 {case} (Cred)", "group": "revocation" if "revoked" in case else "authz", "cls": "record",
                    "description": desc[case], "expected": "", "capture": None,
                    "record": {"file": "scenarios/p1_p8/cred-P8.jsonl", "url": RAW + "scenarios/p1_p8/cred-P8.jsonl"},
                    "checker": "manifest digest only (not re-run here)",
                    "entities": row_layout([("agent", "Agent", ""), ("cred", "Cred", "cred-ninja/sdk 83e9cec"), ("provider", "Bearer-only API", "local mock")]), "frames": [],
                    "steps": steps, "result": {"verdict": "RECORD", "text": "Cred's own run of 15 Nov 2026, wall clock, against a local mock provider; recorded and hashed here, not re-run."}})
    return out


def build_mintid():
    rows = [json.loads(x) for x in (P1P8 / "revocation-trace-testnet-20261114T104257Z.jsonl").read_text().splitlines() if x.strip()]
    res = next(r for r in rows if r.get("kind") == "summary")["results"]
    out = []

    def tstep(frm, to, label, ok, comment, d, t_rel, note=""):
        return {"from": frm, "to": to, "label": label, "result": ok, "comment": comment, "drafts": [D["mintid"][0]],
                "record": {k: v for k, v in d.items() if k in ("utc", "agent", "attempt", "accepted", "reason_code", "session_id", "presented_root")} if d else None,
                "time": {"rel": round(t_rel, 1), "dt": 0.0, "note": note or "seconds after t0, wall clock"}, "verdict": None}
    for r in res:
        paths = [(r["path"], None)] if r["path"] != "cascade" else [("cascade", a) for a in r["per_agent"]]
        for path, agent in paths:
            src = r if agent is None else r["per_agent"][agent]
            t0 = r["t0"]
            lo, fn = src.get("last_ok"), src.get("first_no")
            name = {"issuer": "issuer revocation", "kill_switch": "holder kill switch"}.get(path, f"cascade, {agent}")
            steps = [{"from": "issuer", "to": "verifier", "label": f"t0: {r['t0_def']}", "result": True, "comment": f"Time zero, as MintID defines it: {r['t0_def']}.",
                      "drafts": [D["mintid"][0]], "record": None, "time": {"rel": 0.0, "dt": 0.0, "note": "seconds after t0"}, "verdict": None}]
            if lo:
                steps.append(tstep("agent", "verifier", f"+{lo['unix'] - t0:.1f} s: accepted", True, "The last time the verifier accepted the agent's proof: it still held the old status root.", lo, lo["unix"] - t0))
            if fn:
                steps.append(tstep("verifier", "agent", f"+{fn['unix'] - t0:.1f} s: refused ({fn['reason_code']})", False,
                                   "First refusal. The verifier cannot tell a revoked credential from one with a stale witness: both get the same code.", fn, fn["unix"] - t0))
            if agent is None and r.get("refresh_failed_at"):
                steps.append({"from": "issuer", "to": "agent", "dashed": True, "label": "witness refresh refused (credential_revoked)", "result": False,
                              "comment": "Attribution: the issuer refuses the revoked credential's witness refresh, while a never-revoked sibling refreshes and is accepted again.",
                              "drafts": [D["mintid"][0]], "record": None, "time": {"rel": round(r["refresh_failed_at"] - t0, 1), "dt": 0.0, "note": "seconds after t0"}, "verdict": None})
            bound = r["bound_seconds"]
            steps = steps[:1] + sorted(steps[1:], key=lambda x: x["time"]["rel"])
            for k in range(1, len(steps)):
                steps[k]["time"]["dt"] = round(steps[k]["time"]["rel"] - steps[k - 1]["time"]["rel"], 1)
            out.append({"id": f"mintid-{path}" + (f"-{agent}" if agent else ""), "title": f"MintID trace: {name}", "group": "revocation", "cls": "record",
                        "description": f"How long after the revocation does the verifier refuse? Promised bound {bound} s; measured last accepted {lo['unix'] - t0:.1f} s, first refused {fn['unix'] - t0:.1f} s (one run).",
                        "expected": f"refused within {bound} s", "capture": None,
                        "record": {"file": "scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.jsonl", "url": RAW + "scenarios/p1_p8/revocation-trace-testnet-20261114T104257Z.jsonl"},
                        "checker": "observes_p1_p8.py (manifest and trace checks)", "bound": bound,
                        "entities": row_layout([("agent", "Agent", ""), ("verifier", "MintID verifier", "mintid-testnet-3"), ("issuer", "MintID issuer", "")]), "frames": [],
                        "steps": steps, "result": {"verdict": "RECORD", "text": f"first refusal at {fn['unix'] - t0:.1f} s, within the {bound} s bound. MintID's own trace of 14 Nov 2026, recorded here, not re-run."}})
    return out


def build_sandbox_neg():
    rows = jl("redthread-P2-mintid-sandbox-negative.jsonl")
    out = []
    for case in dict.fromkeys(r["case"] for r in rows):
        ls = [r for r in rows if r["case"] == case]
        steps = []
        for ln in ls:
            outside = ln["check"] == "outside-verifier"
            steps.append({"from": "enforcer", "to": "verifier" if outside else "agent", "dashed": not outside,
                          "label": f"{ln['check']}: {ln['decision']} ({ln['reason']})", "result": ln["decision"] == "allow",
                          "comment": ("The enforcing hop asks the live MintID sandbox verifier for a fresh proof; it is refused, so no effect." if outside else "Authorized so far; the effect is still pending."),
                          "drafts": [D["mintid"][0], D["passport"][0]], "record": ln, "time": {"rel": 0.0, "dt": 0.0, "note": ln.get("utc", "")}, "verdict": None})
        out.append({"id": f"redthread-p2-sandbox-{case}", "title": f"P2 {case} (live MintID sandbox, 15 Nov)", "group": "revocation", "cls": "record",
                    "description": "Redthread's executor against the live MintID sandbox verifier on 15 Nov 2026 01:23 UTC: a negative control that must be refused before any effect.",
                    "expected": "deny before the effect", "capture": None,
                    "record": {"file": "scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.jsonl", "url": RAW + "scenarios/p1_p8/redthread-P2-mintid-sandbox-negative.jsonl"},
                    "checker": "observes_p1_p8.py (manifest and digests)",
                    "entities": row_layout([("agent", "Agent", ""), ("enforcer", "Enforcing hop", "Redthread"), ("verifier", "MintID verifier", "sandbox")]), "frames": [],
                    "steps": steps, "result": {"verdict": "RECORD", "text": "denied before the effect. A live call to the sandbox, recorded and hashed here."}})
    return out


def build_reports():
    out = []
    ent_p7 = row_layout([("person", "Person (device)", ""), ("agent", "Agent", ""), ("verifier", "Verifier", "holds the action")])
    for vec, mism, text in (("V5", False, "The approval text matches the action: accepted."), ("R2", True, "Same action and request digests, but the screen showed something else: refused, display-mismatch, the only reason.")):
        out.append({"id": f"p7-{vec.lower()}-omniarx", "title": f"P7 {vec} (OmniArx's verifier)", "group": "tricks" if mism else "normal", "cls": "report",
                    "description": "OmniArx's verifier run with OASNT Appendix A: key A.1, action A.2 (V1), request A.5 (V4), time 1800000000, fresh replay state. " + text,
                    "expected": "deny display-mismatch" if mism else "allow", "capture": None, "record": None, "checker": "none: reported by OmniArx, re-confirmed 17 Nov 2026",
                    "entities": ent_p7, "frames": [],
                    "steps": [
                        {"from": "agent", "to": "person", "label": "show approval text", "result": True, "comment": "The agent shows the person text describing the action.", "drafts": [D["oasnt"][0]], "record": None, "time": {"rel": 0.0, "dt": 0.0, "note": ""}, "verdict": None},
                        {"from": "person", "to": "agent", "dashed": True, "label": "approve: signed token with 3 digests", "result": True, "comment": "The person approves; the token carries digests of the action, the text shown and the HTTP request.", "drafts": [D["oasnt"][0]], "record": None, "time": {"rel": 0.0, "dt": 0.0, "note": ""}, "verdict": None},
                        {"from": "agent", "to": "verifier", "label": f"token {vec} + request", "result": True, "comment": "The agent sends the token and the request to a verifier that holds the action.", "drafts": [D["oasnt"][0]], "record": None, "time": {"rel": 0.0, "dt": 0.0, "note": ""}, "verdict": None},
                        {"from": "verifier", "to": "agent", "dashed": True, "label": "refused: display-mismatch" if mism else "accepted", "result": not mism,
                         "comment": ("The verifier recomputes the display digest from the action and finds a mismatch. A gateway that sees only the request would accept this token (OASNT-ENFORCE 5.1)." if mism else "All digests match; the action runs."),
                         "drafts": [D["oasnt"][0]], "record": None, "time": {"rel": 0.0, "dt": 0.0, "note": ""}, "verdict": None}],
                    "result": {"verdict": "REPORT", "text": "Reported by Arun Thallapelly (OmniArx); no record or run in this repository."}})
    ent17 = row_layout([("agent", "Agent", ""), ("enforcer", "Enforcing hop", "Redthread (simulated clock)"), ("verifier", "MintID sandbox", "real calls")])
    runs = {
        "issuer": ("Issuer route", "The issuer revokes the agent: the revoked agent's witness refresh is refused, so the first attempt after the revocation is refused.",
                   [("00:28:56.607", "valid agent: allowed, operation ran", True, 0), ("00:28:57.403", "issuer revocation response", True, 0.8),
                    ("00:28:59.000", "revoked agent: denied before the effect (credential_revoked)", False, 2.4), ("00:29:40.804", "revoked agent again: denied", False, 44.2)]),
        "killswitch": ("Kill-switch route", "The agent revokes itself: it can still answer from a witness it already held, valid until the next status commitment.",
                       [("00:30:03.416", "valid agent: allowed", True, 0), ("00:30:13.410", "self-revocation recorded", True, 10.0),
                        ("00:30:19.226", "attempt 5.8 s after self-revocation: accepted on a witness held from custody", True, 15.8), ("00:31:00.996", "attempt at 47.6 s: denied before the effect (credential_revoked)", False, 57.6)]),
    }
    for key, (name, desc, evs) in runs.items():
        steps = [{"from": "agent", "to": "enforcer", "dashed": not ok and False, "label": f"{utc}  {lab}", "result": ok, "comment": lab + ". Time from Redthread's 17 Nov 2026 message, as reported.",
                  "drafts": [D["mintid"][0], D["passport"][0]], "record": None, "time": {"rel": rel, "dt": 0.0, "note": "seconds after the first call, UTC clock of the MintID sandbox"}, "verdict": None}
                 for utc, lab, ok, rel in evs]
        out.append({"id": f"redthread-p2-17nov-{key}", "title": f"P2 {name}, 17 Nov (Redthread)", "group": "revocation", "cls": "report",
                    "description": desc + " The calls to MintID were real; Redthread's own verifier chain ran on a simulated clock.", "expected": "no operation after the refused witness refresh",
                    "capture": None, "record": None, "checker": "none: record sent 17 Nov (commit 64f7a64), not yet committed here",
                    "entities": ent17, "frames": [], "steps": steps,
                    "result": {"verdict": "REPORT", "text": "Reported by Ben Le (Redthread); times from his email of 17 Nov 2026. The record is not yet in this repository."}})
    return out


# ------------------------------------------------------------------ break it
def run_checker(script, pcap):
    r = subprocess.run([sys.executable, str(ROOT / "checkers" / script), str(ROOT / "checkers" / "negatives" / pcap)], capture_output=True, text=True, check=False)
    lines = [ln for ln in (r.stderr + r.stdout).splitlines() if ln.startswith(("FAIL", "SUMMARY"))]
    if r.returncode == 0:
        raise SystemExit(f"negative {pcap} was accepted by {script}")
    return "\n".join(lines[:4]) or (r.stderr.strip().splitlines() or ["rejected"])[-1]


def add_breaks(scens):
    by_id = {s["id"]: s for s in scens}
    out = {n: run_checker(s, n) for s, n in (("observes_chain.py", "chain_hop_flipped.pcap"), ("observes_chain.py", "chain_leaked_txn.pcap"),
                                              ("observes_chain.py", "chain_leaked_txn_body.pcap"), ("observes_chain.py", "chain_request_only.pcap"),
                                              ("observes_wimse.py", "request_only.pcap"), ("observes_wimse.py", "forbidden_fetch.pcap"),
                                              ("observes_p1_p8.py", "p1_p8_missing_before_effect.pcap"), ("observes_p1_p8.py", "p1_p8_request_only.pcap"))}
    leak_step = {"from": "client", "to": "research", "label": "POST /research  (Domain A Txn-Token leaked to Domain B)", "result": False, "injected": True,
                 "comment": "The mutant: a Domain A Transaction Token (aud maurice.ietf127.example) appears in a request to a Domain B port. The checker must reject it.", "drafts": [D["txn"][0]], "http": None, "time": {"rel": 0.0, "dt": 0.0}, "verdict": None}
    for s in scens:
        if s["cls"] == "wire":
            kind = "inbound" if s["capture"]["file"] == INBOUND else "chain"
            req_only = "request_only.pcap"
            s["breaks"] = [{"name": "Responses stripped", "mutant": req_only if kind == "inbound" else "chain_request_only.pcap",
                            "description": "Every response removed from the capture: there is no evidence of any decision.", "strip_responses": True,
                            "checker_output": out[req_only] if kind == "inbound" else out["chain_request_only.pcap"]}]
    by_id["B_CHAIN"]["breaks"] += [
        {"name": "Leaked token in a header", "mutant": "chain_leaked_txn.pcap", "description": "A Domain A Txn-Token is sent to Domain B in a header.", "add_step": leak_step, "checker_output": out["chain_leaked_txn.pcap"]},
        {"name": "Leaked token in a body", "mutant": "chain_leaked_txn_body.pcap", "description": "The same token is hidden in a request body (an untagged request, so only the body scan notices).", "add_step": leak_step, "checker_output": out["chain_leaked_txn_body.pcap"]}]
    by_id["C7"]["breaks"].append({"name": "One hop flipped", "mutant": "chain_hop_flipped.pcap", "description": "An intermediate hop (the call to TTS-B) is changed from 200 to 403. The set of statuses is unchanged, so only the hop-by-hop comparison catches it.",
                                  "set_status": {"step": 1, "status": 403}, "checker_output": out["chain_hop_flipped.pcap"]})
    for cid in ("C12", "C12b"):
        by_id[cid]["breaks"].append({"name": "Forbidden fetch", "mutant": "forbidden_fetch.pcap", "description": "Maurice connects to the attacker's URL on :47999. The checker must reject any connection there.",
                                     "add_step": {"from": "maurice", "to": "attacker", "label": "TCP connection to :47999 (forbidden)", "result": False, "injected": True, "comment": "The mutant: a connection to the attacker's address.", "drafts": [D["wit"][0]], "http": None, "time": {"rel": 0.0, "dt": 0.0}, "verdict": None},
                                     "checker_output": out["forbidden_fetch.pcap"]})
    for s in scens:
        if s["id"] == "p2-before-effect":
            s["breaks"] = [{"name": "Re-check missing", "mutant": "p1_p8_missing_before_effect.pcap", "description": "The capture is cut before the before-effect response.", "strip_responses": True, "checker_output": out["p1_p8_missing_before_effect.pcap"]}]
        elif s["id"].startswith(("p2-", "p7-", "p8-")) and s["cls"] in ("sim", "mock"):
            s["breaks"] = [{"name": "Responses stripped", "mutant": "p1_p8_request_only.pcap", "description": "Every response removed from the capture.", "strip_responses": True, "checker_output": out["p1_p8_request_only.pcap"]}]


# ------------------------------------------------------------------ tags (what a scenario shows)
# Result is derived from the data. Checks and topic are curated here; the build fails if a scenario has none.
RESULT_ITEMS = [
    ("accepted", "Accepted", "Every decision in the scenario is an accept."),
    ("refused", "Refused", "Every decision is a refusal: the scenario passes when the system refuses."),
    ("mixed", "Accepted and refused", "Some decisions are accepts and some refusals, for example a replay that is accepted once and then refused."),
]
CHECK_ITEMS = [
    ("validation", "Validation", "Is the credential or message genuine, fresh, well-formed and bound to this request and receiver? (signatures, badges, expiry, audience, replay, identifier syntax)"),
    ("enforcement", "Enforcement", "Is this caller allowed to do this? Policy applied to an authenticated caller: grants, scope, delegation limits, revocation and status, pinning."),
    ("containment", "Containment", "Hostile content or addresses (prompt injection, attacker URLs, unsigned claims) must not change what happens."),
    ("flow", "End-to-end flow", "A normal exchange across several entities: token exchange, delegation, narrowing."),
    ("timing", "Timing", "How quickly a change, such as a revocation, takes effect, against a bound."),
]
TOPIC_ITEMS = [
    ("identity", "Identity", "The WIT (workload badge), issuer trust, workload identifier syntax and comparison."),
    ("signature", "Signature and proof", "HTTP message signatures, the WPT, key and algorithm checks."),
    ("replay", "Replay", "A signed request sent again."),
    ("audience", "Audience", "A token or request meant for a different receiver."),
    ("tampering", "Tampering", "Content changed after it was signed, or in transit."),
    ("tokenvalidity", "Token validity", "Expiry, issuer key, token type and required claims."),
    ("scope", "Scope and grants", "What the caller may do, and which route it may use."),
    ("delegation", "Delegation", "Narrowing, widening and limits when authority is handed on."),
    ("crossdomain", "Cross-domain", "Domain A's authority must stay in A; Domain B issues its own, narrower one."),
    ("revocation", "Revocation and status", "Withdrawn permission, status lists, and what happens after."),
    ("failclosed", "Fail closed", "When status is unknown, stale or unreachable, refuse."),
    ("injection", "Injection and hostile addresses", "Prompt injection, attacker URLs."),
    ("approval", "Approval integrity", "What the person saw must match what is executed."),
    ("pinning", "Tool and build pinning", "The approved tool or build must be the one that runs."),
]
V, E, C_, F, T = "validation", "enforcement", "containment", "flow", "timing"
CURATED = {
    # Suite 1 (inbound)
    "A2": ([V], ["signature"]), "A3": ([V], ["signature"]), "A4": ([V], ["signature"]), "A5": ([V], ["signature"]),
    "A6a": ([V], ["signature"]), "A6b": ([V], ["signature"]),
    "A12a": ([V], ["identity", "signature"]), "A12b": ([V], ["identity", "signature"]), "A12c": ([V], ["identity", "signature"]), "A12d": ([V], ["identity", "signature"]),
    **{f"A13{x}": ([V], ["identity"]) for x in "abcdefghi"}, "A13j": ([E], ["identity", "scope"]),
    "C2": ([V], ["signature"]), "C3": ([V], ["replay"]), "C4": ([V], ["audience"]), "C4b": ([V], ["audience"]),
    "C11": ([V], ["identity"]), "C12": ([C_], ["injection", "identity"]), "C12b": ([C_], ["injection", "identity"]),
    "IN4": ([V], ["identity"]), "IN6": ([V], ["identity"]), "IN10": ([V], ["tampering"]), "IN11": ([V], ["signature"]),
    "IN12": ([V], ["signature"]), "IN13": ([V], ["signature"]), "IN15": ([E], ["scope"]),
    # Suite 2 (chain)
    "B_CHAIN": ([F], ["crossdomain", "delegation"]), "C5": ([V], ["tampering", "signature"]), "C6": ([E], ["crossdomain", "audience"]),
    "C7": ([C_, E], ["injection", "scope"]), "C8": ([C_], ["injection"]), "C9": ([E], ["scope"]), "C9b": ([E], ["scope"]), "C10": ([E], ["revocation"]),
    "D1": ([V], ["tampering", "signature"]), "D2": ([V], ["signature", "tampering"]),
    **{k: ([V], ["tokenvalidity"]) for k in ("D3_exp", "D3_sig", "D3_typ", "D3_reqwl", "D3_dup")},
    "D4": ([E], ["scope"]), "D5": ([V], ["crossdomain", "tokenvalidity"]), "D6": ([F], ["delegation", "crossdomain"]), "D7": ([V], ["crossdomain", "audience"]),
    # :5064 loopback cases
    "p2-revoke-upstream": ([E, T], ["revocation"]), "p2-before-effect": ([E], ["revocation"]),
    "p2-outside-made-up-proof": ([E], ["revocation"]), "p2-outside-no-agent-answer": ([E], ["revocation", "failclosed"]),
    "p7-display-match": ([E], ["approval"]), "p7-display-mismatch": ([E], ["approval"]),
    "p8-no-delegation": ([E], ["scope"]), "p8-write-under-read": ([E], ["scope"]),
    "p8-revoked-between-authz-and-use": ([E], ["revocation"]), "p8-revoked-after-token-released": ([E], ["revocation"]),
    # partner records and reports
    "redthread-p1-confirmed-revocation": ([E], ["revocation"]), "redthread-p1-expired-cache": ([E], ["failclosed"]),
    "redthread-p1-service-unavailable": ([E], ["failclosed"]), "redthread-p1-low-value-grace": ([E], ["failclosed", "revocation"]),
    "redthread-p1-one-element-in-chain": ([E], ["failclosed"]),
    "redthread-p2-revoke-upstream": ([E, T], ["revocation"]), "redthread-p2-before-effect": ([E], ["revocation"]),
    **{f"redthread-p3-{k}": ([E], ["delegation"]) for k in ("wider-host", "more-methods", "longer-lifetime", "dropped-tools", "absent-means-default")},
    "redthread-p3-unknown-member": ([E], ["delegation", "failclosed"]),
    **{f"redthread-p4-{k}": ([E], ["delegation"]) for k in ("per-rp-counting", "single-accounting-rp", "child-limit-wider")},
    "redthread-p5-rewrite-authority": ([V], ["tampering", "signature"]), "redthread-p5-rewrite-path": ([V], ["tampering", "signature"]),
    "redthread-p5-authenticated-proxy-verifies": ([V], ["signature"]), "redthread-p5-forwarded-headers-unauthenticated": ([C_], ["tampering"]),
    "redthread-p6-build-changed": ([E], ["pinning"]), "redthread-p6-tool-swapped": ([E], ["pinning"]),
    "redthread-p2-sandbox-outside-made-up-proof": ([E], ["revocation"]), "redthread-p2-sandbox-outside-no-agent-answer": ([E], ["revocation", "failclosed"]),
    "cred-p8-no-delegation": ([E], ["scope"]), "cred-p8-write-under-read": ([E], ["scope"]),
    "cred-p8-revoked-between-authz-and-use": ([E], ["revocation"]), "cred-p8-revoked-after-token-released": ([E], ["revocation"]),
    "mintid-issuer": ([T, E], ["revocation"]), "mintid-kill_switch": ([T, E], ["revocation"]),
    "mintid-cascade-cascade_agent_1": ([T, E], ["revocation"]), "mintid-cascade-cascade_agent_2": ([T, E], ["revocation"]),
    "p7-v5-omniarx": ([E], ["approval"]), "p7-r2-omniarx": ([E], ["approval"]),
    "redthread-p2-17nov-issuer": ([T, E], ["revocation"]), "redthread-p2-17nov-killswitch": ([T, E], ["revocation"]),
}


def decision_of(st):
    """'allow', 'deny' or None for one step: from the reply status, the partner's recorded decision, or its wording."""
    if st.get("reply"):
        return "deny" if st["reply"]["status"] >= 400 else "allow"
    rec = st.get("record") or {}
    if "accepted" in rec:
        return "allow" if rec["accepted"] else "deny"
    d = str(rec.get("decision", ""))
    if d in ("allow", "effect occurred at provider"):
        return "allow"
    if d == "deny":
        return "deny"
    if not rec:
        lab = st.get("label", "").lower()
        if "refused" in lab or "denied" in lab:
            return "deny"
        if "accepted" in lab or "allowed" in lab:
            return "allow"
    return None


def tags_for(scen):
    decisions = [d for d in (decision_of(st) for st in scen["steps"]) if d]
    if not decisions:
        raise SystemExit(f"{scen['id']}: no decision found, cannot derive a result tag")
    result = "mixed" if len(set(decisions)) > 1 else ("accepted" if decisions[0] == "allow" else "refused")
    if scen["id"] not in CURATED:
        raise SystemExit(f"{scen['id']}: no checks/topic tags in CURATED")
    checks, topics = CURATED[scen["id"]]
    return {"result": [result], "checks": list(checks), "topic": list(topics)}


# ------------------------------------------------------------------ whole TCP conversations
def stream_packets(capture):
    """All TCP packets of a capture, grouped by TCP stream."""
    cmd = ["tshark", "-r", str(ROOT / capture), "-Y", "tcp", "-T", "fields", "-e", "tcp.stream", "-e", "frame.number",
           "-e", "frame.time_relative", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.flags", "-e", "tcp.len",
           "-e", "tcp.analysis.window_update"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    streams = defaultdict(list)
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 7 or not f[0]:
            continue
        streams[int(f[0])].append({"frame": int(f[1]), "t": float(f[2]), "src": int(f[3]), "dst": int(f[4]),
                                   "flags": int(f[5], 16), "len": int(f[6] or 0), "wu": len(f) > 7 and f[7] == "1"})
    return streams


def label_packets(pkts):
    """Plain-language label for each packet of one connection (the 'phone call' view)."""
    pkts = sorted(pkts, key=lambda p: p["frame"])
    for p in pkts:
        p["dir"] = "c2s" if p["dst"] in PORT_ENT else "s2c"
    n_req = sum(1 for p in pkts if p["len"] and p["dir"] == "c2s")
    n_resp = sum(1 for p in pkts if p["len"] and p["dir"] == "s2c")
    out, k_req, k_resp, t0, prev = [], 0, 0, pkts[0]["t"], None
    for p in pkts:
        f, d = p["flags"], p["dir"]
        syn, ack, fin, rst = f & 2, f & 16, f & 1, f & 4
        kind = "plumbing"
        if syn and not ack:
            title, text = "Dial", "The client asks the server to open a connection, like dialing a phone."
        elif syn:
            title, text = "Pick up", "The server says yes, it is listening."
        elif rst:
            title, text = "Refused or cut", "Nobody is listening there, or one side hung up abruptly."
        elif p["len"] and d == "c2s":
            k_req += 1
            kind = "content"
            title = "Request" + (f", part {k_req} of {n_req}" if n_req > 1 else "")
            text = "What the client says" + (": the request line and headers (badge, signature)." if k_req == 1 else ": the rest of the request (the body).")
        elif p["len"]:
            k_resp += 1
            kind = "content"
            title = "Response" + (f", part {k_resp} of {n_resp}" if n_resp > 1 else "")
            text = "What the server says back: the status and the answer."
        elif fin:
            title, text = "Hang up", "This side says it is done and closes its end of the connection."
        elif p["wu"]:
            title, text = "Room for more", "Housekeeping: the receiver announces how much more data it can take."
        elif prev is not None and prev["flags"] & 2 and prev["flags"] & 16:
            title, text = "Line open", "The client confirms: the connection is established."
        else:
            title, text = "Got it", "Housekeeping: confirms that the data just sent arrived."
        rec = {"n": p["frame"], "t": round((p["t"] - t0) * 1000, 3), "dir": d, "label": title, "kind": kind, "len": p["len"], "text": text}
        if prev is not None and p["t"] - prev["t"] > 0.02:
            rec["gap_ms"] = round((p["t"] - prev["t"]) * 1000)
        out.append(rec)
        prev = p
    return out


# ------------------------------------------------------------------ main
def main():
    DATA.mkdir(parents=True, exist_ok=True)
    cases = json.loads((ROOT / "cases.json").read_text())["cases"]
    chain = {c["id"]: c for c in json.loads((ROOT / "chain_cases.json").read_text())}
    cases = {c["id"]: c for c in cases}
    group_of = {}
    for row in CASES:
        for i in row["ids"]:
            group_of[i] = row["group"]
    missing = (set(cases) | set(chain)) - set(group_of)
    if missing:
        raise SystemExit(f"cases without a group: {sorted(missing)}")

    inb = exchanges(INBOUND, [5050, 47999])
    cha = exchanges(CHAIN, [5050, 5051, 5060, 5061, 5062, 5063, 5064])
    scens = []
    s_in = build_wire(inb, cases, group_of.get, "inbound")
    for s in s_in:
        verdict_inbound(s, cases[s["id"]])
    s_ch = build_wire(cha, chain, group_of.get, "chain")
    for s in s_ch:
        verdict_chain(s, chain[s["id"]])
    scens += s_in + s_ch + build_5064(cha) + build_redthread() + build_sandbox_neg() + build_cred() + build_mintid() + build_reports()
    ids = [s["id"] for s in scens]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise SystemExit(f"duplicate scenario ids: {sorted(dup)}")
    add_breaks(scens)
    pk = {INBOUND: stream_packets(INBOUND), CHAIN: stream_packets(CHAIN)}
    for s in scens:
        for st in s["steps"]:
            h = st.get("http")
            if h and s.get("capture"):
                pkts = label_packets(pk[s["capture"]["file"]][h["stream"]])
                st["packets"] = pkts
                st["tokens"], st["reply"] = enrich(h)
                h["req_first"] = min((p["n"] for p in pkts if p["kind"] == "content" and p["dir"] == "c2s"), default=h["frame"])
                h["resp_first"] = min((p["n"] for p in pkts if p["kind"] == "content" and p["dir"] == "s2c"), default=h["resp_frame"])
    for s in scens:
        s["tags"] = tags_for(s)
    unknown = set(CURATED) - {s["id"] for s in scens} - set(PENDING_RERECORD)  # pending cases have no scenario yet
    if unknown:
        raise SystemExit(f"CURATED has ids that are not scenarios: {sorted(unknown)}")
    for s in scens:
        s.setdefault("breaks", [])
        if s["frames"]:
            used = {e["id"] for e in s["entities"]}
            s["context"] = [ent(e) for e in ENT if e not in used]
        s["drafts"] = drafts_for(s["id"], s["group"], s["cls"])
        for st in s["steps"]:
            st.pop("_ex", None)
        (DATA / f"{s['id']}.json").write_text(json.dumps(s, ensure_ascii=False, separators=(",", ":")))
    index = {
        "repo": REPO, "built_from": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT, check=False).stdout.strip(),
        "classes": {k: {"label": v[0], "meaning": v[1]} for k, v in CLASSES.items()},
        "groups": [{"id": g, "name": n, "question": q} for g, n, q in GROUPS],
        "tag_facets": [{"id": fid, "name": fname, "items": [{"id": i, "label": lab, "meaning": m} for i, lab, m in items]}
                       for fid, fname, items in (("result", "Result", RESULT_ITEMS), ("checks", "Checks", CHECK_ITEMS), ("topic", "Topic", TOPIC_ITEMS))],
        "scenarios": [{"id": s["id"], "title": s["title"], "group": s["group"], "cls": s["cls"], "tags": s["tags"], "steps": len(s["steps"]),
                       "messages": sum(2 if st.get("http") else 1 for st in s["steps"]),
                       "short": (s["description"] if len(s["description"]) <= 150 else s["description"][:150].rsplit(" ", 1)[0] + "\u2026")} for s in scens],
    }
    (DATA / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1))
    by_cls = defaultdict(int)
    for s in scens:
        by_cls[s["cls"]] += 1
    print(f"{len(scens)} scenarios:", dict(by_cls), "| wire cases:", len(s_in) + len(s_ch))


if __name__ == "__main__":
    main()
