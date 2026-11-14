"""Client peer: runs the WIMSE inbound cases against Maurice and exits 0 only if every case matched.

Expectations come from cases.json. Each request carries an unsigned `X-Test-Case: <id>` header so the
independent checker can pair requests with cases in the capture. Maurice's decision journal is
read to compare the precise reject reason (HTTP responses must not reveal it).
"""
import argparse, hashlib, json, pathlib, socketserver, sys, threading, time
from cryptography.hazmat.primitives import serialization

import wimse as w

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET = json.loads((ROOT / "setup/target.json").read_text())
CASES = {c["id"]: c for c in json.loads((ROOT / "cases.json").read_text())["cases"]}
URL = f'{TARGET["base"]}/api/v2/agents/{TARGET["agent"]}/workflows/{TARGET["workflow"]}/executions'
AUD = TARGET["base"]
PEER = "wimse://peer.ietf127.example"
ISS = "http://peer.ietf127.example"
JOURNAL = pathlib.Path.home() / ".maurice/one/logs/wimse-decisions.jsonl"
PTYPE = "https://iana.org/assignments/http-problem-types#"
BODY = json.dumps({"inputs": {"text": "hello wimse"}}).encode()


def load_key(name):
    return serialization.load_pem_private_key((ROOT / f"keys/{name}.pem").read_bytes(), None)


PEER_KEY, ROGUE_KEY = load_key("peer"), load_key("rogue")


class Ident:
    """A fresh workload key plus a WIT for it."""

    def __init__(self, sub=f"{PEER}/client", *, iss=ISS, issuer_key=PEER_KEY, kid="peer-1", kind="ES256", alg=None, **wit_kw):
        self.key = w.new_workload_key(kind)
        self.alg = alg or ("ES256" if kind == "ES256" else "Ed25519")
        self.wit = w.issue_wit(issuer_key, kid=kid, iss=iss, sub=sub, workload_pub_jwk=w.jwk_from_public(self.key.public_key(), alg=self.alg), **wit_kw)

    def sig(self, **kw):
        return w.http_sig("POST", URL, BODY, self.wit, self.key, aud=kw.pop("aud", AUD), **kw)

    def wpt(self, **kw):
        return w.wpt_request("POST", URL, BODY, self.wit, self.key, aud=kw.pop("aud", AUD), alg=kw.pop("alg", self.alg), **kw)


def ident_sub(sub, **kw):
    return [Ident(sub, **kw).sig()]


def build(cid):
    """Return the list of Req for a case (one per expectation step)."""
    now = int(time.time())
    simple = {
        "A2": lambda: [Ident().sig()],
        "A3": lambda: [Ident().sig(sign_response=True)],
        "A4": lambda: [Ident().wpt()],
        "A5": lambda: [w.Req("POST", URL, {"Workload-Identity-Token": Ident().wit, "Content-Type": "application/json"}, BODY)],
        "A6a": lambda: [Ident().sig(headers={"X-API-Key": "stolen-key-not-real"})],
        "A6b": lambda: mixed_bearer(),
        "A12a": lambda: [Ident(kind="Ed25519", alg="Ed25519").sig()],
        "A12b": lambda: [Ident(kind="Ed25519", alg="EdDSA").sig()],
        "A12c": lambda: [Ident(kind="Ed25519", alg="Ed25519").wpt()],
        "A12d": lambda: [Ident(kind="Ed25519", alg="EdDSA").wpt()],
        "A13a": lambda: ident_sub("wimse://peer.ietf127.example"),
        "A13b": lambda: ident_sub(f"{PEER}/a/./b"),
        "A13c": lambda: ident_sub(f"{PEER}/a/../b"),
        "A13d": lambda: ident_sub(f"{PEER}/a/%2E%2E/b"),
        "A13e": lambda: ident_sub("wimse://peer.ietf127.example:8080/client"),
        "A13f": lambda: ident_sub(f"{PEER}/client?x=1"),
        "A13g": lambda: ident_sub(f"{PEER}/client#f"),
        "A13h": lambda: ident_sub("wimse://user@peer.ietf127.example/client"),
        "A13i": lambda: ident_sub("wimse://Peer.Ietf127.Example/a%7Eb"),
        "A13j": lambda: ident_sub(f"{PEER}/a%2Fb"),
        "C4": lambda: [Ident().sig(aud="http://rich.ietf127.example")],
        "C4b": lambda: [Ident().sig(aud=AUD + "/")],
        "C11": lambda: ident_sub("wimse://rogue.ietf127.example/client", iss="http://rogue.ietf127.example", issuer_key=ROGUE_KEY, kid="rogue-1"),
        "C12": lambda: ident_sub(f"{PEER}/client", iss="http://127.0.0.1:47999/jwks.json"),
        "C12b": lambda: ident_sub("wimse://lax.ietf127.example/client", iss="http://127.0.0.1:47999/jwks.json"),
        "IN4": lambda: [Ident(now=now - 7200, ttl=3600).sig()],
        "IN6": lambda: ident_sub(f"{PEER}/client", iss="http://other.ietf127.example"),
        "IN10": lambda: [Ident().sig(tamper_digest=True)],
        "IN11": lambda: [Ident().sig(extra_signature=True)],
        "IN12": lambda: [Ident().sig(keyid_param="peer-1")],
        "IN13": lambda: [Ident(kind="Ed25519", alg="Ed25519").wpt(alg="EdDSA")],
        "IN15": lambda: ident_sub(f"{PEER}/ungranted"),
    }
    if cid == "C2":  # genuine WIT, signature made by a key that is not in cnf
        victim = Ident()
        return [w.http_sig("POST", URL, BODY, victim.wit, w.new_workload_key(), aud=AUD)]
    if cid == "C3":
        r = Ident().sig()
        return [r, r]
    return simple[cid]()


def mixed_bearer():
    """Send both a valid WPT and a Bearer credential as separate header fields."""
    req = Ident().wpt()
    req.extra_headers.append(("Authorization", "Bearer not-a-real-token"))
    return [req]


class _Sink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    hits = 0


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        type(self.server).hits += 1
        self.request.recv(1024)
        self.request.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def journal_entry(wit, offset, timeout=2, allow_unfingerprinted=False):
    """Find this request's decision, ignoring concurrent journal entries."""
    fingerprint = "sha256:" + hashlib.sha256(wit.encode()).hexdigest()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if JOURNAL.exists():
            with JOURNAL.open() as f:
                f.seek(offset)
                for line in f:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("direction") != "inbound":
                        continue
                    if entry.get("wit_sha256") == fingerprint:
                        return entry
                    # Maurice rejects mixed credentials before parsing the WIT, so its entry has
                    # no fingerprint; match it by reason within this request's journal window.
                    if allow_unfingerprinted and not entry.get("wit_sha256") and entry.get("reason") == "mixed-credentials":
                        return entry
        time.sleep(0.05)
    return None


def check(cid, case, journal_out=None):
    reqs = build(cid)
    steps = case["steps"]
    assert len(reqs) == len(steps), f"{cid}: {len(reqs)} requests, {len(steps)} expectations"
    ok, notes = True, []
    for i, (req, exp) in enumerate(zip(reqs, steps), 1):
        before = JOURNAL.stat().st_size if JOURNAL.exists() else 0
        r = w.send(req, case=cid)
        entry = journal_entry(req.headers.get("Workload-Identity-Token", ""), before,
                              allow_unfingerprinted="mixed-credentials" in exp.get("reason", []))
        got_reason = (entry.get("reason") or entry.get("decision")) if entry else None
        if journal_out:
            with journal_out.open("a") as out:
                out.write(json.dumps({"case": cid, "step": i, "decision": entry}) + "\n")
        step_ok = r.status in exp["status"]
        if "type" in exp:
            step_ok &= r.problem_type == PTYPE + exp["type"]
        if "www_authenticate" in exp:
            step_ok &= exp["www_authenticate"].lower() in r.headers.get("www-authenticate", "").lower()
        if exp.get("reason"):
            step_ok &= got_reason in exp["reason"]
        ok &= step_ok
        notes.append(f"step={i} status={r.status} want={exp['status']} type={r.problem_type.rsplit('#', 1)[-1] or '-'} reason={got_reason} want_reason={exp.get('reason', '-')} {'ok' if step_ok else 'MISMATCH'}")
    return ok, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="all", help="comma-separated ids or 'all'")
    ap.add_argument("--journal-out", type=pathlib.Path, help="write matching decision entries into the evidence bundle")
    a = ap.parse_args()
    ids = list(CASES) if a.cases == "all" else a.cases.split(",")
    if a.journal_out:
        a.journal_out.parent.mkdir(parents=True, exist_ok=True)
        a.journal_out.write_text("")
    srv = _Sink(("127.0.0.1", 47999), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    failed = []
    for cid in ids:
        before_hits = _Sink.hits
        try:
            ok, notes = check(cid, CASES[cid], a.journal_out)
        except Exception as e:  # a case that cannot run is a failure, not a skip
            ok, notes = False, [f"error {type(e).__name__}: {e}"]
        if CASES[cid].get("no_fetch_port") and _Sink.hits != before_hits:
            ok, notes = False, notes + ["Maurice fetched the attacker URL"]
        print(f"CASE {cid} [{CASES[cid]['ref']}] {'PASS' if ok else 'FAIL'} :: {CASES[cid]['title']} :: " + "; ".join(notes), flush=True)
        if not ok:
            failed.append(cid)
    srv.shutdown()
    print(f"SUMMARY total={len(ids)} failed={len(failed)} {failed}", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
