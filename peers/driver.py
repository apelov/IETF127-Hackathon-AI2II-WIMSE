"""Client peer: runs the WIMSE inbound cases against a WIMSE-verifying server (default: Maurice) and
exits 0 only if every case matched.

Expectations come from cases.json. The target defaults to Maurice (setup/target.json); point it at
another server with --target / --base / --route (see RUN_YOUR_IMPLEMENTATION.md). Each request
carries an unsigned `X-Test-Case: <id>` header so the independent checker can pair requests with
cases in the capture. Maurice's decision journal is read to compare the precise reject reason (HTTP
responses must not reveal it); `--wire-only` (or `"journal": false` in the target file) skips that
and judges status and problem type only.
"""
import argparse
import hashlib
import json
import pathlib
import socketserver
import sys
import threading
import time
import urllib.parse
from cryptography.hazmat.primitives import serialization

import wimse as w

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_TARGET = ROOT / "setup/target.json"
CASES = {c["id"]: c for c in json.loads((ROOT / "cases.json").read_text())["cases"]}
APPLICABILITY = json.loads((ROOT / "cases_applicability.json").read_text())
DEFAULT_ROUTE = "/api/v2/agents/{agent}/workflows/{workflow}/executions"
TARGET_FIELDS = {"base", "agent", "workflow", "route", "audience", "journal"}


class TargetError(ValueError):
    """The target configuration is unusable; the message says which field and why."""


def load_target(path=None, *, base=None, route=None, audience=None, agent=None, workflow=None, journal=None):
    """Build the target settings: the file (default setup/target.json), then explicit overrides.

    Returns a dict with base, route (template), url, audience, journal, agent, workflow. With no
    arguments the result is what the driver always used for Maurice: the Maurice route,
    audience == base, decision-journal comparison on.
    """
    path = pathlib.Path(path) if path else DEFAULT_TARGET
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError:
        raise TargetError(f"target file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise TargetError(f"{path}: not valid JSON ({e})") from None
    if not isinstance(raw, dict):
        raise TargetError(f"{path}: must be a JSON object")
    unknown = sorted(k for k in raw if k not in TARGET_FIELDS and not k.startswith("_"))
    if unknown:
        raise TargetError(f"{path}: unknown field(s) {unknown}; allowed: {sorted(TARGET_FIELDS)} (keys starting with _ are comments)")
    t = {k: v for k, v in raw.items() if k in TARGET_FIELDS}
    overrides = (("base", base), ("route", route), ("audience", audience), ("agent", agent), ("workflow", workflow), ("journal", journal))
    t.update({k: v for k, v in overrides if v is not None})
    if "base" not in t:
        raise TargetError(f"{path}: missing required field 'base' (for example http://127.0.0.1:8080)")
    for k in ("base", "route", "audience", "agent", "workflow"):
        if k in t and not isinstance(t[k], str):
            raise TargetError(f"'{k}' must be a string")
    if "journal" in t and not isinstance(t["journal"], bool):
        raise TargetError("'journal' must be true or false")
    u = urllib.parse.urlsplit(t["base"])
    if u.scheme != "http":
        raise TargetError(f"base {t['base']!r}: only http:// is supported (the driver sends plain HTTP so the capture is readable)")
    if not u.hostname or u.path or u.query or u.fragment or u.username:
        raise TargetError(f"base {t['base']!r}: must be http://host[:port] with no path, trailing slash, query or credentials")
    t.setdefault("route", DEFAULT_ROUTE)
    if not t["route"].startswith("/"):
        raise TargetError(f"route {t['route']!r}: must start with /")
    try:
        route_path = t["route"].format_map(t)
    except KeyError as e:
        raise TargetError(f"route {t['route']!r} uses {{{e.args[0]}}} but the target has no field {e.args[0]!r}; set it in the file or on the command line") from None
    except (ValueError, IndexError) as e:
        raise TargetError(f"route {t['route']!r}: bad template ({e}); use {{agent}}, {{workflow}} or fixed text") from None
    t.setdefault("audience", t["base"])
    t.setdefault("journal", True)
    t["url"] = t["base"] + route_path
    return t


TARGET = load_target()
URL = TARGET["url"]
AUD = TARGET["audience"]
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


def check(cid, case, journal_out=None, journal=True):
    reqs = build(cid)
    steps = case["steps"]
    assert len(reqs) == len(steps), f"{cid}: {len(reqs)} requests, {len(steps)} expectations"
    ok, notes = True, []
    for i, (req, exp) in enumerate(zip(reqs, steps), 1):
        before = JOURNAL.stat().st_size if journal and JOURNAL.exists() else 0
        r = w.send(req, case=cid)
        entry = journal_entry(req.headers.get("Workload-Identity-Token", ""), before,
                              allow_unfingerprinted="mixed-credentials" in exp.get("reason", [])) if journal else None
        got_reason = (entry.get("reason") or entry.get("decision")) if entry else None
        if journal_out:
            with journal_out.open("a") as out:
                out.write(json.dumps({"case": cid, "step": i, "decision": entry}) + "\n")
        step_ok = r.status in exp["status"]
        if "type" in exp:
            step_ok &= r.problem_type == PTYPE + exp["type"]
        if "www_authenticate" in exp:
            step_ok &= exp["www_authenticate"].lower() in r.headers.get("www-authenticate", "").lower()
        matched = ""
        alt = APPLICABILITY.get("draft_conflict", {}).get(cid)
        if not journal and alt and not step_ok and r.status == alt["alt_status"] and r.problem_type == PTYPE + alt["alt_type"]:
            step_ok, matched = True, f"matched=alternative({alt['alt_status']} {alt['alt_type']}, http-signature-08) "
        elif not journal and alt and step_ok:
            matched = f"matched=primary({r.status}, wpt-02) "
        if exp.get("reason") and journal:
            step_ok &= got_reason in exp["reason"]
        ok &= step_ok
        verdict = matched + ("ok" if step_ok else "MISMATCH")
        ptype = r.problem_type.rsplit("#", 1)[-1] or "-"
        if journal:
            notes.append(f"step={i} status={r.status} want={exp['status']} type={ptype} reason={got_reason} want_reason={exp.get('reason', '-')} {verdict}")
        else:
            skipped = "reason-skipped " if exp.get("reason") else ""
            notes.append(f"step={i} status={r.status} want={exp['status']} type={ptype} {skipped}{verdict}")
    return ok, notes


def classify(cid):
    """'draft' or 'policy' for a case, from cases_applicability.json (unlisted cases are draft)."""
    return "policy" if cid in APPLICABILITY["policy"] else "draft"


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Run the WIMSE inbound cases against a WIMSE-verifying HTTP server (default: Maurice).")
    ap.add_argument("--cases", default="all", help="comma-separated ids or 'all'")
    ap.add_argument("--only", choices=["draft", "all"], default="all",
                    help="'draft' runs only the cases whose outcome the drafts fix; the others depend on server policy")
    ap.add_argument("--target", type=pathlib.Path, help="target file (default setup/target.json; fields are documented in RUN_YOUR_IMPLEMENTATION.md)")
    ap.add_argument("--base", help="override target base, e.g. http://127.0.0.1:8080")
    ap.add_argument("--route", help="override the route template, e.g. /v1/run (may use {agent} and {workflow})")
    ap.add_argument("--audience", help="override the audience the requests are bound to (default: base)")
    ap.add_argument("--wire-only", action="store_true",
                    help="judge each step on HTTP status and problem type only; do not read Maurice's decision journal")
    ap.add_argument("--journal-out", type=pathlib.Path, help="write matching decision entries into the evidence bundle")
    return ap.parse_args(argv)


def main(argv=None):
    global URL, AUD
    a = parse_args(argv)
    try:
        t = load_target(a.target, base=a.base, route=a.route, audience=a.audience, journal=False if a.wire_only else None)
    except TargetError as e:
        sys.exit(f"target error: {e}")
    URL, AUD, journal = t["url"], t["audience"], t["journal"]
    if a.journal_out and not journal:
        sys.exit("--journal-out needs the decision journal; it cannot be combined with --wire-only or journal:false")
    ids = list(CASES) if a.cases == "all" else a.cases.split(",")
    unknown = [c for c in ids if c not in CASES]
    if unknown:
        sys.exit(f"unknown case id(s): {unknown}")
    if a.only == "draft":
        ids = [c for c in ids if classify(c) == "draft"]
    custom = t != load_target() or a.only != "all"
    if custom:
        checks = "status+problem-type (wire-only)" if not journal else "status+problem-type+decision-journal"
        print(f"TARGET url={URL} audience={AUD} checks={checks} only={a.only}", flush=True)
    if a.journal_out:
        a.journal_out.parent.mkdir(parents=True, exist_ok=True)
        a.journal_out.write_text("")
    srv = _Sink(("127.0.0.1", 47999), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    failed, skipped_steps = [], 0
    for cid in ids:
        before_hits = _Sink.hits
        try:
            ok, notes = check(cid, CASES[cid], a.journal_out, journal)
        except Exception as e:  # a case that cannot run is a failure, not a skip
            ok, notes = False, [f"error {type(e).__name__}: {e}"]
        if CASES[cid].get("no_fetch_port") and _Sink.hits != before_hits:
            ok, notes = False, notes + ["Maurice fetched the attacker URL"]
        skipped_steps += sum("reason-skipped" in n for n in notes)
        print(f"CASE {cid} [{CASES[cid]['ref']}] {'PASS' if ok else 'FAIL'} :: {CASES[cid]['title']} :: " + "; ".join(notes), flush=True)
        if classify(cid) == "policy":
            print(f"CLASS {cid} needs your policy (see guide): {APPLICABILITY['policy'][cid]}", flush=True)
        elif cid in APPLICABILITY.get("draft_conflict", {}):
            print(f"CLASS {cid} {APPLICABILITY['draft_conflict'][cid]['label']}", flush=True)
        else:
            print(f"CLASS {cid} draft", flush=True)
        if not ok:
            failed.append(cid)
    srv.shutdown()
    print(f"SUMMARY total={len(ids)} failed={len(failed)} {failed}", flush=True)
    if custom:
        fd = [c for c in failed if classify(c) == "draft"]
        fp = [c for c in failed if classify(c) == "policy"]
        print(f"BREAKDOWN failed_draft={fd} failed_needs_policy={fp}", flush=True)
    if not journal:
        print(f"SKIPPED decision-journal reason comparison on {skipped_steps} step(s): only HTTP status and problem type were checked. "
              "Outcomes fixed by the drafts are verified; internal reject reasons are not.", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
