"""Three slides for the WIMSE session, then the summary slides as backup.

1. What we tested, against which drafts (picture with the drafts at each place; use-case types)
2. Results by use-case type and evidence class
3. What it means for the drafts, and next steps

Counts come from CASES in setup/generate_test_catalog.py, as in the other two decks.

Usage: .venv/bin/python setup/generate_session_deck.py [--force]  ->  IETF127_WIMSE_Session.pptx

The committed deck has two slides added by hand (title, goal of AI2II) before slide 1, so this
script refuses to overwrite an existing deck unless --force is given.
"""
import pathlib
import sys

from pptx.enum.text import PP_ALIGN

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from generate_test_catalog import (
    CASES,
    CLASSES,
    GROUPS,
    ROOT,
    arrow,
    box,
    check_coverage,
    frame,
    new_deck,
    table,
    text,
    title,
)
from generate_wg_deck import SLIDES as BACKUP

OUT = ROOT / "IETF127_WIMSE_Session.pptx"
FOOTER = "IETF 127 Hackathon, WIMSE interop: github.com/apelov/IETF127-Hackathon-AI2II-WIMSE"

# The seven use-case types shown on slides 1 and 2 (the two checking rows of GROUPS go to backup).
USE_CASES = [
    ("normal", "Normal path across two domains", "B_CHAIN: 9 hops, 3 agents, one file read"),
    ("identity", "Identity: is the WIT valid and correctly named?", "expired, untrusted issuer, ../ in the name"),
    ("proof", "Proof: signed by its owner, for this receiver, once, unaltered?", "replay, wrong audience, body changed"),
    ("authz", "Authorization and scope", "no grant, wrong scope, bad Txn-Token"),
    ("xdomain", "Crossing domains: A's token stays in A, B's is narrower", "C6, D5-D7; delegation must not widen (P3, P4)"),
    ("revocation", "Revocation before the effect", "P1, P2, P8; C10; MintID testnet"),
    ("tricks", "Attacks on agents", "prompt injection, attacker URL, tool swap (P6), approval screen (P7)"),
]

RESULT_CLASSES = ["wire", "record", "report", "sim", "mock"]

FINDINGS = [
    ("Finding", "Evidence", "Draft"),
    ("A changed approval screen (R2) is caught only by a verifier that holds the action", "Partner report", "oasnt-02; oasnt-enforce-01 5.1"),
    ("Action binding alone accepts R2; a root receipt from the person's authenticator is still open", "Partner report", "le-agent-passport-00, Open Issues"),
    ("Once a bearer token is released, revocation cannot stop the provider call", "Partner record", "sweeney-wimse-credential-delegation"),
    ("A ZK status check refuses revoked and stale alike; only a refused witness refresh shows revocation", "Partner record", "P2 status reasons"),
    ("Kill-switch route: accepted 5.8 s after self-revocation on a held witness, refused at 47.6 s (issuer route: refused at the first attempt)", "Partner report", "revocation bounds"),
    ("Latency depends on where t = 0 is: request vs trigger root, 13.9 s apart", "Partner record", "scenario schema, any bound"),
    ("An unreachable status list fails closed, also when one link of a chain is unknown", "Partner record", "le-agent-passport (-01)"),
    ("%7E equals ~ and the host is case-insensitive, but %2F is not /", "Wire", "wimse-identifier-04"),
]


def slide_tested(s):
    title(s, "What we tested, and against which drafts",
          "Every call, draft-ietf-wimse-: workload-creds-03 (WIT), wpt-02 (WPT), http-signature-08 and RFC 9421, 9530, identifier-04")
    # Left: the three places, top to bottom.
    box(s, 0.5, 1.6, 6.9, 1.0, "Domain A: AgentMaurice\nclient workload, Maurice (agent 1), TTS-A / AS-A", size=12, bold=True)
    arrow(s, 3.95, 2.6, 3.95, 3.25)
    text(s, 4.1, 2.68, 3.3, 0.5, "cross-domain grant, draft-ietf-oauth-:\ntransaction-tokens-11, identity-chaining-17; RFC 8693, 7523", size=10)
    box(s, 0.5, 3.25, 6.9, 1.0, "Domain B: RICH\nAS-B / TTS-B, Coordinator (agent 2), Research (agent 3), File Tool", size=12, bold=True)
    arrow(s, 3.95, 4.25, 3.95, 4.75)
    text(s, 4.1, 4.33, 3.3, 0.3, "the last hop before the effect", size=10)
    frame(s, 0.5, 4.75, 6.9, 2.15, "Partners at the last hop (their own code); before-effect design: EMILIA")
    for i, lab in enumerate([
        "Redthread Security\ndraft-le-agent-passport",
        "OmniArx\ndraft-thallapelly-oasnt-02, -enforce-01",
        "Cred\ndraft-sweeney-wimse-credential-delegation",
        "MintID\nZK non-revocation (own protocol)",
    ]):
        box(s, 0.7 + (i % 2) * 3.35, 5.18 + (i // 2) * 0.82, 3.15, 0.7, lab, size=10, bold=True)
    # Right: the use-case types.
    rows = [("Use-case type", "For example")] + [(name, ex) for _, name, ex in USE_CASES]
    table(s, 7.7, 1.6, 5.13, [2.6, 2.53], rows, size=11, row_h=0.6)


def slide_results(s):
    title(s, "Results by use-case type and evidence class", None)
    text(s, 0.5, 0.95, 12.3, 0.55,
         "Identity, proof and scope interoperate on the wire across two domains. "
         "Revocation is shown mostly by partner records, not yet on our wire.", size=15, bold=True)
    count = {}
    for c in CASES:
        count[(c["group"], c["cls"])] = count.get((c["group"], c["cls"]), 0) + c["n"]
    rows = [("Use-case type",) + tuple(CLASSES[k][0] for k in RESULT_CLASSES)]
    for g, name, _ in USE_CASES:
        rows.append((name,) + tuple(count.get((g, k), "") for k in RESULT_CLASSES))
    rows.append(("Total",) + tuple(sum(count.get((g, k), 0) for g, _, _ in USE_CASES) for k in RESULT_CLASSES))
    table(s, 0.5, 1.7, 12.33, [5.13, 1.3, 1.6, 1.55, 1.55, 1.2], rows, size=13, row_h=0.47)
    probes = sum(c["n"] for c in CASES if c["cls"] == "probe")
    controls = sum(c["n"] for c in CASES if c["cls"] == "control")
    text(s, 0.5, 6.15, 12.3, 0.7,
         f"Wire: real implementations, recorded and checked by an independent packet checker. "
         f"Columns are never added together. Also: {controls} bad captures, all rejected by the checkers; "
         f"{probes} live probes of the MintID testnet. Everything is re-checkable with ./reproduce.sh.", size=13)


def slide_findings(s):
    title(s, "What it means for the drafts", "Each finding names its evidence class and the draft it bears on (draft- prefix omitted)")
    table(s, 0.5, 1.45, 12.33, [7.6, 1.75, 2.98], FINDINGS, size=12, row_h=0.5)
    text(s, 0.5, 6.15, 12.3, 0.7,
         "Next: add Redthread's 17 Nov record (sent 17 Nov) to the repository  |  a P7 verifier written from the OASNT draft  |  "
         "live P2 from this harness against the MintID sandbox  |  more implementations for any role "
         "(a pinned revision and a sample request and response)", size=13)


def main():
    if OUT.exists() and "--force" not in sys.argv:
        raise SystemExit(f"{OUT.name} exists and has hand-edited slides; pass --force to overwrite it")
    check_coverage()
    groups = {g for g, _, _ in GROUPS}
    assert {g for g, _, _ in USE_CASES} <= groups
    prs, new_slide = new_deck(FOOTER)
    for build in (slide_tested, slide_results, slide_findings):
        build(new_slide())
    s = new_slide()
    text(s, 0.5, 3.2, 12.3, 0.8, "Backup", size=36, bold=True, align=PP_ALIGN.CENTER)
    text(s, 0.5, 4.0, 12.3, 0.4, "Full list of cases: IETF127_WIMSE_Test_Catalog.pptx", size=14, align=PP_ALIGN.CENTER)
    for build in BACKUP:
        build(new_slide())
    prs.save(OUT)
    print(f"saved {OUT.name}: {len(prs.slides)} slides (3 + backup)")


if __name__ == "__main__":
    main()
