"""Short black-and-white deck for the WIMSE session: who, where, what, how, one example, results.

Reuses the drawing helpers and the case data of setup/generate_test_catalog.py, so the counts
here are the same as in the test catalog (its appendix).

Usage: .venv/bin/python setup/generate_wg_deck.py  ->  IETF127_WIMSE_WG_Summary.pptx
"""
import pathlib
import sys

from pptx.enum.text import PP_ALIGN

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from generate_test_catalog import (
    CASES,
    CLASSES,
    GROUPS,
    LIMITS,
    MATRIX_COLS,
    ROOT,
    arrow,
    bchain_sequence,
    box,
    chain_picture,
    check_coverage,
    frame,
    matrix_rows,
    new_deck,
    table,
    text,
    title,
)

OUT = ROOT / "IETF127_WIMSE_WG_Summary.pptx"
FOOTER = "IETF 127 Hackathon, WIMSE interop: summary for the working group"

PARTICIPANTS = [
    ("Participant", "Provided", "Where it acts", "Evidence"),
    ("Alexander Pelov\nIMT Atlantique / AgentMaurice; the Domain B reference agents are named RICH",
     "Harness and checkers; Maurice (inbound verifier); Domain A and B services; the two-domain chain (B_CHAIN); Suites 1 and 2",
     "Every hop of the chain, ports :5050-5064", "Wire"),
    ("Ben Le\nRedthread Security",
     "Scenarios P1-P8; draft-le-agent-passport-00; Redthread runner 0.7.591 (3a6560c): P1-P6, 22 cases, 151 lines, all passing, simulated clock; MintID sandbox runs of 15 and 17 Nov (17 Nov records: commit 64f7a64)",
     "The last hop before the effect: verifier and protected-operation executor", "Partner record; 17 Nov: partner report (record sent)"),
    ("Marc Miro i Rierola\nMintID",
     "Zero-knowledge non-revocation verifier, testnet (mintid-testnet-3), revocation trace of 14 Nov",
     "The status check made by the last hop", "Partner record; live probe"),
    ("Iman Schrock\nEMILIA Protocol",
     "Before-effect test design for P2; scenario schema; separate status reasons (revoked, stale, unavailable)",
     "Design of the re-check at the last hop (no runtime)", "Test design"),
    ("Arun Thallapelly\nOmniArx",
     "Scenario P7; OASNT vectors V1, V4, V5, R2 (draft-thallapelly-oasnt-02); a verifier run",
     "The approval verifier before the action", "Partner report"),
    ("Kieran Sweeney\nCred",
     "Scenario P8; Cred's runner (cred-ninja/sdk 83e9cec) and its results",
     "The last hop, to a bearer-only third-party API", "Partner record"),
]

EXAMPLES = {
    "normal": "B_CHAIN: 9 hops, two domains, one file read",
    "identity": "IN4: an expired WIT is refused",
    "proof": "C3: a replayed signed request is refused",
    "authz": "D4: a profile:view token on a files:read route",
    "xdomain": "C6: a Domain A Txn-Token at the Domain B File Tool",
    "revocation": "P2: revoked between approval and effect, nothing happens",
    "tricks": "C7: a prompt injection asks for another file",
    "health": "MintID testnet endpoints answer",
    "controls": "chain_hop_flipped: one hop changed from 200 to 403",
}

FINDINGS = [
    ("Finding", "Shown by", "Bears on"),
    ("A changed approval screen (R2) is caught only by a verifier that holds the action; a gateway that sees only the request accepts it",
     "P7, OmniArx's run (partner report)", "draft-thallapelly-oasnt-02; OASNT-ENFORCE 5.1"),
    ("Action binding alone accepts R2; a root receipt signed by the person's authenticator is still an open issue",
     "P7 scenario note (Redthread, OmniArx)", "draft-le-agent-passport-00, Open Issues"),
    ("Once a bearer token is released, revocation cannot stop the provider call; the provider's token lifetime bounds the exposure",
     "P8, Cred's run (partner record)", "draft-sweeney-wimse-credential-delegation"),
    ("A zero-knowledge verifier gives a revoked and a stale credential the same refusal; only the issuer refusing the witness refresh attributes it to revocation",
     "MintID trace, 14 Nov (partner record)", "P2 status reasons (revoked / stale / unavailable)"),
    ("Kill-switch route: an attempt 5.8 s after the recorded self-revocation was accepted on a witness held from custody; the attempt at 47.6 s was refused. Issuer route: refused at the first attempt",
     "Redthread, 17 Nov (partner report; MintID calls real, Redthread verifier on a simulated clock)", "Revocation bounds (MintID: 245 s)"),
    ("Latency depends on where t = 0 is: P2 counts from the revocation request, MintID's cascade from the trigger root, 13.9 s later",
     "MintID trace, 14 Nov", "Scenario schema; any latency bound"),
    ("An unreachable status list must fail closed, including when one link of a chain is unknown",
     "P1, Redthread (partner record)", "draft-le-agent-passport (-01 adopts fail-closed)"),
    ("Identifier matching: confirmed, not a gap. identifier-04 sections 4.1, 4.3 and 7.1 already say %7E equals ~, %2F stays encoded and dot segments are refused; Maurice follows them",
     "A13i, A13j (wire)", "draft-ietf-wimse-identifier-04"),
]

ASKS = [
    ("Next step", "Who"),
    ("17 Nov P2 sandbox record (commit 64f7a64, SHA-256 for four files): sent 17 Nov; to be added to the repository", "Ben Le (Redthread): sent"),
    ("A P7 verifier written from the OASNT draft alone, so P7 runs here instead of being mocked", "Volunteer; OmniArx to compare R2"),
    ("Live positive and revoked P2 cases from this harness against the MintID sandbox", "Alexander Pelov, Marc Miro i Rierola"),
    ("Record the chain capture again at the current commit", "Alexander Pelov"),
    ("More implementations for any role: a pinned revision and a sample request and response", "Working group"),
]


def slide_participants(s):
    title(s, "Participants and what each provided", None)
    text(s, 0.5, 0.95, 12.3, 0.35, "Each partner's own results are listed under its name; nothing here was re-run for a partner.", size=14)
    table(s, 0.5, 1.45, 12.33, [2.6, 4.75, 3.08, 1.9], PARTICIPANTS, size=12, row_h=0.72)


def slide_picture(s):
    title(s, "Where each participant sits", "The chain (AgentMaurice plus our reference services; Domain B is named RICH) and, under the File Tool, the partners' code at the last hop")
    chain_picture(s, dy=-0.15)
    arrow(s, 11.72, 5.0, 11.72, 5.55)
    text(s, 8.0, 5.37, 3.6, 0.17, "same position: the last hop before the effect", size=10, align=PP_ALIGN.RIGHT)
    frame(s, 0.5, 5.55, 12.33, 1.38, "At the last hop (partner implementations, run by the partners)")
    for i, (lab, dash) in enumerate([
        ("Redthread\nverifier + executor (P1-P6, P2)", False),
        ("MintID\nZK non-revocation check (P2)", False),
        ("EMILIA Protocol\nbefore-effect design (P2)", True),
        ("OmniArx\napproval verifier (P7)", False),
        ("Cred\nbroker to bearer-only API (P8)", False),
    ]):
        box(s, 0.75 + i * 2.43, 5.98, 2.2, 0.75, lab, size=10, bold=True, dash=dash)


def slide_categories(s):
    title(s, "What was tested: nine questions", "Every case answers one question; the counts are cases, runs or captures")
    rows = [("Question", "What it checks", "Example", "On the wire", "Other evidence")]
    for g, name, question in GROUPS:
        wire = sum(c["n"] for c in CASES if c["group"] == g and c["cls"] == "wire")
        other = sum(c["n"] for c in CASES if c["group"] == g and c["cls"] != "wire")
        rows.append((name, question, EXAMPLES[g], wire or "", other or ""))
    table(s, 0.5, 1.45, 12.33, [2.6, 4.2, 3.43, 1.0, 1.1], rows, size=12, row_h=0.52)


def slide_method(s):
    title(s, "Method: how a result earns its class", "Rectangles are steps; every result ends with exactly one evidence class")
    top = [
        "Scenarios\nfrom drafts and partners",
        "Implementations\nbuilt separately",
        "Run on loopback\ncapture every packet",
        "Independent checker\nother model family",
        "Must reject\nnegative captures",
        "Hashed bundle\nre-checked by CI",
    ]
    for i, lab in enumerate(top):
        x = 0.5 + i * 2.1
        box(s, x, 1.6, 1.8, 0.95, lab, size=11, bold=True)
        if i:
            arrow(s, x - 0.3, 2.07, x, 2.07)
    low = [
        ("Partner runs\ntheir own code", 0.5),
        ("Record + manifest\nwith SHA-256", 2.6),
        ("Verified here,\nnot re-run", 4.7),
    ]
    for i, (lab, x) in enumerate(low):
        box(s, x, 3.05, 1.8, 0.95, lab, size=11, bold=True)
        if i:
            arrow(s, x - 0.3, 3.52, x, 3.52)
    box(s, 6.8, 3.05, 6.03, 0.95, "Reviews by Claude Opus, Gemini, NVIDIA Nemotron, Mistral Vibe;\nfindings triaged in the repository", size=11)
    rows = [("Evidence class", "Meaning")] + [(CLASSES[k][0], CLASSES[k][1]) for k in CLASSES]
    table(s, 0.5, 4.3, 12.33, [2.4, 9.93], rows, size=11, row_h=0.33)


def slide_example(s):
    title(s, "Example: the two-domain chain, B_CHAIN", "Domain A's token never enters Domain B. Call 5 stays open while calls 6 to 9 happen; its reply is the last message.")
    bchain_sequence(s)


def slide_results(s):
    title(s, "Results by question and evidence class", None)
    text(s, 0.5, 0.95, 12.3, 0.55,
         "Identity, proof and scope interoperate on the wire across two domains. Revocation is shown mostly by partner records, not yet on our wire.",
         size=15, bold=True)
    table(s, 0.5, 1.65, 12.33, MATRIX_COLS, matrix_rows(), size=13, row_h=0.45)


def slide_findings(s):
    title(s, "What we learned for the drafts", "Each finding names the evidence it rests on and its class")
    table(s, 0.5, 1.45, 12.33, [6.4, 2.95, 2.98], FINDINGS, size=11, row_h=0.6)


def slide_limits(s):
    title(s, "Limits and next steps", "Details in TEST_RESULTS_SUMMARY.md; the full case list is in the test catalog deck")
    table(s, 0.5, 1.45, 6.6, [1.75, 4.85], [("Limit", "What it means")] + LIMITS, size=11, row_h=0.62)
    table(s, 7.35, 1.45, 5.48, [3.6, 1.88], ASKS, size=11, row_h=0.62)


SLIDES = [slide_participants, slide_picture, slide_categories, slide_method, slide_example, slide_results, slide_findings, slide_limits]


def main():
    check_coverage()
    prs, new_slide = new_deck(FOOTER)
    for build in SLIDES:
        build(new_slide())
    prs.save(OUT)
    print(f"saved {OUT.name}: {len(prs.slides)} slides")


if __name__ == "__main__":
    main()
