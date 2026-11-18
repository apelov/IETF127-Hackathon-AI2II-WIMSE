"""Black-and-white test catalog deck: entities, sequence diagrams, and every tested case.

Every case of cases.json (Suite 1) and chain_cases.json (Suite 2) must appear exactly once in
CASES below; the build fails otherwise. The counts on the summary slide are computed from CASES,
so they cannot drift from the tables.

Usage: .venv/bin/python setup/generate_test_catalog.py  ->  IETF127_WIMSE_Test_Catalog.pptx
"""
import json
import pathlib
from collections import Counter

from lxml import etree
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.dml import MSO_LINE
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Inches, Pt

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "IETF127_WIMSE_Test_Catalog.pptx"
BLACK = RGBColor(0, 0, 0)
WHITE = RGBColor(255, 255, 255)
# Warm accents, used sparingly: titles, table headers and arrows; box fill; container outlines.
TERRACOTTA = RGBColor(0xB5, 0x53, 0x2B)
SAND = RGBColor(0xFB, 0xF1, 0xE3)
AMBER = RGBColor(0xD9, 0x9A, 0x2B)
FONT = "Arial"
TABLE_GRID = "{5940675A-B579-460E-94D1-54222C63F5DA}"  # built-in "No Style, Table Grid"

# Evidence classes, strongest first.
CLASSES = {
    "wire": ("Wire", "Real implementations ran here; recorded in a capture; checked by an independent packet checker"),
    "record": ("Partner record", "The partner ran its own code; the record is committed and hashed here, not re-run"),
    "report": ("Partner report", "Reported by the partner by email; no record in the repository yet"),
    "sim": ("Simulated / replayed", "Our code with a fake clock, or a recorded outcome played back"),
    "mock": ("Mocked", "Fixed answers; says nothing about the partner's implementation"),
    "probe": ("Live probe", "A health check against a live service: is it up?"),
    "control": ("Checker control", "A deliberately bad capture the checker must reject"),
}

GROUPS = [
    ("normal", "1. Normal path works", "Does the right request get through?"),
    ("identity", "2. Who are you?", "Is the badge (WIT) real, current, from a trusted issuer, and correctly named?"),
    ("proof", "3. Prove it is yours", "Is the request signed by the badge's owner, for this receiver, once, unaltered?"),
    ("authz", "4. Are you allowed?", "With a valid identity, is this action on the permission slip (Txn-Token)?"),
    ("xdomain", "5. Crossing company lines", "Does Domain A's permission stay in A, and is what B grants narrower?"),
    ("revocation", "6. Taking it back", "Once permission is withdrawn, how fast is it refused, and can anything still happen?"),
    ("tricks", "7. Do not be tricked", "Can content, tools or an attacker make the system do something else?"),
    ("health", "8. Is the service up?", "Are the partner's live endpoints reachable?"),
    ("controls", "9. Is the checker honest?", "Would the checker notice a bad or fake capture?"),
]


def C(group, case, test, eli5, expected, cls, ids=None, n=None):
    return {"group": group, "case": case, "test": test, "eli5": eli5, "expected": expected,
            "cls": cls, "ids": ids or [], "n": n or (len(ids) if ids else 1)}


CASES = [
    # 1. Normal path
    C("normal", "A2", "Badge + HTTP signature, allowed workload", "Right badge, signed note, on the guest list: come in", "200 accept", "wire", ["A2"]),
    C("normal", "A4", "Badge + WPT, allowed workload", "Same, with the other kind of proof", "200 accept", "wire", ["A4"]),
    C("normal", "A12a-d", "Ed25519 key, alg written Ed25519 or EdDSA, with each proof", "One key type written two ways must work both ways", "200 accept", "wire", ["A12a", "A12b", "A12c", "A12d"]),
    C("normal", "A13i", "Peer.Ietf127.Example/a%7Eb vs grant .../a~b", "Capitals in the domain and an encoded ~ are the same name", "200 accept", "wire", ["A13i"]),
    C("normal", "B_CHAIN", "The full 9-hop, two-domain chain", "Alice's request crosses two companies and three agents; exactly one file is read", "9 x 200, one txn id, WPT bound to WIT and Txn-Token", "wire", ["B_CHAIN"]),
    C("normal", "P3 absent-means-default", "Redthread: a rule left out of a delegation", "Missing means the default, not 'anything goes'", "allow", "record"),
    C("normal", "P5 authenticated-proxy", "Redthread: a trusted proxy verifies and forwards", "A proxy that checks before passing on is fine", "allow", "record"),
    C("normal", "P7 V5 (OmniArx)", "OASNT vector V5 at time 1800000000", "The person saw exactly what will be done", "accepted", "report"),
    C("normal", "P7 display-match (:5064)", "Fixed digest compare on loopback", "Fixed answer, no OASNT code runs", "200 allow", "mock"),
    # 2. Identity
    C("identity", "IN4", "Expired WIT", "Last year's badge", "400 wit-expired", "wire", ["IN4"]),
    C("identity", "IN6", "Issuer not on the allowlist", "A known company, but not allowed to issue for this door", "400 issuer-not-allowed", "wire", ["IN6"]),
    C("identity", "C11", "WIT from an issuer not in trust", "A badge printed by an unknown company", "400 untrusted-trust-domain", "wire", ["C11"]),
    C("identity", "A13a", "Identifier with no path", "The badge address has no department part", "400 identifier-invalid", "wire", ["A13a"]),
    C("identity", "A13b-d", "Identifier with ./, ../, %2E%2E", "Tricks to walk into another folder", "400 identifier-invalid", "wire", ["A13b", "A13c", "A13d"]),
    C("identity", "A13e-h", "Identifier with port, query, fragment, userinfo", "Extra bits glued onto a name that must not have them", "400 identifier-invalid (or untrusted-trust-domain)", "wire", ["A13e", "A13f", "A13g", "A13h"]),
    C("identity", "A13j", "/a%2Fb vs grant /a/b", "An encoded slash is not a slash: a different name", "403 not-authorized", "wire", ["A13j"]),
    # 3. Proof of possession
    C("proof", "A5", "WIT without proof", "A badge anyone could have picked up: prove it is yours", "401 proof-missing, WWW-Authenticate: WPT", "wire", ["A5"]),
    C("proof", "A6a", "WIT + HTTP-sig + X-API-Key", "Two kinds of ID at once: ambiguous, refused", "400 mixed-credentials", "wire", ["A6a"]),
    C("proof", "A6b", "WIT + WPT + Bearer", "Same, with a different second ID", "400 or 401 mixed-credentials", "wire", ["A6b"]),
    C("proof", "C2", "Genuine WIT, signed with another key", "Real badge, a stranger's signature", "400 proof-invalid", "wire", ["C2"]),
    C("proof", "C3", "Replay of a signed request", "A photocopy of yesterday's signed note", "200, then 400 replay", "wire", ["C3"]),
    C("proof", "C4", "Signed for RICH, sent to Maurice", "A letter addressed to the neighbour", "400 audience-mismatch", "wire", ["C4"]),
    C("proof", "C4b", "Audience differs by a trailing slash", "'maurice/' is not 'maurice': exact match only", "400 audience-mismatch", "wire", ["C4b"]),
    C("proof", "IN10", "Body modified after signing", "The letter changed after it was sealed", "400 digest-mismatch", "wire", ["IN10"]),
    C("proof", "IN11", "Two signatures with the WIMSE tag", "Two seals on one letter: which counts?", "400", "wire", ["IN11"]),
    C("proof", "IN12", "Signature carries keyid", "The key must come from the badge, not a hint in the request", "400", "wire", ["IN12"]),
    C("proof", "IN13", "WPT alg differs from cnf.jwk.alg", "Proof signed in a way the badge does not allow", "401", "wire", ["IN13"]),
    C("proof", "C5", "Txn-Token swapped after signing", "Permission slip swapped after the envelope was sealed", "5063 400 proof-invalid", "wire", ["C5"]),
    C("proof", "D1", "Txn-Token not covered by the signature", "Slip clipped outside the seal", "5063 400 proof-invalid", "wire", ["D1"]),
    C("proof", "D2", "WPT names the wrong Txn-Token (tth)", "Proof says 'I come with slip X', slip Y attached", "5063 401 proof-invalid, then Maurice 401", "wire", ["D2"]),
    C("proof", "P5 rewrite-authority, rewrite-path", "Redthread: a proxy changes host or path", "The signature no longer matches the request", "signature-invalid (2 cases)", "record", n=2),
    C("proof", "P5 forwarded-headers", "Redthread: 'the real target was X', unauthenticated", "A claim nobody signed is not believed", "forwarded-target-uri-unauthenticated", "record"),
    # 4. Authorization
    C("authz", "IN15", "Valid identity, no grant", "You are who you say, but not on the list", "403 not-authorized", "wire", ["IN15"]),
    C("authz", "C9", "No Txn-Token on a delegated-only route", "A robot acting alone at a door that needs a person's slip", "5063 403 not-authorized", "wire", ["C9"]),
    C("authz", "C9b", "Txn-Token on an autonomous-only route", "A slip used where only robots acting alone may go", "5063 403 not-authorized", "wire", ["C9b"]),
    C("authz", "D4", "Scope profile:view on a files:read route", "A canteen slip used at the archive", "5063 403 not-authorized", "wire", ["D4"]),
    C("authz", "D3_exp", "Expired Txn-Token", "Yesterday's permission slip", "5063 403 txn-token-invalid", "wire", ["D3_exp"]),
    C("authz", "D3_sig", "Txn-Token signed by a rogue key", "A forged stamp", "5063 403 txn-token-invalid", "wire", ["D3_sig"]),
    C("authz", "D3_typ", "Txn-Token with typ=jwt", "A generic paper dressed as a permission slip", "5063 403 txn-token-invalid", "wire", ["D3_typ"]),
    C("authz", "D3_reqwl", "Txn-Token without req_wl", "A slip with no requester filled in", "5063 403 txn-token-invalid", "wire", ["D3_reqwl"]),
    C("authz", "D3_dup", "Two Txn-Token headers", "Two slips: which counts? Refused", "5063 403 txn-token-invalid", "wire", ["D3_dup"]),
    C("authz", "P8 no-delegation, write-under-read (Cred)", "Cred's own run", "No delegation; read permission used to write", "401 invalid_token; 403 scope_insufficient", "record", n=2),
    C("authz", "P8 no-delegation, write-under-read (:5064)", "Fixed answers on loopback", "Fixed answers, no Cred code runs", "403 (2 cases)", "mock", n=2),
    # 5. Cross-domain
    C("xdomain", "C6", "Domain A Txn-Token at the Domain B File Tool", "Company A's slip used in company B's building", "5063 403 txn-token-invalid", "wire", ["C6"]),
    C("xdomain", "D5", "Access token (at+jwt) presented as a cross-domain grant", "A gym card where a visa is required", "5061 403 grant-invalid", "wire", ["D5"]),
    C("xdomain", "D6", "TTS-A issues a narrowed replacement Txn-Token", "B may make the slip narrower; the driver rejects widened or altered ones (not on the wire)", "4 x 5051 200", "wire", ["D6"]),
    C("xdomain", "D7", "Cross-domain grant with the wrong audience", "A visa for the wrong country", "... 5061 403 grant-invalid", "wire", ["D7"]),
    C("xdomain", "P3 wider-host, more-methods, longer-lifetime, dropped-tools", "Redthread: a delegate gives itself more", "A helper may not hand on more than it received", "attenuation:host / methods / exp / tools", "record", n=4),
    C("xdomain", "P3 unknown-member", "Redthread: a rule nobody understands", "Refuse rather than guess", "attenuation:unknown-member", "record"),
    C("xdomain", "P4 per-rp-counting", "Redthread: a call limit counted by each service alone", "A shared limit nobody can add up is refused", "limit-aud-not-single", "record"),
    C("xdomain", "P4 single-accounting-rp", "Redthread: one service counts the calls", "N calls allowed, call N+1 refused", "limit-exceeded", "record"),
    C("xdomain", "P4 child-limit-wider", "Redthread: a delegate raises its own limit", "A helper cannot raise its own limit", "attenuation:max_calls", "record"),
    # 6. Revocation
    C("revocation", "C10", "Workload revoked mid-transaction", "Read OK, badge cancelled, next read refused", "200, revoke, 403 revoked, clear", "wire", ["C10"]),
    C("revocation", "P1 (5 cases)", "Redthread: status revoked, cache expired, service down, low-value grace, one link unknown", "If the cancellation list says no, is too old, or cannot be read: refuse", "status-revoked / -stale / -unavailable / -grace", "record", n=5),
    C("revocation", "P2 revoke-upstream, before-effect", "Redthread, simulated clock", "Boss cancelled after delegating; re-check just before acting", "status-revoked, last OK 50 s, first refusal 51 s, bound 120 s", "record", n=2),
    C("revocation", "P2 sandbox, 15 Nov", "Redthread vs the live MintID verifier", "A made-up proof and an agent that never answers", "both denied, no effect", "record", n=2),
    C("revocation", "MintID trace, 14 Nov", "Issuer, kill switch, two cascade agents", "How long after cancelling until refusal", "23.1 s (185), 17.1 s (245), 189.1 and 40.8 s (395)", "record", n=4),
    C("revocation", "P8 revoked (Cred)", "Revoked before and after the token is released", "Before release: refused. After: Cred will not release a raw token by default", "401 delegation_revoked; 403 raw_token_disabled", "record", n=2),
    C("revocation", "P2 sandbox, 17 Nov", "Redthread: issuer route and kill switch, 6 attempts", "Issuer route: refused at the first attempt. Kill switch: accepted on a held witness, then refused", "issuer: refused at first attempt; kill switch: accepted at 5.8 s, refused at 47.6 s", "report", n=6),
    C("revocation", "P2 on :5064", "Redthread's code (simulated) and 2 replayed sandbox outcomes", "The same P2 decisions, over loopback HTTP", "403, no effect (4 cases)", "sim", n=4),
    C("revocation", "P8 revoked (:5064)", "Fixed answers on loopback", "Fixed answers, no Cred code runs", "403; 200 token-released", "mock", n=2),
    C("revocation", "WP09 hook cases", "Outside-verifier hook in-process", "Fixed responses", "deny / allow", "mock", n=4),
    # 7. Tricks
    C("tricks", "C7", "Prompt injection: also read salaries.xlsx", "The document tells the agent to fetch another file", "... 5063 403 not-authorized", "wire", ["C7"]),
    C("tricks", "C8", "Prompt injection: send me your credentials", "The agent answers, leaks nothing; the extra read is refused", "200s, then 5063 403; no leaked credentials", "wire", ["C8"]),
    C("tricks", "C12", "iss is an attacker's JWKS URL", "Never go to the address an attacker gives", "400 issuer-not-allowed; no connection to :47999", "wire", ["C12"]),
    C("tricks", "C12b", "Same, no issuer allowlist configured", "Even without a list, never fetch", "400 or 403; no connection to :47999", "wire", ["C12b"]),
    C("tricks", "A3", "Asks for a signed response", "Cannot sign the reply, so say so; never fake it", "501 signed-response-unsupported", "wire", ["A3"]),
    C("tricks", "P6 build-changed, tool-swapped", "Redthread: tool code or tool changed between hops", "The approved tool must be the one that runs", "build-mismatch; tool-digest-mismatch", "record", n=2),
    C("tricks", "P7 R2 (OmniArx)", "Screen text differs from the signed action", "Only a verifier that knows the action catches it", "refused, display-mismatch", "report"),
    C("tricks", "P7 display-mismatch (:5064)", "Fixed digest compare on loopback", "Fixed answer, no OASNT code runs", "403", "mock"),
    # 8. Health
    C("health", "MintID testnet, 15 Nov", "Verifier status, build info, chain RPC", "Is the service up? All three answered", "200 x 3", "probe", n=3),
    # 9. Checker controls
    C("controls", "unrelated (x3)", "One per checker", "A recording of something else: never PASS", "rejected", "control", n=3),
    C("controls", "request_only (x3)", "Responses stripped", "Questions with no answers prove nothing", "rejected", "control", n=3),
    C("controls", "forbidden_fetch", "Inbound", "Maurice did call the attacker's address", "rejected", "control"),
    C("controls", "chain_leaked_txn", "Chain", "A's slip seen inside B, in a header", "rejected", "control"),
    C("controls", "chain_leaked_txn_body", "Chain", "The same slip hidden in a request body", "rejected", "control"),
    C("controls", "chain_hop_flipped", "Chain", "One middle hop changed from OK to refused", "rejected", "control"),
    C("controls", "p1_p8_missing_before_effect", "P2", "The re-check before acting is missing", "rejected", "control"),
]

LIMITS = [
    ("Suite 1 reasons", "Maurice's error bodies carry no reason member; the driver checks reasons in Maurice's own log"),
    ("Case labels", "Cases are named by an unsigned header; C9, C9b and D4 have the same hop and could be swapped in a forged capture"),
    ("D5 and D6", "The driver's outbound guard (D5) and its rejection of widened or altered tokens (D6) are not on the wire"),
    ("Test peers", "test_mode is read from request bodies; /admin/revoke has no authentication. No published result depends on them"),
    ("Checker independence", "Nemotron wrote the checkers; Claude and Gemini, which wrote the peers, edited them later: separation is partial"),
    ("Revocation", "Our harness's own revocation cases are simulated, replayed or mocked. Partner evidence: Redthread P1-P6 on a simulated clock; Redthread's 17 Nov P2 calls to the MintID sandbox were real"),
]


def check_coverage():
    want = [c["id"] for c in json.loads((ROOT / "cases.json").read_text())["cases"]]
    want += [c["id"] for c in json.loads((ROOT / "chain_cases.json").read_text())]
    got = [i for c in CASES for i in c["ids"]]
    dup = [i for i, k in Counter(got).items() if k > 1]
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    if dup or missing or extra:
        raise SystemExit(f"case coverage wrong: duplicated {dup}, missing {missing}, unknown {extra}")


# ---------------------------------------------------------------- drawing helpers
def text(slide, x, y, w, h, s, size=14, bold=False, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, color=BLACK):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    tf.vertical_anchor = anchor
    for i, line in enumerate(s.split("\n")):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        r = p.add_run()
        r.text = line
        r.font.name, r.font.size, r.font.bold, r.font.color.rgb = FONT, Pt(size), bold, color
    return tb


def title(slide, s, sub=None):
    text(slide, 0.5, 0.35, 12.3, 0.6, s, size=28, bold=True, color=TERRACOTTA)
    if sub:
        text(slide, 0.5, 0.95, 12.3, 0.35, sub, size=14)


def box(slide, x, y, w, h, label, size=12, bold=False, line=1.0, dash=False):
    shp = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    shp.fill.solid()
    shp.fill.fore_color.rgb = SAND
    shp.line.color.rgb = BLACK
    shp.line.width = Pt(line)
    if dash:
        shp.line.dash_style = MSO_LINE.DASH
    shp.shadow.inherit = False
    tf = shp.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for i, ln in enumerate(label.split("\n")):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = PP_ALIGN.CENTER
        r = p.add_run()
        r.text = ln
        r.font.name, r.font.size, r.font.color.rgb = FONT, Pt(size), BLACK
        r.font.bold = bold if i == 0 else False
    return shp


def frame(slide, x, y, w, h, label):
    """A container rectangle with its label in the top-left corner."""
    shp = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    shp.fill.background()
    shp.line.color.rgb = AMBER
    shp.line.width = Pt(1.5)
    shp.shadow.inherit = False
    text(slide, x + 0.12, y + 0.08, w - 0.24, 0.3, label, size=13, bold=True)


def arrow(slide, x1, y1, x2, y2, dash=False, head=True, width=1.25):
    c = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x1), Inches(y1), Inches(x2), Inches(y2))
    c.line.color.rgb = TERRACOTTA
    c.line.width = Pt(width)
    if dash:
        c.line.dash_style = MSO_LINE.DASH
    if head:
        ln = c.line._get_or_add_ln()
        tail = etree.SubElement(ln, qn("a:tailEnd"))
        tail.set("type", "triangle")
        tail.set("w", "med")
        tail.set("len", "med")
    return c


def table(slide, x, y, w, col_w, rows, size=11, header=True, row_h=0.3):
    shape = slide.shapes.add_table(len(rows), len(col_w), Inches(x), Inches(y), Inches(w), Inches(row_h * len(rows)))
    tbl = shape.table
    tbl_pr = shape._element.graphic.graphicData.tbl.tblPr
    style = tbl_pr.find(qn("a:tableStyleId"))
    if style is None:
        style = etree.SubElement(tbl_pr, qn("a:tableStyleId"))
    style.text = TABLE_GRID
    tbl.first_row = header
    tbl.horz_banding = False
    for i, cw in enumerate(col_w):
        tbl.columns[i].width = Inches(cw)
    for r, row in enumerate(rows):
        tbl.rows[r].height = Inches(row_h)
        for ci, val in enumerate(row):
            cell = tbl.cell(r, ci)
            cell.margin_left = cell.margin_right = Inches(0.06)
            cell.margin_top = cell.margin_bottom = Inches(0.03)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            head = header and r == 0
            cell.fill.solid()
            cell.fill.fore_color.rgb = TERRACOTTA if head else WHITE
            tf = cell.text_frame
            tf.word_wrap = True
            p = tf.paragraphs[0]
            run = p.add_run()
            run.text = str(val)
            run.font.name, run.font.size = FONT, Pt(size)
            run.font.bold = head
            run.font.color.rgb = WHITE if head else BLACK
    return tbl


def footer(slide, n, label="IETF 127 Hackathon, WIMSE interop: test catalog"):
    text(slide, 0.5, 7.05, 9.0, 0.25, label, size=10)
    text(slide, 11.8, 7.05, 1.03, 0.25, str(n), size=10, align=PP_ALIGN.RIGHT)


# ---------------------------------------------------------------- sequence diagrams
def sequence(slide, lifelines, messages, top=1.45, bottom=6.85, box_w=1.55, notes=(), label_size=10, bars=()):
    """lifelines: labels. messages: (from, to, label, dashed). from == to draws a self-note.
    bars: (lifeline, first message, last message): a narrow bar on that lifeline while the entity is busy."""
    n = len(lifelines)
    left, right = 0.5, 12.83
    step = (right - left - box_w) / (n - 1)
    xs = [left + box_w / 2 + i * step for i in range(n)]
    for x, lab in zip(xs, lifelines):
        box(slide, x - box_w / 2, top, box_w, 0.6, lab, size=11, bold=True)
        arrow(slide, x, top + 0.6, x, bottom, dash=True, head=False, width=0.75)
    y0 = top + 0.95
    gap = min((bottom - y0 - 0.15) / max(len(messages), 1), 0.52)
    ys = [y0 + i * gap for i in range(len(messages))]
    for li, a, b in bars:
        box(slide, xs[li] - 0.055, ys[a] - 0.06, 0.11, ys[b] - ys[a] + 0.12, "", size=8, line=1.0)
    for (src, dst, label, dashed), y in zip(messages, ys):
        if src == dst:
            x = xs[src]
            box(slide, x - box_w / 2 + 0.05, y - 0.19, box_w - 0.1, 0.38, label, size=label_size)
        else:
            x1, x2 = xs[src], xs[dst]
            arrow(slide, x1, y, x2, y, dash=dashed)
            lx, lw = min(x1, x2) + 0.05, abs(x2 - x1) - 0.1
            text(slide, lx, y - 0.24, lw, 0.22, label, size=label_size, align=PP_ALIGN.CENTER)
    for nx, ny, nw, ns in notes:
        box(slide, nx, ny, nw, 0.5, ns, size=10, dash=True)


def new_deck(footer_text="IETF 127 Hackathon, WIMSE interop: test catalog"):
    """A 16:9 deck and a function that adds a blank slide with a footer (none on the first)."""
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    blank = prs.slide_layouts[6]
    page = [0]

    def new_slide():
        s = prs.slides.add_slide(blank)
        page[0] += 1
        if page[0] > 1:
            footer(s, page[0], footer_text)
        return s
    return prs, new_slide


def class_totals():
    totals = Counter()
    for c in CASES:
        totals[c["cls"]] += c["n"]
    return totals


def matrix_rows():
    """Question x evidence class counts, computed from CASES, with a total row."""
    keys = list(CLASSES)
    grid = Counter()
    for c in CASES:
        grid[(c["group"], c["cls"])] += c["n"]
    totals = class_totals()
    rows = [("Question",) + tuple(CLASSES[k][0] for k in keys)]
    for g, name, _ in GROUPS:
        rows.append((name,) + tuple(grid[(g, k)] or "" for k in keys))
    rows.append(("Total",) + tuple(totals[k] for k in keys))
    return rows


MATRIX_COLS = [3.33, 1.25, 1.35, 1.35, 1.45, 1.2, 1.2, 1.2]


def chain_picture(s, dy=0.0):
    """Domain A and Domain B, the seven entities and the nine B_CHAIN hops (4.0 in tall)."""
    frame(s, 0.5, 1.5 + dy, 4.4, 4.0, "Domain A (maurice.ietf127.example)")
    frame(s, 6.1, 1.5 + dy, 6.73, 4.0, "Domain B (rich.ietf127.example)")
    client = (0.75, 2.05 + dy, 1.75, 0.8)
    tts_a = (3.0, 2.05 + dy, 1.65, 0.8)
    maur = (0.75, 4.35 + dy, 1.75, 0.8)
    as_b = (6.4, 2.05 + dy, 1.9, 0.8)
    coord = (6.4, 4.35 + dy, 1.9, 0.8)
    res = (8.65, 4.35 + dy, 1.85, 0.8)
    ftool = (10.85, 4.35 + dy, 1.75, 0.8)
    box(s, *client, "Client workload\nwimse://peer.../client", bold=True, size=11)
    box(s, *tts_a, "TTS-A / AS-A\n:5051", bold=True, size=11)
    box(s, *maur, "Maurice (Agent 1)\n:5050", bold=True, size=11)
    box(s, *as_b, "AS-B / TTS-B\n:5061", bold=True, size=11)
    box(s, *coord, "Coordinator (Agent 2)\n:5060", bold=True, size=11)
    box(s, *res, "Research (Agent 3)\n:5062", bold=True, size=11)
    box(s, *ftool, "File Tool\n:5063", bold=True, size=11)
    for x1, y1, x2, y2, lab, lx, ly in [
        (2.5, 2.45, 3.0, 2.45, "1, 3", 2.52, 2.12),
        (1.62, 2.85, 1.62, 4.35, "2", 1.75, 3.45),
        (2.5, 2.7, 6.4, 2.7, "4", 4.95, 2.75),
        (2.5, 2.8, 6.4, 4.55, "5", 4.55, 3.85),
        (7.35, 4.35, 7.35, 2.85, "6", 7.48, 3.45),
        (8.3, 4.75, 8.65, 4.75, "7", 8.4, 4.42),
        (9.57, 4.35, 8.3, 2.85, "8", 9.15, 3.45),
        (10.5, 4.75, 10.85, 4.75, "9", 10.6, 4.42),
    ]:
        arrow(s, x1, y1 + dy, x2, y2 + dy)
        text(s, lx, ly + dy, 0.45, 0.25, lab, size=11, bold=True)


def bchain_sequence(slide):
    """B_CHAIN in true capture order: call 5 stays open while calls 6 to 9 happen; its reply is the last message."""
    sequence(slide, ["Client workload", "TTS-A / AS-A :5051", "Maurice :5050", "AS-B / TTS-B :5061", "Coordinator :5060", "Research :5062", "File Tool :5063"], [
        (0, 1, "1 Txn-Token for Alice", False),
        (1, 0, "T_A (read, list)", True),
        (0, 2, "2 WIT + signature + T_A", False),
        (2, 0, "workflow completed", True),
        (0, 1, "3 exchange T_A (AS-A)", False),
        (1, 0, "cross-domain grant", True),
        (0, 3, "4 redeem grant (AS-B)", False),
        (3, 0, "AT_B (access token)", True),
        (0, 4, "5 WIT + Bearer AT_B + signature", False),
        (4, 3, "6 Txn-Token (TTS-B)", False),
        (3, 4, "T_B1", True),
        (4, 5, "7 WIT + signature + T_B1", False),
        (5, 3, "8 narrow to files:read", False),
        (3, 5, "T_B2", True),
        (5, 6, "9 WIT + WPT + T_B2", False),
        (6, 5, "file Q3.pdf", True),
        (5, 4, "reply 7: result $4.2M", True),
        (4, 0, "reply 5: result $4.2M (last)", True),
    ], box_w=1.6, label_size=9, bars=[(1, 0, 1), (2, 2, 3), (1, 4, 5), (3, 6, 7), (4, 8, 17), (3, 9, 10), (5, 11, 16), (3, 12, 13), (6, 14, 15)])


def main():
    check_coverage()
    prs, new_slide = new_deck()

    # 1. Title
    s = new_slide()
    text(s, 0.8, 2.3, 11.7, 0.9, "WIMSE interop at the IETF 127 Hackathon", size=36, bold=True)
    text(s, 0.8, 3.3, 11.7, 0.5, "What was tested, how it was tested, and how far each result can be trusted", size=20)
    text(s, 0.8, 4.4, 11.7, 1.2,
         "Implementations: AgentMaurice and the Domain B reference agents (named RICH); partners Redthread Security, MintID, OmniArx, Cred\n"
         "Evidence: github.com/apelov/IETF127-Hackathon-AI2II-WIMSE (TEST_RESULTS_SUMMARY.md, EVIDENCE.md)\n"
         "Every count in this deck is generated from the case files in the repository", size=14)

    # 2. Evidence classes
    s = new_slide()
    title(s, "How to read a result: the evidence class", "Each result carries exactly one class. Results of different classes are never added together.")
    totals = class_totals()
    rows = [("Class", "What it means", "Count")]
    rows += [(CLASSES[k][0], CLASSES[k][1], totals[k]) for k in CLASSES]
    table(s, 0.5, 1.5, 12.33, [2.4, 8.73, 1.2], rows, size=14, row_h=0.55)

    # 3. Entities
    s = new_slide()
    title(s, "Who talks to whom", "Ports are the loopback ports in the committed captures. Numbers are the hops of B_CHAIN.")
    chain_picture(s)
    frame(s, 0.5, 5.75, 12.33, 1.15, "Partners (their own code, outside these captures) and the :5064 loopback executor")
    for i, lab in enumerate(["Redthread\nP1-P6, P2 sandbox", "MintID\nZK revocation, testnet", "OmniArx\nP7 verifier", "Cred\nP8 runner", ":5064 executor\nP2 sim, P7/P8 mocked"]):
        box(s, 0.75 + i * 2.43, 6.15, 2.2, 0.6, lab, size=10, bold=True)

    # 4. Suite 1 sequence
    s = new_slide()
    title(s, "Suite 1: one request at Maurice's front door (34 cases)", "Each case changes one thing in the request; Maurice must answer with the right status and error type")
    sequence(s, ["Client workload", "Maurice :5050", "Attacker URL :47999"], [
        (0, 1, "POST + WIT (badge) + WPT or HTTP signature (proof)", False),
        (1, 1, "check badge, issuer, name", False),
        (1, 1, "check proof, audience, replay", False),
        (1, 1, "check grant for this workload", False),
        (1, 0, "200 accept, or 4xx problem+json (type, WWW-Authenticate)", True),
        (1, 2, "C12 / C12b: this call must never happen", True),
    ], box_w=2.6)

    # 5. B_CHAIN sequence
    s = new_slide()
    title(s, "Suite 2: the two-domain chain, B_CHAIN (9 hops)", "Every hop is in the capture; the checker compares each hop's port, status and reason, in order")
    bchain_sequence(s)

    # 6. P2 sequence
    s = new_slide()
    title(s, "P2: revocation after delegation, before the effect", "Redthread's runs and MintID's sandbox; the question is whether anything happens after the revocation")
    sequence(s, ["Issuer / status", "Agent A", "Agent B (delegate)", "Enforcing service", "Protected operation"], [
        (1, 2, "delegate (child receipt)", False),
        (2, 3, "request", False),
        (3, 0, "authorize: status check", False),
        (0, 3, "valid: effect pending", True),
        (0, 0, "revoke A (t = 0)", False),
        (3, 0, "before-effect re-check (MintID: fresh ZK proof, 10 s)", False),
        (0, 3, "revoked", True),
        (3, 2, "403 status-revoked, effect: none", True),
        (3, 4, "never called after revocation", True),
    ], box_w=2.0)

    # 7. P7 sequence
    s = new_slide()
    title(s, "P7: the approval screen differs from the executed action", "OmniArx's run with the OASNT Appendix A vectors at time 1800000000")
    sequence(s, ["Person (device)", "Agent", "Verifier (holds the action)", "Protected action"], [
        (1, 0, "show approval text", False),
        (0, 1, "approve: signed token (3 digests)", True),
        (1, 2, "token + request", False),
        (2, 2, "recompute display digest", False),
        (2, 3, "V5: display matches, run", False),
        (2, 1, "R2: refused, display-mismatch", True),
    ], box_w=2.4, bottom=5.75, notes=[(0.6, 6.15, 12.1, "A gateway that sees only the request accepts R2: that is expected (OASNT-ENFORCE 5.1). Only a verifier that holds the action can catch it.")])

    # 8. P8 sequence
    s = new_slide()
    title(s, "P8: the last hop is a bearer-only API", "Cred's run (commit 83e9cec) against a local mock of a bearer-only provider")
    sequence(s, ["Agent", "Cred", "Status", "Bearer-only API"], [
        (0, 1, "use delegation (read or write)", False),
        (1, 2, "re-check before release", False),
        (2, 1, "revoked", True),
        (1, 0, "401 delegation_revoked (nothing released)", True),
        (1, 0, "default: 403 raw_token_disabled (no raw token)", True),
        (1, 0, "deprecated allowRawTokens: raw token released", True),
        (0, 3, "call with raw token", False),
        (2, 2, "too late to stop it", False),
    ], box_w=2.4, bottom=5.75, notes=[(0.6, 6.15, 12.1, "Once a raw bearer token is released, the provider's token lifetime bounds the exposure, not the status list.")])

    # 9. Matrix
    s = new_slide()
    title(s, "What was tested, by question and by evidence class", "Numbers are cases (or runs, or captures). Read across: how strongly each question is answered.")
    table(s, 0.5, 1.5, 12.33, MATRIX_COLS, matrix_rows(), size=13, row_h=0.45)

    # 10+. One table per question
    for g, name, question in GROUPS:
        cases = [c for c in CASES if c["group"] == g]
        pages = -(-len(cases) // 7)
        per = -(-len(cases) // pages)
        for part in range(0, len(cases), per):
            chunk = cases[part:part + per]
            s = new_slide()
            suffix = f" ({part // per + 1}/{pages})" if pages > 1 else ""
            title(s, name + suffix, question)
            rows = [("Case", "Test", "In plain words", "Expected", "Evidence")]
            rows += [(c["case"], c["test"], c["eli5"], c["expected"], CLASSES[c["cls"]][0]) for c in chunk]
            table(s, 0.5, 1.5, 12.33, [2.45, 2.85, 3.45, 2.18, 1.4], rows, size=12, row_h=0.62)

    # Last: limits
    s = new_slide()
    title(s, "What the evidence does not show", "Listed in TEST_RESULTS_SUMMARY.md; found by the Mistral Vibe reviews of 17 Nov")
    table(s, 0.5, 1.5, 12.33, [2.6, 9.73], [("Limit", "Consequence")] + LIMITS, size=14, row_h=0.7)

    prs.save(OUT)
    print(f"saved {OUT.name}: {len(prs.slides)} slides, {sum(c['n'] for c in CASES)} cases/runs/captures")


if __name__ == "__main__":
    main()
