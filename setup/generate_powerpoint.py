#!/usr/bin/env python3
"""Generates the 2-slide IETF 127 WIMSE Hackathon presentation.
Produces: IETF127_WIMSE_Hackathon_Results.pptx
Slide 1: Executive Summary, Architecture Flow, Results Scoreboard
Slide 2: Detailed Interoperability Matrix & Actor Table
"""
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def create_deck(filename="IETF127_WIMSE_Hackathon_Results.pptx"):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Palette
    c_navy_dark  = RGBColor(15, 23, 42)     # #0f172a
    c_blue_dark  = RGBColor(30, 41, 59)     # #1e293b
    c_blue_acc   = RGBColor(37, 99, 235)    # #2563eb
    c_cyan_acc   = RGBColor(14, 165, 233)   # #0ea5e9
    c_green_pass = RGBColor(16, 185, 129)   # #10b981
    c_green_bg   = RGBColor(236, 253, 245)  # #ecfdf5
    c_card_bg    = RGBColor(248, 250, 252)  # #f8fafc
    c_border     = RGBColor(226, 232, 240)  # #e2e8f0
    c_text_dark  = RGBColor(30, 41, 59)     # #1e293b
    c_text_muted = RGBColor(100, 116, 139)  # #64748b
    c_white      = RGBColor(255, 255, 255)
    c_header_bg  = RGBColor(241, 245, 249)  # #f1f5f9
    c_alt_row    = RGBColor(250, 250, 250)

    # =========================================================================
    # SLIDE 1: Executive Summary & Scoreboard
    # =========================================================================
    slide1 = prs.slides.add_slide(blank_layout)

    # Header tag
    tag_box = slide1.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.35))
    tf_tag = tag_box.text_frame
    p_tag = tf_tag.paragraphs[0]
    p_tag.text = "IETF 127 HACKATHON · WORKING GROUP: WIMSE · MONTREAL 2026"
    p_tag.font.name = "Arial"
    p_tag.font.size = Pt(10)
    p_tag.font.bold = True
    p_tag.font.color.rgb = c_blue_acc

    # Main Title
    title_box = slide1.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.55))
    tf_title = title_box.text_frame
    p_title = tf_title.paragraphs[0]
    p_title.text = "Multi-Domain AI Agent Delegation with WIMSE & OAuth"
    p_title.font.name = "Arial"
    p_title.font.size = Pt(24)
    p_title.font.bold = True
    p_title.font.color.rgb = c_navy_dark

    # Subtitle
    sub_box = slide1.shapes.add_textbox(Inches(0.8), Inches(1.22), Inches(11.7), Inches(0.35))
    tf_sub = sub_box.text_frame
    p_sub = tf_sub.paragraphs[0]
    p_sub.text = "Cross-Domain Workload Identity, Monotonic Scope Narrowing, and Wire-Level Evidence"
    p_sub.font.name = "Arial"
    p_sub.font.size = Pt(12)
    p_sub.font.color.rgb = c_text_muted

    # Architecture Banner
    arch_card = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.65), Inches(11.733), Inches(1.35))
    arch_card.fill.solid()
    arch_card.fill.fore_color.rgb = c_card_bg
    arch_card.line.color.rgb = c_border
    arch_card.line.width = Pt(1)

    arch_lbl = slide1.shapes.add_textbox(Inches(0.95), Inches(1.7), Inches(11.4), Inches(0.28))
    p_al = arch_lbl.text_frame.paragraphs[0]
    p_al.text = "9-HOP CROSS-DOMAIN ARCHITECTURE & CRYPTOGRAPHIC EVIDENCE CHAIN"
    p_al.font.name = "Arial"
    p_al.font.size = Pt(9.5)
    p_al.font.bold = True
    p_al.font.color.rgb = c_blue_acc

    nodes = [
        ("User / Initiator", "Task Input"),
        ("Agent 1: Maurice", "WIT + RFC 9421"),
        ("Token Authority", "OAuth Txn-Token"),
        ("Agent 2: Coordinator", "Cross-Domain WPT"),
        ("Agent 3: Research", "Scope Narrowing"),
        ("File Tool", "Protected Read"),
    ]
    node_w = Inches(1.72)
    node_h = Inches(0.72)
    start_x = Inches(0.95)
    gap = Inches(0.22)

    for i, (title, sub) in enumerate(nodes):
        x = start_x + i * (node_w + gap)
        y = Inches(2.05)
        block = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, node_w, node_h)
        block.fill.solid()
        block.fill.fore_color.rgb = c_white
        block.line.color.rgb = c_blue_acc if i in (1, 3, 5) else c_border
        block.line.width = Pt(1)

        tf = block.text_frame
        tf.word_wrap = True
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE

        p1 = tf.paragraphs[0]
        p1.text = title
        p1.font.name = "Arial"
        p1.font.size = Pt(9.5)
        p1.font.bold = True
        p1.font.color.rgb = c_navy_dark
        p1.alignment = PP_ALIGN.CENTER

        p2 = tf.add_paragraph()
        p2.text = sub
        p2.font.name = "Arial"
        p2.font.size = Pt(8.5)
        p2.font.color.rgb = c_blue_acc
        p2.alignment = PP_ALIGN.CENTER

        if i < len(nodes) - 1:
            arr_box = slide1.shapes.add_textbox(x + node_w, y + Inches(0.18), gap, Inches(0.35))
            p_a = arr_box.text_frame.paragraphs[0]
            p_a.text = "▶"
            p_a.font.name = "Arial"
            p_a.font.size = Pt(11)
            p_a.font.color.rgb = c_blue_acc
            p_a.alignment = PP_ALIGN.CENTER

    # 3 Columns
    col_w = Inches(3.73)
    col_h = Inches(3.8)
    col_y = Inches(3.15)

    # Column 1
    c1_x = Inches(0.8)
    card1 = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c1_x, col_y, col_w, col_h)
    card1.fill.solid()
    card1.fill.fore_color.rgb = c_card_bg
    card1.line.color.rgb = c_border
    card1.line.width = Pt(1)

    t1 = slide1.shapes.add_textbox(c1_x + Inches(0.15), col_y + Inches(0.15), col_w - Inches(0.3), col_h - Inches(0.3))
    tf1 = t1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "1. Protocols & Attack Matrix"
    p.font.name = "Arial"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = c_navy_dark

    bullets1 = [
        ("18 RFCs & Internet-Drafts", "Run here: Maurice + RICH. Partner runs: Redthread, MintID, OmniArx, Cred. Continuation: OpenA2A + AEP."),
        ("Monotonic Scope Narrowing", "OAuth Txn-Tokens narrow privileges across hops (files:read files:list → files:read)."),
        ("Dual Token PoP Bindings", "WPT cryptographically binds both WIT hash (wth) and Txn-Token hash (tth)."),
        ("Security Vectors Tested", "Token swap, body tampering, replay attacks, cross-domain isolation, and SSRF jku/x5u defense."),
        ("Prompt Injection Containment", "Exfiltration blocked at domain boundary (C7/C8 denied 403, 0 credential leaks)."),
    ]
    for b_title, b_desc in bullets1:
        p = tf1.add_paragraph()
        p.space_before = Pt(6)
        r1 = p.add_run()
        r1.text = "• " + b_title + ": "
        r1.font.bold = True
        r1.font.size = Pt(9)
        r1.font.color.rgb = c_text_dark
        r2 = p.add_run()
        r2.text = b_desc
        r2.font.size = Pt(8.5)
        r2.font.color.rgb = c_text_muted

    # Column 2
    c2_x = Inches(4.8)
    card2 = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c2_x, col_y, col_w, col_h)
    card2.fill.solid()
    card2.fill.fore_color.rgb = c_card_bg
    card2.line.color.rgb = c_border
    card2.line.width = Pt(1)

    t2 = slide1.shapes.add_textbox(c2_x + Inches(0.15), col_y + Inches(0.15), col_w - Inches(0.3), col_h - Inches(0.3))
    tf2 = t2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "2. Verification & Tooling"
    p.font.name = "Arial"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = c_navy_dark

    bullets2 = [
        ("AI2II Rule L4 (Zero Log Trust)", "Packet checkers inspect ONLY raw .pcap bytes via tshark. Zero reliance on application logs."),
        ("Wireshark Dissector (dissectors/wimse.lua)", "Custom Lua dissector visually decodes WIT, WPT, Txn-Tokens, and RFC 9421 signatures in Wireshark GUI."),
        ("Live Testnet Probes (WP09)", "3 live endpoint probes (MintID RPC, verifier status/build-info). Live P2 hook cases here: mocked."),
        ("P2 Live Sandbox (Redthread, partner-reported)", "Issuer route: refused at once. Kill switch: allowed on held witness, refused after next commitment (40 s)."),
        ("Reviews by 4 AI Families", "Claude Opus, Gemini, NVIDIA Nemotron and Mistral Vibe reviewed code and captures; findings and fixes are in validation/."),
    ]
    for b_title, b_desc in bullets2:
        p = tf2.add_paragraph()
        p.space_before = Pt(6)
        r1 = p.add_run()
        r1.text = "• " + b_title + ": "
        r1.font.bold = True
        r1.font.size = Pt(9)
        r1.font.color.rgb = c_text_dark
        r2 = p.add_run()
        r2.text = b_desc
        r2.font.size = Pt(8.5)
        r2.font.color.rgb = c_text_muted

    # Column 3
    c3_x = Inches(8.8)
    card3 = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c3_x, col_y, col_w, col_h)
    card3.fill.solid()
    card3.fill.fore_color.rgb = c_card_bg
    card3.line.color.rgb = c_border
    card3.line.width = Pt(1)

    t3 = slide1.shapes.add_textbox(c3_x + Inches(0.15), col_y + Inches(0.15), col_w - Inches(0.3), col_h - Inches(0.3))
    tf3 = t3.text_frame
    tf3.word_wrap = True
    p = tf3.paragraphs[0]
    p.text = "3. Results Scoreboard"
    p.font.name = "Arial"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = c_navy_dark

    # One row per evidence class; classes are never added together.
    scores = [
        ("Result", "Count", "Class"),
        ("Suite 1: inbound matrix", "34/34", "on wire"),
        ("Suite 2: 9-hop chain, attacks", "19/19", "on wire"),
        ("Redthread P1-P6 traces", "22/22", "simulated"),
        ("P7/P8 on :5064", "6", "mocked"),
        ("MintID probes, 15 Nov", "3/3", "live probe"),
        ("P2 sandbox, Redthread 17 Nov", "6", "partner"),
        ("Negative mutants rejected", "11/11", "checker"),
    ]
    row_h = Inches(0.27)
    table_shape = slide1.shapes.add_table(
        len(scores), 3, c3_x + Inches(0.15), col_y + Inches(0.55), col_w - Inches(0.3), row_h * len(scores)
    )
    table = table_shape.table
    table.columns[0].width = Inches(2.0)
    table.columns[1].width = Inches(0.6)
    table.columns[2].width = col_w - Inches(0.3) - Inches(2.6)
    class_color = {"on wire": c_green_pass, "checker": c_green_pass}
    for row_idx, row in enumerate(scores):
        table.rows[row_idx].height = row_h
        for col_idx, val in enumerate(row):
            cell = table.cell(row_idx, col_idx)
            cell.text = val
            cell.margin_top = cell.margin_bottom = Inches(0.02)
            p = cell.text_frame.paragraphs[0]
            p.font.name = "Arial"
            p.font.size = Pt(8.5)
            p.font.bold = row_idx == 0 or col_idx > 0
            if row_idx == 0:
                p.font.color.rgb = c_white
            elif col_idx == 2:
                p.font.color.rgb = class_color.get(val, c_navy_dark)
            else:
                p.font.color.rgb = c_navy_dark
            if col_idx > 0:
                p.alignment = PP_ALIGN.CENTER

    badge = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c3_x + Inches(0.15), col_y + Inches(2.95), col_w - Inches(0.3), Inches(0.65))
    badge.fill.solid()
    badge.fill.fore_color.rgb = c_green_bg
    badge.line.color.rgb = c_green_pass
    badge.line.width = Pt(1.5)

    tf_b = badge.text_frame
    tf_b.word_wrap = True
    p_b1 = tf_b.paragraphs[0]
    p_b1.text = "EVIDENCE RE-CHECKED IN 1 COMMAND"
    p_b1.font.name = "Arial"
    p_b1.font.size = Pt(9.5)
    p_b1.font.bold = True
    p_b1.font.color.rgb = c_green_pass
    p_b1.alignment = PP_ALIGN.CENTER

    p_b2 = tf_b.add_paragraph()
    p_b2.text = "./reproduce.sh"
    p_b2.font.name = "Courier New"
    p_b2.font.size = Pt(9)
    p_b2.font.bold = True
    p_b2.font.color.rgb = c_navy_dark
    p_b2.alignment = PP_ALIGN.CENTER

    p_b3 = tf_b.add_paragraph()
    p_b3.text = "checks hashes and captures; does not re-run peers"
    p_b3.font.name = "Arial"
    p_b3.font.size = Pt(8)
    p_b3.font.color.rgb = c_navy_dark
    p_b3.alignment = PP_ALIGN.CENTER

    # Footer Slide 1
    footer1 = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(7.0), Inches(11.733), Inches(0.38))
    footer1.fill.solid()
    footer1.fill.fore_color.rgb = c_navy_dark
    footer1.line.fill.background()
    p_foot1 = footer1.text_frame.paragraphs[0]
    p_foot1.text = "Open Source Repository: https://github.com/apelov/IETF127-Hackathon-AI2II-WIMSE  |  Includes committed PCAPs, journals, checkers, & Wireshark dissector"
    p_foot1.font.name = "Arial"
    p_foot1.font.size = Pt(9)
    p_foot1.font.color.rgb = c_white
    p_foot1.alignment = PP_ALIGN.CENTER

    # =========================================================================
    # SLIDE 2: Detailed Interoperability & Architecture Table
    # =========================================================================
    slide2 = prs.slides.add_slide(blank_layout)

    # Header Slide 2
    tag_box2 = slide2.shapes.add_textbox(Inches(0.8), Inches(0.35), Inches(11.7), Inches(0.3))
    p_tag2 = tag_box2.text_frame.paragraphs[0]
    p_tag2.text = "IETF 127 HACKATHON · INTEROPERABILITY MATRIX · DETAILED BREAKDOWN"
    p_tag2.font.name = "Arial"
    p_tag2.font.size = Pt(10)
    p_tag2.font.bold = True
    p_tag2.font.color.rgb = c_blue_acc

    title_box2 = slide2.shapes.add_textbox(Inches(0.8), Inches(0.62), Inches(11.7), Inches(0.45))
    p_title2 = title_box2.text_frame.paragraphs[0]
    p_title2.text = "Participating Implementations, Trust Domains & Standards"
    p_title2.font.name = "Arial"
    p_title2.font.size = Pt(22)
    p_title2.font.bold = True
    p_title2.font.color.rgb = c_navy_dark

    # Table on Slide 2
    # 12 rows (1 header + 11 content rows), 5 columns
    t2_rows = 12
    t2_cols = 5
    t2_shape = slide2.shapes.add_table(t2_rows, t2_cols, Inches(0.8), Inches(1.15), Inches(11.733), Inches(5.65))
    t2_table = t2_shape.table

    # Column Widths
    t2_table.columns[0].width = Inches(2.2)   # Actor / Implementation
    t2_table.columns[1].width = Inches(1.1)   # Runtime / Port
    t2_table.columns[2].width = Inches(1.8)   # Trust Domain
    t2_table.columns[3].width = Inches(2.8)   # Standards / Drafts
    t2_table.columns[4].width = Inches(3.833) # Role & Interoperability Function

    headers = [
        "Actor / Implementation",
        "Runtime / Port",
        "Trust Domain",
        "Standards / Drafts",
        "Role & What Was Interoperated / Verified",
    ]
    for c_idx, h_text in enumerate(headers):
        cell = t2_table.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = c_navy_dark
        p = cell.text_frame.paragraphs[0]
        p.text = h_text
        p.font.name = "Arial"
        p.font.size = Pt(9.5)
        p.font.bold = True
        p.font.color.rgb = c_white
        p.alignment = PP_ALIGN.LEFT if c_idx != 1 else PP_ALIGN.CENTER

    data = [
        (
            "AgentMaurice",
            ":5050",
            "Domain A (maurice.ietf127.example)",
            "draft-ietf-wimse-s2s-protocol\nRFC 9421 HTTP Message Signatures\ndraft-ietf-wimse-identifier-04",
            "Autonomous Workload initiator (Agent 1). WIT Profile 1 (WPT) & Profile 2 (HTTP-Sig), key compromise (C11), and port 47999 SSRF anti-probing defense.",
        ),
        (
            "Token Authority (TTS-A)",
            ":5051",
            "Domain A (maurice.ietf127.example)",
            "draft-ietf-wimse-workload-identity-bcp\ndraft-ietf-oauth-transaction-tokens",
            "Issues the initial Transaction Token with the broad delegation scope (files:read files:list); AS-A issues the cross-domain grant.",
        ),
        (
            "Coordinator Agent (Agent 2)",
            ":5060",
            "Domain B (rich.ietf127.example)",
            "draft-ietf-wimse-s2s-protocol\ndraft-ietf-oauth-transaction-tokens",
            "Inter-domain gateway. Validates inbound Domain A WIMSE proofs, passes sanitized context, and calls Domain B Token Authority for token exchange.",
        ),
        (
            "Token Authority (TTS-B)",
            ":5061",
            "Domain B (rich.ietf127.example)",
            "draft-ietf-oauth-transaction-tokens\ndraft-ietf-wimse-wpt",
            "AS-B and TTS-B: accepts the cross-domain grant and issues the narrowed Txn-Token (files:read). The calling workload's WPT binds the WIT hash (wth) and the Txn-Token hash (tth).",
        ),
        (
            "Research Sub-Agent (Agent 3)",
            ":5062",
            "Domain B (rich.ietf127.example)",
            "draft-ietf-wimse-s2s-protocol\nRFC 9421 HTTP Message Signatures",
            "Executes research queries. Sanitizes caller_context to prevent credential exfiltration; prompt injection vectors C7/C8 stopped at boundary.",
        ),
        (
            "File Tool Microservice",
            ":5063",
            "Domain B (rich.ietf127.example)",
            "draft-ietf-oauth-transaction-tokens\nRFC 8941 Structured Headers",
            "Protected resource. Verifies the WIT, the WPT binding to WIT and narrowed Txn-Token, and the scope before exactly one protected read.",
        ),
        (
            "Redthread Security",
            "Simulated / :5064",
            "Partner runtime",
            "draft-le-agent-passport\n(0.7.591, commit 3a6560c)",
            "Scenarios P1–P6 on a simulated clock: status revoked, stale, unavailable (P1), attenuation (P3), cumulative limit (P4), request rewritten (P5), tool and build pinning (P6).",
        ),
        (
            "MintID Testnet",
            "MintID testnet",
            "External Live Testnet",
            "MintID protocol (open source)\nZK non-revocation proof",
            "MintID's recorded 14 Nov testnet trace (partner-attested): revocation attributed via holder witness refresh (credential_revoked) + sibling control.",
        ),
        (
            "OmniArx",
            "Vector V5 / R2",
            "External Spec / :5064",
            "draft-thallapelly-oasnt-02",
            "Scenario P7, OmniArx's own run: V5 accepted, R2 refused (display-mismatch). The :5064 cases are mocked (fixed digests).",
        ),
        (
            "Cred Delegation",
            "Boundary check",
            "External Spec / :5064",
            "draft-sweeney-wimse-credential-delegation",
            "Scenario P8, Cred's own run: denials 401/403; bearer token not released by default. The :5064 cases are mocked (fixed answers).",
        ),
        (
            "OpenA2A & AEP",
            "Continuation",
            "branch feature/opena2a-wimse-aep",
            "ATX Credential, AAP Grants\nAction Evidence Packages",
            "Next step: cross-domain agent payment (legitimate transfer; prompt injection contained). Prototype stand-ins built here; OpenA2A and official AEP (eatf-verifier) runs pending.",
        ),
    ]

    for r_idx, row_data in enumerate(data):
        row_num = r_idx + 1
        bg_col = c_card_bg if r_idx % 2 == 0 else c_white
        for c_idx, val in enumerate(row_data):
            cell = t2_table.cell(row_num, c_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = bg_col
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.name = "Arial"
            p.font.size = Pt(7.8)
            p.font.color.rgb = c_text_dark
            if c_idx == 0:
                p.font.bold = True
                p.font.color.rgb = c_navy_dark
            elif c_idx == 1:
                p.font.name = "Courier New"
                p.font.size = Pt(7.5)
                p.alignment = PP_ALIGN.CENTER
            elif c_idx == 3:
                p.font.name = "Courier New"
                p.font.size = Pt(7.2)
                p.font.color.rgb = c_blue_acc

    # Footer Slide 2
    footer2 = slide2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(6.9), Inches(11.733), Inches(0.38))
    footer2.fill.solid()
    footer2.fill.fore_color.rgb = c_navy_dark
    footer2.line.fill.background()
    p_foot2 = footer2.text_frame.paragraphs[0]
    p_foot2.text = "11 Implementations & Microservices  ·  18 RFCs & Internet-Drafts  ·  Zero Log Trust  ·  https://github.com/apelov/IETF127-Hackathon-AI2II-WIMSE"
    p_foot2.font.name = "Arial"
    p_foot2.font.size = Pt(9)
    p_foot2.font.color.rgb = c_white
    p_foot2.alignment = PP_ALIGN.CENTER

    prs.save(filename)
    print(f"2-Slide Presentation saved successfully to: {filename}")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "IETF127_WIMSE_Hackathon_Results.pptx"
    create_deck(out_file)
