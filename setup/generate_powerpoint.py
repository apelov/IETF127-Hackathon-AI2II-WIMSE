#!/usr/bin/env python3
"""Generates the single-slide IETF 127 WIMSE Hackathon presentation.
Produces: IETF127_WIMSE_Hackathon_Results.pptx
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
    slide = prs.slides.add_slide(blank_layout)

    # Palette
    c_navy_dark  = RGBColor(15, 23, 42)     # #0f172a
    c_blue_dark  = RGBColor(30, 41, 59)     # #1e293b
    c_blue_acc   = RGBColor(37, 99, 235)    # #2563eb
    c_cyan_acc   = RGBColor(14, 165, 233)   # #0ea5e9
    c_green_pass = RGBColor(16, 185, 129)   # #10b981
    c_green_bg   = RGBColor(236, 253, 245)   # #ecfdf5
    c_card_bg    = RGBColor(248, 250, 252)  # #f8fafc
    c_border     = RGBColor(226, 232, 240)  # #e2e8f0
    c_text_dark  = RGBColor(30, 41, 59)     # #1e293b
    c_text_muted = RGBColor(100, 116, 139)  # #64748b
    c_white      = RGBColor(255, 255, 255)

    # 1. Top Header Area
    # Header tag
    tag_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.35))
    tf_tag = tag_box.text_frame
    tf_tag.word_wrap = True
    p_tag = tf_tag.paragraphs[0]
    p_tag.text = "IETF 127 HACKATHON · WORKING GROUP: WIMSE · MONTREAL 2026"
    p_tag.font.name = "Arial"
    p_tag.font.size = Pt(10)
    p_tag.font.bold = True
    p_tag.font.color.rgb = c_blue_acc

    # Main Title
    title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.55))
    tf_title = title_box.text_frame
    tf_title.word_wrap = True
    p_title = tf_title.paragraphs[0]
    p_title.text = "Multi-Domain AI Agent Delegation with WIMSE & OAuth"
    p_title.font.name = "Arial"
    p_title.font.size = Pt(24)
    p_title.font.bold = True
    p_title.font.color.rgb = c_navy_dark

    # Subtitle
    sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.22), Inches(11.7), Inches(0.35))
    tf_sub = sub_box.text_frame
    tf_sub.word_wrap = True
    p_sub = tf_sub.paragraphs[0]
    p_sub.text = "Cross-Domain Workload Identity, Monotonic Scope Narrowing, and Wire-Level Evidence"
    p_sub.font.name = "Arial"
    p_sub.font.size = Pt(12)
    p_sub.font.color.rgb = c_text_muted

    # 2. Top Architecture Banner Card
    arch_card = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.65), Inches(11.733), Inches(1.35)
    )
    arch_card.fill.solid()
    arch_card.fill.fore_color.rgb = c_card_bg
    arch_card.line.color.rgb = c_border
    arch_card.line.width = Pt(1)

    # Architecture Header inside Banner
    arch_lbl = slide.shapes.add_textbox(Inches(0.95), Inches(1.7), Inches(11.4), Inches(0.28))
    p_al = arch_lbl.text_frame.paragraphs[0]
    p_al.text = "9-HOP CROSS-DOMAIN ARCHITECTURE & CRYPTOGRAPHIC EVIDENCE CHAIN"
    p_al.font.name = "Arial"
    p_al.font.size = Pt(9.5)
    p_al.font.bold = True
    p_al.font.color.rgb = c_blue_acc

    # 5 Flow Blocks inside Architecture Banner
    nodes = [
        ("User / Initiator", "Task Input", "Port 5050"),
        ("Agent 1: Maurice", "WIT + RFC 9421", "Domain A (:5050)"),
        ("Token Authority", "OAuth Txn-Token", "Domain A (:5051)"),
        ("Agent 2: Coordinator", "Cross-Domain WPT", "Domain B (:5060)"),
        ("Agent 3: Research", "Scope Narrowing", "Domain B (:5062)"),
        ("File Tool", "Protected Op / ZK", "Domain B (:5063)"),
    ]
    node_w = Inches(1.72)
    node_h = Inches(0.72)
    start_x = Inches(0.95)
    gap = Inches(0.22)

    for i, (title, sub, meta) in enumerate(nodes):
        x = start_x + i * (node_w + gap)
        y = Inches(2.05)
        # Block shape
        block = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, node_w, node_h)
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

        # Arrow between nodes
        if i < len(nodes) - 1:
            arr_box = slide.shapes.add_textbox(x + node_w, y + Inches(0.18), gap, Inches(0.35))
            tf_a = arr_box.text_frame
            p_a = tf_a.paragraphs[0]
            p_a.text = "▶"
            p_a.font.name = "Arial"
            p_a.font.size = Pt(11)
            p_a.font.color.rgb = c_blue_acc
            p_a.alignment = PP_ALIGN.CENTER

    # 3. Three Main Content Columns
    col_w = Inches(3.73)
    col_h = Inches(3.8)
    col_y = Inches(3.15)

    # ================= COLUMN 1 =================
    c1_x = Inches(0.8)
    card1 = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c1_x, col_y, col_w, col_h)
    card1.fill.solid()
    card1.fill.fore_color.rgb = c_card_bg
    card1.line.color.rgb = c_border
    card1.line.width = Pt(1)

    t1 = slide.shapes.add_textbox(c1_x + Inches(0.15), col_y + Inches(0.15), col_w - Inches(0.3), col_h - Inches(0.3))
    tf1 = t1.text_frame
    tf1.word_wrap = True

    p = tf1.paragraphs[0]
    p.text = "1. Protocols & Attack Matrix"
    p.font.name = "Arial"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = c_navy_dark

    bullets1 = [
        ("18 RFCs & Internet-Drafts", "Tested across 7 runtimes (Maurice, Redthread, MintID, OmniArx, Cred, OpenA2A, AEP)."),
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

    # ================= COLUMN 2 =================
    c2_x = Inches(4.8)
    card2 = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c2_x, col_y, col_w, col_h)
    card2.fill.solid()
    card2.fill.fore_color.rgb = c_card_bg
    card2.line.color.rgb = c_border
    card2.line.width = Pt(1)

    t2 = slide.shapes.add_textbox(c2_x + Inches(0.15), col_y + Inches(0.15), col_w - Inches(0.3), col_h - Inches(0.3))
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
        ("Live Testnet Integration (WP09)", "Verified live against MintID Tendermint RPC (:443/status) and Verifier (verifier.testnet.mintid.net)."),
        ("Multi-Partner Revocation", "Simulated clock bounds (Redthread), live ZK witness refreshes (MintID), display match (OmniArx)."),
        ("4 Independent AI Family Audits", "Full code and PCAP verification by Claude Opus, Gemini, NVIDIA Nemotron, and Mistral Vibe."),
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

    # ================= COLUMN 3 =================
    c3_x = Inches(8.8)
    card3 = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, c3_x, col_y, col_w, col_h)
    card3.fill.solid()
    card3.fill.fore_color.rgb = c_card_bg
    card3.line.color.rgb = c_border
    card3.line.width = Pt(1)

    t3 = slide.shapes.add_textbox(c3_x + Inches(0.15), col_y + Inches(0.15), col_w - Inches(0.3), col_h - Inches(0.3))
    tf3 = t3.text_frame
    tf3.word_wrap = True

    p = tf3.paragraphs[0]
    p.text = "3. Results Scoreboard"
    p.font.name = "Arial"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = c_navy_dark

    # Table inside Column 3
    table_shape = slide.shapes.add_table(6, 3, c3_x + Inches(0.15), col_y + Inches(0.55), col_w - Inches(0.3), Inches(2.2))
    table = table_shape.table
    table.columns[0].width = Inches(1.95)
    table.columns[1].width = Inches(0.68)
    table.columns[2].width = Inches(0.77)

    scores = [
        ("Suite 1: Inbound Matrix", "34/34", "✅ PASS"),
        ("Suite 2: 9-Hop Chain & Attacks", "19/19", "✅ PASS"),
        ("Suite 3: Partner Manifests", "32/32", "✅ PASS"),
        ("Suite 4: Live Partner Testnet", "7/7", "✅ PASS"),
        ("Negative Control Mutants", "9/9", "🛡️ REJ"),
        ("TOTAL REPRODUCIBILITY", "92/92", "100% PASS"),
    ]
    for row_idx, (name, count, res) in enumerate(scores):
        for col_idx, val in enumerate((name, count, res)):
            cell = table.cell(row_idx, col_idx)
            cell.text = val
            p = cell.text_frame.paragraphs[0]
            p.font.name = "Arial"
            p.font.size = Pt(8.5 if row_idx < 5 else 9.5)
            p.font.bold = (row_idx == 5 or col_idx > 0)
            if row_idx == 5:
                p.font.color.rgb = c_green_pass
            else:
                p.font.color.rgb = c_navy_dark if col_idx < 2 else c_green_pass
            if col_idx > 0:
                p.alignment = PP_ALIGN.CENTER

    # Badge below table in Column 3
    badge = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, c3_x + Inches(0.15), col_y + Inches(2.9), col_w - Inches(0.3), Inches(0.7)
    )
    badge.fill.solid()
    badge.fill.fore_color.rgb = c_green_bg
    badge.line.color.rgb = c_green_pass
    badge.line.width = Pt(1.5)

    tf_b = badge.text_frame
    tf_b.word_wrap = True
    p_b1 = tf_b.paragraphs[0]
    p_b1.text = "100% REPRODUCIBLE IN 1 COMMAND"
    p_b1.font.name = "Arial"
    p_b1.font.size = Pt(9.5)
    p_b1.font.bold = True
    p_b1.font.color.rgb = c_green_pass
    p_b1.alignment = PP_ALIGN.CENTER

    p_b2 = tf_b.add_paragraph()
    p_b2.text = "./reproduce.sh  ·  ./reproduce.sh --live-testnet"
    p_b2.font.name = "Courier New"
    p_b2.font.size = Pt(8.5)
    p_b2.font.bold = True
    p_b2.font.color.rgb = c_navy_dark
    p_b2.alignment = PP_ALIGN.CENTER

    # 4. Bottom Footer Bar
    footer_card = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(7.0), Inches(11.733), Inches(0.38)
    )
    footer_card.fill.solid()
    footer_card.fill.fore_color.rgb = c_navy_dark
    footer_card.line.fill.background()

    tf_foot = footer_card.text_frame
    tf_foot.word_wrap = True
    p_foot = tf_foot.paragraphs[0]
    p_foot.text = "Open Source Repository: https://github.com/apelov/IETF127-Hackathon-AI2II-WIMSE  |  Includes committed PCAPs, journals, checkers, & Wireshark dissector"
    p_foot.font.name = "Arial"
    p_foot.font.size = Pt(9)
    p_foot.font.color.rgb = c_white
    p_foot.alignment = PP_ALIGN.CENTER

    prs.save(filename)
    print(f"Presentation saved successfully to: {filename}")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "IETF127_WIMSE_Hackathon_Results.pptx"
    create_deck(out_file)
