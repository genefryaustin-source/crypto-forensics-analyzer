"""
forensics_fullreport.py  —  Crypto Forensics Analyzer Pro v5.0
Complete Investigation PDF Report Generator.

Pulls from st.session_state to include EVERY analysis that was run:
OFAC · Ransomware · USD values · Contracts · DeFi protocols · Dust attacks ·
Flash loans · MEV · Rug pulls · Honeypots · Coordinated dumps · Structuring ·
Velocity · Peeling chains · Tornado links · Atomic swaps · Privacy coins ·
GNN clusters · Co-spending clusters · Address classification · Exchange endpoints ·
Darknet intel · Change addresses · Multi-sig · NFT wash trading · Airdrop farming ·
Time series ML · Multi-hop trace · AI analysis · SAR narrative · Evidence log ·
EIP-712 certificate · Case notes
"""

import io
import json
import hashlib
import pandas as pd
import streamlit as st
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, NextPageTemplate
from reportlab.lib.colors import HexColor


# ─────────────────────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────────────────────
C_CRITICAL  = HexColor("#ff4444")
C_HIGH      = HexColor("#ff8800")
C_MEDIUM    = HexColor("#ffcc00")
C_LOW       = HexColor("#22c55e")
C_HEADER    = HexColor("#0f172a")
C_SUBHEADER = HexColor("#1e293b")
C_ACCENT    = HexColor("#3b82f6")
C_GREY_LIGHT= HexColor("#f1f5f9")
C_GREY      = HexColor("#94a3b8")
C_WHITE     = colors.white

RISK_COLOR  = {"CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
               "MEDIUM":   C_MEDIUM,   "LOW":  C_LOW}

SECTION_NUM = [0]  # Mutable counter for section numbering


def _next_section(title: str, styles) -> List:
    """Return section heading elements and increment counter."""
    SECTION_NUM[0] += 1
    n = SECTION_NUM[0]
    return [
        Spacer(1, 14),
        HRFlowable(width="100%", thickness=1.5, color=C_ACCENT, spaceAfter=4),
        Paragraph(f"{n}. {title}", styles["h1"]),
        Spacer(1, 4),
    ]


def _subsection(title: str, styles) -> List:
    return [Paragraph(title, styles["h2"]), Spacer(1, 3)]


# ─────────────────────────────────────────────────────────────
# PAGE TEMPLATE WITH HEADER / FOOTER
# ─────────────────────────────────────────────────────────────

def _header_footer(canvas, doc):
    canvas.saveState()
    w, h = letter

    # Header bar
    canvas.setFillColor(C_HEADER)
    canvas.rect(0, h - 0.5*inch, w, 0.5*inch, fill=1, stroke=0)
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(0.4*inch, h - 0.33*inch, "CRYPTO FORENSICS INVESTIGATION REPORT")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - 0.4*inch, h - 0.33*inch, f"CONFIDENTIAL — Page {doc.page}")

    # Footer bar
    canvas.setFillColor(C_SUBHEADER)
    canvas.rect(0, 0, w, 0.35*inch, fill=1, stroke=0)
    canvas.setFillColor(C_GREY)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(0.4*inch, 0.13*inch,
        "Crypto Forensics Analyzer Pro v5.0  |  For authorized investigative use only  |  DO NOT DISCLOSE")
    canvas.drawRightString(w - 0.4*inch, 0.13*inch,
        datetime.now().strftime("%Y-%m-%d %H:%M UTC"))

    canvas.restoreState()


# ─────────────────────────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────────────────────────

def _build_styles():
    S = getSampleStyleSheet()
    styles = {}

    styles["cover_title"] = ParagraphStyle("ct", parent=S["Title"],
        fontSize=26, textColor=C_WHITE, spaceAfter=8, alignment=TA_CENTER)
    styles["cover_sub"] = ParagraphStyle("cs", parent=S["Normal"],
        fontSize=11, textColor=C_GREY, alignment=TA_CENTER, spaceAfter=4)
    styles["cover_meta"] = ParagraphStyle("cm", parent=S["Normal"],
        fontSize=9, textColor=HexColor("#cbd5e1"), alignment=TA_CENTER)

    styles["h1"] = ParagraphStyle("h1", parent=S["Heading1"],
        fontSize=12, textColor=C_HEADER, spaceBefore=6, spaceAfter=4,
        fontName="Helvetica-Bold")
    styles["h2"] = ParagraphStyle("h2", parent=S["Heading2"],
        fontSize=10, textColor=C_ACCENT, spaceBefore=4, spaceAfter=2,
        fontName="Helvetica-Bold")
    styles["h3"] = ParagraphStyle("h3", parent=S["Heading3"],
        fontSize=9, textColor=C_SUBHEADER, spaceBefore=2, spaceAfter=2,
        fontName="Helvetica-BoldOblique")

    styles["body"] = ParagraphStyle("body", parent=S["Normal"],
        fontSize=8, leading=12, textColor=HexColor("#1e293b"))
    styles["small"] = ParagraphStyle("small", parent=S["Normal"],
        fontSize=7, leading=10, textColor=C_GREY)
    styles["code"] = ParagraphStyle("code", parent=S["Code"],
        fontSize=7, leading=9, fontName="Courier", textColor=HexColor("#1e293b"))
    styles["warn"] = ParagraphStyle("warn", parent=S["Normal"],
        fontSize=8, leading=11, textColor=C_CRITICAL, fontName="Helvetica-Bold")
    styles["toc_entry"] = ParagraphStyle("toc", parent=S["Normal"],
        fontSize=8, leading=14, textColor=HexColor("#334155"))

    return styles


# ─────────────────────────────────────────────────────────────
# TABLE HELPERS
# ─────────────────────────────────────────────────────────────


def _fmt_crypto(x, decimals: int = 10) -> str:
    """Full-precision crypto amount — no $ sign, no trailing zeros."""
    try:
        v = float(x)
        if v != v or v == 0:
            return "0"
        return f"{v:.{decimals}f}".rstrip("0").rstrip(".")
    except (ValueError, TypeError):
        return str(x)


def _std_table(data: list, col_widths: list, styles_extra: list = None) -> Table:
    """Standard table with default forensics styling."""
    base_styles = [
        ("BACKGROUND",    (0,0), (-1,0),  C_HEADER),
        ("TEXTCOLOR",     (0,0), (-1,0),  C_WHITE),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 7),
        ("FONTNAME",      (0,1), (-1,-1), "Courier"),
        ("GRID",          (0,0), (-1,-1), 0.3, HexColor("#cbd5e1")),
        ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
        ("TOPPADDING",    (0,0), (-1,-1), 3),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_GREY_LIGHT, C_WHITE]),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("WORDWRAP",      (0,0), (-1,-1), True),
    ]
    if styles_extra:
        base_styles.extend(styles_extra)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(base_styles))
    return t


def _risk_col_styles(df: pd.DataFrame, col_name: str, data_start_row: int = 1) -> list:
    """Generate TableStyle entries to color-code a risk column."""
    styles_extra = []
    if col_name not in df.columns:
        return styles_extra
    col_idx = list(df.columns).index(col_name)
    for i, val in enumerate(df[col_name].values):
        bg = RISK_COLOR.get(str(val).upper(), C_GREY_LIGHT)
        row = i + data_start_row
        styles_extra.append(("BACKGROUND", (col_idx, row), (col_idx, row), bg))
        text_col = C_WHITE if str(val).upper() in ("CRITICAL","HIGH") else colors.black
        styles_extra.append(("TEXTCOLOR", (col_idx, row), (col_idx, row), text_col))
        styles_extra.append(("FONTNAME",  (col_idx, row), (col_idx, row), "Helvetica-Bold"))
    return styles_extra


# Address/hash column name fragments — these columns get auto-truncated
_ADDR_COL_KEYWORDS = (
    "address", "addr", "tx_hash", "hash", "pubkey",
    "bot_addr", "victim_addr", "wallet",
)

def _truncate_addr(val: str, first: int = 12, last: int = 6) -> str:
    """
    Shorten a crypto address for PDF display.
    Addresses have no spaces so ReportLab cannot wrap them — truncation
    is the only reliable fix.
    Result: first_N + "…" + last_M  (e.g. "1BoatSLRHtKN…TtpyT")
    """
    s = str(val).strip()
    if len(s) > first + last + 3 and " " not in s:
        return s[:first] + "…" + s[-last:]
    return s


def _df_to_table(df: pd.DataFrame, col_widths: list,
                 max_rows: int = 50, risk_col: str = "risk_level") -> Table:
    """Convert a DataFrame to a formatted reportlab Table.
    Address and hash columns are automatically truncated so that long
    hex/base58 strings cannot bleed across adjacent PDF columns.
    """
    display = df.head(max_rows).copy()

    # Format floats — column-aware
    # Crypto amount columns: full precision, no $ sign
    # Score/ratio/usd columns: conventional numeric format
    _CRYPTO_COL_KEYS = ("amount","volume","balance","paid","sent","received","out_volume","in_volume")
    _USD_COL_KEYS    = ("usd","price","value","worth")
    for col in display.columns:
        if display[col].dtype != float:
            continue
        col_lower = col.lower()
        if any(k in col_lower for k in _CRYPTO_COL_KEYS):
            display[col] = display[col].apply(_fmt_crypto)
        elif any(k in col_lower for k in _USD_COL_KEYS):
            display[col] = display[col].apply(
                lambda x: f"${x:,.2f}" if pd.notna(x) and float(x)==float(x) else ""
            )
        else:
            # Scores, ratios, counts etc — compact numeric
            display[col] = display[col].apply(
                lambda x: f"{x:,.4f}" if abs(x) < 1 else (f"{x:,.2f}" if abs(x) < 10000 else f"{x:,.0f}")
                if pd.notna(x) and float(x)==float(x) else ""
            )

    display = display.astype(str)

    # Auto-truncate address / hash columns
    for col in display.columns:
        col_lower = col.lower()
        is_addr_col = any(kw in col_lower for kw in _ADDR_COL_KEYWORDS)
        if is_addr_col:
            display[col] = display[col].apply(_truncate_addr)
        else:
            # Also truncate any cell value that looks like an address
            # (long, no spaces, looks like hex or base58)
            import re as _re
            _addr_pat = _re.compile(r"^(0x[a-fA-F0-9]{20,}|[13bc][a-zA-Z0-9]{20,}|T[a-zA-Z0-9]{25,})$")
            display[col] = display[col].apply(
                lambda v: _truncate_addr(v) if _addr_pat.match(v.strip()) else v
            )

    headers = [c.replace("_"," ").title() for c in display.columns]
    data = [headers] + display.values.tolist()
    risk_styles = _risk_col_styles(df.head(max_rows), risk_col)
    return _std_table(data, col_widths, risk_styles)


def _metric_table(metrics: dict, n_cols: int = 4) -> Table:
    """Render a row of metric boxes."""
    keys   = list(metrics.keys())
    values = [str(v) for v in metrics.values()]
    # Pad to multiple of n_cols
    while len(keys) % n_cols:
        keys.append(""); values.append("")

    rows = []
    for i in range(0, len(keys), n_cols):
        rows.append(keys[i:i+n_cols])
        rows.append(values[i:i+n_cols])

    col_w = [6.5*inch / n_cols] * n_cols
    ts = TableStyle([
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("GRID",          (0,0), (-1,-1), 0.3, HexColor("#e2e8f0")),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("BACKGROUND",    (0,0), (-1,-1), C_GREY_LIGHT),
        ("FONTNAME",      (0,1), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,1), (-1,-1), 11),
        ("TEXTCOLOR",     (0,1), (-1,-1), C_HEADER),
    ])
    # Label rows (even rows) are smaller grey text
    for r in range(0, len(rows), 2):
        ts.add("FONTSIZE",   (0,r), (-1,r), 7)
        ts.add("TEXTCOLOR",  (0,r), (-1,r), C_GREY)
        ts.add("FONTNAME",   (0,r), (-1,r), "Helvetica")

    t = Table(rows, colWidths=col_w)
    t.setStyle(ts)
    return t


def _flag_table(findings: list, key_field: str, detail_field: str,
                severity_field: str = "severity", styles=None) -> List:
    """Render a list of findings as flag rows."""
    if not findings:
        return [Paragraph("✅ No findings.", styles["small"])]
    elems = []
    for f in findings[:30]:
        sev   = str(f.get(severity_field, "")).upper()
        color = RISK_COLOR.get(sev, C_GREY)
        key   = str(f.get(key_field, ""))[:80]
        detail= str(f.get(detail_field, ""))[:200]
        data  = [[f"[{sev}]", key], ["", detail]]
        ts = TableStyle([
            ("FONTSIZE",    (0,0), (-1,-1), 7),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("TOPPADDING",  (0,0), (-1,-1), 2),
            ("BACKGROUND",  (0,0), (0,0),   color),
            ("TEXTCOLOR",   (0,0), (0,0),   C_WHITE),
            ("FONTNAME",    (0,0), (0,0),   "Helvetica-Bold"),
            ("TEXTCOLOR",   (1,0), (1,-1),  C_HEADER),
            ("TEXTCOLOR",   (0,1), (0,1),   C_GREY),
            ("TEXTCOLOR",   (1,1), (1,1),   C_GREY),
            ("GRID",        (0,0), (-1,-1), 0.2, HexColor("#e2e8f0")),
        ])
        t = Table(data, colWidths=[0.7*inch, 5.8*inch])
        t.setStyle(ts)
        elems.append(t)
        elems.append(Spacer(1, 2))
    return elems


# ─────────────────────────────────────────────────────────────
# SESSION STATE HELPER
# ─────────────────────────────────────────────────────────────

def _ss(key: str, default=None):
    """Safe session_state accessor."""
    val = st.session_state.get(key, default)
    if isinstance(val, pd.DataFrame) and val.empty:
        return default
    return val


def _has(key: str) -> bool:
    """True if session_state has non-empty data for key."""
    val = st.session_state.get(key)
    if val is None:
        return False
    if isinstance(val, pd.DataFrame):
        return not val.empty
    if isinstance(val, (list, dict)):
        return bool(val)
    if isinstance(val, str):
        return bool(val.strip())
    return bool(val)


# ─────────────────────────────────────────────────────────────
# COVER PAGE
# ─────────────────────────────────────────────────────────────

def _cover_page(case_id: str, analyst: str, classification: str,
                df: pd.DataFrame, styles) -> List:
    elems = []

    # Dark cover block
    cover_data = [[
        Paragraph("🛡️", styles["cover_title"]),
    ]]
    ct = Table([[Paragraph(
        "CRYPTO FORENSICS<br/>INVESTIGATION REPORT",
        styles["cover_title"]
    )]], colWidths=[6.5*inch])
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_HEADER),
        ("TOPPADDING",    (0,0), (-1,-1), 32),
        ("BOTTOMPADDING", (0,0), (-1,-1), 32),
    ]))
    elems.append(ct)
    elems.append(Spacer(1, 20))

    # Classification banner
    if classification == "TOP SECRET":
        banner_col = C_CRITICAL
    elif classification == "CONFIDENTIAL":
        banner_col = C_HIGH
    elif classification == "RESTRICTED":
        banner_col = C_MEDIUM
    else:
        banner_col = C_ACCENT

    bt = Table([[Paragraph(f"⚠️ {classification}", ParagraphStyle(
        "cls", fontSize=11, textColor=C_WHITE, alignment=TA_CENTER, fontName="Helvetica-Bold"
    ))]], colWidths=[6.5*inch])
    bt.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), banner_col),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    elems.append(bt)
    elems.append(Spacer(1, 24))

    # Case details table
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    total_vol = df["amount"].sum() if "amount" in df.columns else 0
    critical  = int((df.get("risk_level","") == "CRITICAL").sum()) if "risk_level" in df.columns else 0

    meta = [
        ["Field",            "Value"],
        ["Case ID",          case_id],
        ["Analyst",          analyst],
        ["Date / Time",      date_str],
        ["Total Transactions", f"{len(df):,}"],
        ["Total Volume",     _fmt_crypto(total_vol)],
        ["Critical Flags",   str(critical)],
        ["Tool Version",     "Crypto Forensics Analyzer Pro v5.0"],
        ["Report Hash",      hashlib.sha256(case_id.encode()).hexdigest()[:24]],
    ]
    mt = Table(meta, colWidths=[2*inch, 4.5*inch])
    mt.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  C_SUBHEADER),
        ("TEXTCOLOR",     (0,0), (-1,0),  C_WHITE),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("GRID",          (0,0), (-1,-1), 0.5, HexColor("#cbd5e1")),
        ("FONTNAME",      (0,1), (0,-1),  "Helvetica-Bold"),
        ("TEXTCOLOR",     (0,1), (0,-1),  C_SUBHEADER),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [C_GREY_LIGHT, C_WHITE]),
    ]))
    # Red-highlight critical row if critical > 0
    if critical > 0:
        for r, row in enumerate(meta[1:], 1):
            if row[0] == "Critical Flags":
                mt.setStyle(TableStyle([
                    ("BACKGROUND", (1,r), (1,r), C_CRITICAL),
                    ("TEXTCOLOR",  (1,r), (1,r), C_WHITE),
                    ("FONTNAME",   (1,r), (1,r), "Helvetica-Bold"),
                ]))
    elems.append(mt)
    elems.append(Spacer(1, 20))

    # Disclaimer
    disc = Table([[Paragraph(
        "CONFIDENTIAL — This report is generated by automated forensic analysis. "
        "All findings require verification by a qualified analyst before legal action. "
        "Do not disclose to unauthorized parties.",
        ParagraphStyle("disc", fontSize=7, textColor=C_GREY, alignment=TA_CENTER)
    )]], colWidths=[6.5*inch])
    disc.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),HexColor("#f8fafc")),
                               ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8)]))
    elems.append(disc)
    elems.append(PageBreak())
    return elems


# ─────────────────────────────────────────────────────────────
# TABLE OF CONTENTS  (dynamic — only lists sections with data)
# ─────────────────────────────────────────────────────────────

def _toc(sections: List[str], styles) -> List:
    elems = [Paragraph("Table of Contents", styles["h1"]), Spacer(1, 8)]
    for i, title in enumerate(sections, 1):
        elems.append(Paragraph(f"{i}. {title}", styles["toc_entry"]))
    elems.append(PageBreak())
    return elems


# ─────────────────────────────────────────────────────────────
# SECTION BUILDERS — one per analysis module
# ─────────────────────────────────────────────────────────────

def _section_executive_summary(df: pd.DataFrame, sections: list, styles) -> List:
    sections.append("Executive Summary")
    elems = _next_section("Executive Summary", styles)

    total_vol = df["amount"].sum() if "amount" in df.columns else 0
    critical  = int((df.get("risk_level","") == "CRITICAL").sum()) if "risk_level" in df.columns else 0
    high      = int((df.get("risk_level","") == "HIGH").sum()) if "risk_level" in df.columns else 0
    anomalies = int(df.get("is_anomaly", pd.Series(False)).sum()) if "is_anomaly" in df.columns else 0
    chains    = df["chain"].nunique() if "chain" in df.columns else 0
    tokens    = df["token"].nunique() if "token" in df.columns else 0

    # Overall risk verdict
    if critical > 0:
        verdict = "CRITICAL — Immediate escalation required"
        vc = C_CRITICAL
    elif high > 0:
        verdict = "HIGH — SAR filing recommended"
        vc = C_HIGH
    elif anomalies > 5:
        verdict = "MEDIUM — Further investigation warranted"
        vc = C_MEDIUM
    else:
        verdict = "LOW — No significant indicators"
        vc = C_LOW

    vt = Table([[Paragraph(f"Overall Risk Verdict: {verdict}", ParagraphStyle(
        "verdict", fontSize=11, textColor=C_WHITE, fontName="Helvetica-Bold"
    ))]], colWidths=[6.5*inch])
    vt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),vc),
                             ("TOPPADDING",(0,0),(-1,-1),10),
                             ("BOTTOMPADDING",(0,0),(-1,-1),10),
                             ("LEFTPADDING",(0,0),(-1,-1),12)]))
    elems.append(vt)
    elems.append(Spacer(1, 10))

    metrics = {
        "Transactions":   f"{len(df):,}",
        "Total Volume":   _fmt_crypto(total_vol),
        "Critical Flags": str(critical),
        "High Flags":     str(high),
        "ML Anomalies":   str(anomalies),
        "Chains":         str(chains),
        "Tokens":         str(tokens),
        "Analyses Run":   str(sum(1 for k in [
            "ofac_df","rw_df","mev_df","rug_df","tc_df","vel_df",
            "gnn_df","ts_r","pattern_results","swap_df"
        ] if _has(k))),
    }
    elems.append(_metric_table(metrics, 4))
    elems.append(Spacer(1, 10))

    # Top 5 critical findings
    if critical > 0 or high > 0:
        elems += _subsection("Top Risk Transactions", styles)
        top = df[df.get("risk_level","") == "CRITICAL"].head(5) if critical > 0 \
              else df[df.get("risk_level","") == "HIGH"].head(5)
        cols = [c for c in ["date","from_address","to_address","amount","token","risk_level","risk_reasons"]
                if c in top.columns]
        if not top.empty and cols:
            cw = [0.7, 1.2, 1.2, 0.7, 0.5, 0.7, 1.5][:len(cols)]
            cw = [w*inch for w in cw]
            elems.append(_df_to_table(top[cols], cw, max_rows=5))

    return elems


def _section_dataset(df: pd.DataFrame, sections: list, styles) -> List:
    sections.append("Dataset Overview")
    elems = _next_section("Dataset Overview", styles)

    # Date range
    if "date" in df.columns and df["date"].notna().any():
        d_min = str(df["date"].min())[:10]
        d_max = str(df["date"].max())[:10]
        elems.append(Paragraph(f"Date range: {d_min} → {d_max}", styles["small"]))
        elems.append(Spacer(1, 4))

    # Risk distribution table
    elems += _subsection("Risk Distribution", styles)
    if "risk_level" in df.columns:
        rc = df["risk_level"].value_counts().reset_index()
        rc.columns = ["Risk Level","Count"]
        rc["Volume"] = rc["Risk Level"].apply(
            lambda r: _fmt_crypto(df[df["risk_level"]==r]["amount"].sum()) if "amount" in df.columns else "—"
        )
        rc_data = [["Risk Level","Count","Volume"]] + rc.values.tolist()
        rc_table = Table(rc_data, colWidths=[2*inch, 1*inch, 2*inch])
        rc_styles = [
            ("BACKGROUND",(0,0),(-1,0), C_HEADER),("TEXTCOLOR",(0,0),(-1,0), C_WHITE),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),0.3, HexColor("#e2e8f0")),
            ("LEFTPADDING",(0,0),(-1,-1),6),("TOPPADDING",(0,0),(-1,-1),4),
        ]
        for r, row in enumerate(rc.values, 1):
            bg = RISK_COLOR.get(str(row[0]).upper(), C_GREY_LIGHT)
            rc_styles.append(("BACKGROUND",(0,r),(0,r), bg))
            tc = C_WHITE if row[0] in ("CRITICAL","HIGH") else colors.black
            rc_styles.append(("TEXTCOLOR",(0,r),(0,r), tc))
        rc_table.setStyle(TableStyle(rc_styles))
        elems.append(rc_table)
        elems.append(Spacer(1, 8))

    # Transaction ledger (critical + high only)
    elems += _subsection("Critical & High Risk Transactions", styles)
    if "risk_level" in df.columns:
        flagged = df[df["risk_level"].isin(["CRITICAL","HIGH"])].head(40)
        if not flagged.empty:
            cols = [c for c in ["date","from_address","to_address","amount","token",
                                 "risk_level","risk_reasons"] if c in flagged.columns]
            cw   = [0.85,1.35,1.35,0.6,0.45,0.6,1.8][:len(cols)]
            elems.append(_df_to_table(flagged[cols], [w*inch for w in cw]))
            if len(df[df["risk_level"].isin(["CRITICAL","HIGH"])]) > 40:
                elems.append(Paragraph(
                    f"Note: Showing top 40 of {len(df[df['risk_level'].isin(['CRITICAL','HIGH'])])} flagged transactions.",
                    styles["small"]))
    return elems


def _section_ofac(sections: list, styles) -> List:
    odf = _ss("ofac_df")
    if odf is None or not isinstance(odf, pd.DataFrame):
        return []
    hits = odf[odf.get("ofac_hit", pd.Series(False, index=odf.index))==True] if "ofac_hit" in odf.columns else pd.DataFrame()
    sections.append(f"OFAC SDN Screening ({len(hits)} hits)")
    elems = _next_section(f"OFAC SDN Screening", styles)
    elems.append(Paragraph(
        f"Dataset screened against the U.S. Treasury OFAC Specially Designated Nationals list. "
        f"{'🚨 SANCTIONS MATCH DETECTED — immediate legal escalation required.' if not hits.empty else '✅ No SDN matches found.'}",
        styles["warn"] if not hits.empty else styles["body"]))
    elems.append(Spacer(1, 6))
    if not hits.empty:
        cols = [c for c in ["date","from_address","to_address","amount","token","ofac_entity","risk_level"] if c in hits.columns]
        cw   = [0.85,1.35,1.35,0.55,0.45,1.1,0.35][:len(cols)]
        elems.append(_df_to_table(hits[cols], [w*inch for w in cw]))
    return elems


def _section_ransomware(sections: list, styles) -> List:
    rdf = _ss("rw_df")
    if rdf is None or not isinstance(rdf, pd.DataFrame): return []
    hits = rdf[rdf.get("ransomware_hit", pd.Series(False))==True] if "ransomware_hit" in rdf.columns else pd.DataFrame()
    sections.append(f"Ransomware Screening ({len(hits)} hits)")
    elems = _next_section("Ransomware Screening (Ransomwhere.co)", styles)
    status = f"🚨 {len(hits)} RANSOMWARE ADDRESS MATCHES — immediate escalation." if not hits.empty else "✅ No ransomware matches."
    elems.append(Paragraph(status, styles["warn"] if not hits.empty else styles["body"]))
    elems.append(Spacer(1, 6))
    if not hits.empty:
        # from_address is always the ransomware address; to_address adds little
        # forensic value in this table and eats width — show it only if no source col
        has_source = "ransomware_source" in hits.columns
        if has_source:
            cols = [c for c in ["date","from_address","amount","token",
                                 "ransomware_family","ransomware_source","ransomware_paid"]
                    if c in hits.columns]
            cw   = [0.85, 1.5, 0.55, 0.45, 1.0, 1.1, 0.55][:len(cols)]
        else:
            cols = [c for c in ["date","from_address","to_address","amount","token",
                                 "ransomware_family","ransomware_paid"]
                    if c in hits.columns]
            # With truncation active, 1.4" each is safe for addresses
            cw   = [0.85, 1.4, 1.4, 0.55, 0.45, 1.0, 0.55][:len(cols)]
        elems.append(_df_to_table(hits[cols], [w*inch for w in cw]))
    return elems


def _section_pattern_intel(sections: list, styles) -> List:
    pr = _ss("pattern_results")
    if not pr: return []
    sections.append("Pattern Intelligence")
    elems = _next_section("Pattern Intelligence", styles)

    def _mini(label, findings, key_col, detail_col, sev_col="severity"):
        if not findings:
            return [Paragraph(f"**{label}:** No findings.", styles["small"]), Spacer(1,2)]
        sub = _subsection(f"{label} ({len(findings)} findings)", styles)
        sub += _flag_table(findings[:10], key_col, detail_col, sev_col, styles)
        return sub + [Spacer(1,4)]

    # Structuring
    struct = pr.get("structuring",[])
    elems += _mini("Structuring / Smurfing", struct, "address", "fatf_ref")

    # Circular flows
    circular = pr.get("circular",[])
    elems += _mini("Circular Flows", circular, "typology", "cycle_length", "severity_score")

    # Mixers
    mixers = pr.get("mixers",[])
    if mixers:
        elems += _subsection(f"Mixer Candidates ({len(mixers)})", styles)
        mx_df = pd.DataFrame(mixers)
        cols  = [c for c in ["address","mixer_score","fan_in","fan_out","total_volume","classification"] if c in mx_df.columns]
        if cols:
            cw = [1.5,0.8,0.6,0.6,0.9,1.1][:len(cols)]
            elems.append(_df_to_table(mx_df[cols], [w*inch for w in cw]))
        elems.append(Spacer(1,4))

    # Peeling chains
    peeling = pr.get("peeling",[])
    elems += _mini("Peeling Chains", peeling, "start_address", "peel_pct")

    # Cross-chain
    cc = pr.get("cross_chain",[])
    if cc:
        elems += _subsection(f"Cross-chain Hops ({len(cc)})", styles)
        cc_df = pd.DataFrame(cc)
        cols  = [c for c in ["chain_from","chain_to","amount","delta_hours","token_a"] if c in cc_df.columns]
        if cols:
            cw = [1.0,1.0,0.9,0.8,0.8][:len(cols)]
            elems.append(_df_to_table(cc_df[cols], [w*inch for w in cw]))

    return elems


def _section_mev(sections: list, styles) -> List:
    mev = _ss("mev_df")
    rug = _ss("rug_df")
    dump= _ss("dump_df")
    if mev is None and rug is None and dump is None: return []
    sections.append("Market Manipulation Intelligence")
    elems = _next_section("Market Manipulation Intelligence", styles)

    if mev is not None and isinstance(mev, pd.DataFrame) and not mev.empty:
        elems += _subsection(f"MEV / Sandwich Attacks ({len(mev)})", styles)
        cols = [c for c in ["date","attack_type","bot_address","victim_address","token","estimated_profit","severity"] if c in mev.columns]
        cw   = [0.85,0.85,1.35,1.35,0.45,0.75,0.4][:len(cols)]
        elems.append(_df_to_table(mev[cols], [w*inch for w in cw]))
        elems.append(Spacer(1,6))

    if rug is not None and isinstance(rug, pd.DataFrame) and not rug.empty:
        elems += _subsection(f"Rug Pull Indicators ({len(rug)})", styles)
        for _, row in rug.iterrows():
            t = Table([[f"[{row.get('pattern','')}]", str(row.get('token',''))],
                       ["", str(row.get('evidence',''))[:200]]],
                      colWidths=[1.2*inch, 5.3*inch])
            t.setStyle(TableStyle([("FONTSIZE",(0,0),(-1,-1),7),("GRID",(0,0),(-1,-1),0.2,C_GREY_LIGHT),
                                    ("LEFTPADDING",(0,0),(-1,-1),4),("BACKGROUND",(0,0),(0,0),C_CRITICAL),
                                    ("TEXTCOLOR",(0,0),(0,0),C_WHITE),("FONTNAME",(0,0),(0,0),"Helvetica-Bold")]))
            elems += [t, Spacer(1,2)]
        elems.append(Spacer(1,4))

    if dump is not None and isinstance(dump, pd.DataFrame) and not dump.empty:
        elems += _subsection(f"Coordinated Dumps ({len(dump)})", styles)
        cols = [c for c in ["token","coordinated_sellers","total_sold","insider_ratio","window_start","severity"] if c in dump.columns]
        cw   = [0.8,1.0,0.9,0.8,1.0,0.7][:len(cols)]
        elems.append(_df_to_table(dump[cols], [w*inch for w in cw]))

    return elems


def _section_osint(sections: list, styles) -> List:
    proto = _ss("proto_df")
    dark  = _ss("dark_df")
    dust  = _ss("dust_df")
    flash = _ss("flash_df")
    if all(x is None for x in [proto, dark, dust, flash]): return []
    sections.append("OSINT Intelligence")
    elems = _next_section("OSINT Intelligence", styles)

    if proto is not None and isinstance(proto, pd.DataFrame) and "protocol" in proto.columns:
        labeled = proto[proto["protocol"] != ""]
        if not labeled.empty:
            elems += _subsection(f"DeFi Protocol Interactions ({len(labeled)} transactions)", styles)
            summary = labeled.groupby("protocol").agg(count=("amount","size"), volume=("amount","sum")).reset_index()
            cw = [2.5*inch, 0.8*inch, 1.5*inch]
            elems.append(_df_to_table(summary.head(15), cw))
            elems.append(Spacer(1,6))

    if dark is not None and isinstance(dark, pd.DataFrame):
        hits = dark[dark.get("darknet_hit", pd.Series(False))==True] if "darknet_hit" in dark.columns else pd.DataFrame()
        if not hits.empty:
            elems += _subsection(f"Darknet Intelligence ({len(hits)} hits)", styles)
            cols = [c for c in ["date","from_address","to_address","amount","darknet_entity"] if c in hits.columns]
            cw   = [0.85,1.35,1.35,0.65,2.8][:len(cols)]
            elems.append(_df_to_table(hits[cols], [w*inch for w in cw]))
            elems.append(Spacer(1,6))

    if dust is not None and isinstance(dust, pd.DataFrame) and not dust.empty:
        elems += _subsection(f"Dust Attack Suspects ({len(dust)})", styles)
        cols = [c for c in ["attacker_address","token","dust_tx_count","victims_targeted","severity"] if c in dust.columns]
        cw   = [1.8,0.6,0.8,0.9,0.6][:len(cols)]
        elems.append(_df_to_table(dust[cols], [w*inch for w in cw]))
        elems.append(Spacer(1,6))

    if flash is not None and isinstance(flash, pd.DataFrame) and not flash.empty:
        elems += _subsection(f"Flash Loan Activity ({len(flash)} transactions)", styles)
        cols = [c for c in ["date","from_address","to_address","amount","token","protocol","severity"] if c in flash.columns]
        cw   = [0.85,1.35,1.35,0.6,0.45,0.95,0.45][:len(cols)]
        elems.append(_df_to_table(flash[cols], [w*inch for w in cw]))

    return elems


def _section_address_intel(sections: list, styles) -> List:
    cls_df = _ss("class_df")
    exc_df = _ss("exc_df")
    cio    = _ss("cio_summary")
    chg    = _ss("chg_df")
    if all(x is None for x in [cls_df, exc_df, cio, chg]): return []
    sections.append("Address Intelligence")
    elems = _next_section("Address Intelligence", styles)

    if cio is not None and isinstance(cio, pd.DataFrame) and not cio.empty:
        elems += _subsection(f"Entity Clusters / Co-spending ({len(cio)} clusters)", styles)
        cols = [c for c in ["cluster_id","address_count","total_volume","heuristic"] if c in cio.columns]
        cw   = [0.8,0.9,1.2,2.6][:len(cols)]
        elems.append(_df_to_table(cio[cols].head(20), [w*inch for w in cw]))
        elems.append(Spacer(1,6))

    if cls_df is not None and isinstance(cls_df, pd.DataFrame) and not cls_df.empty:
        elems += _subsection(f"Address Type Classification ({len(cls_df)} addresses)", styles)
        cols = [c for c in ["address","type","label","confidence","tx_count","out_volume"] if c in cls_df.columns]
        cw   = [1.6,1.0,1.2,0.7,0.6,0.9][:len(cols)]
        elems.append(_df_to_table(cls_df[cols].head(30), [w*inch for w in cw]))
        elems.append(Spacer(1,6))

    if exc_df is not None and isinstance(exc_df, pd.DataFrame) and not exc_df.empty:
        elems += _subsection(f"Exchange Endpoints ({len(exc_df)} transactions) — Investigation Endpoints", styles)
        elems.append(Paragraph(
            "⚠️ Funds reached the following exchanges. Serve legal process to obtain KYC identity of account holders.",
            styles["warn"]))
        elems.append(Spacer(1,4))
        if "exchange_name" in exc_df.columns:
            summary = exc_df.groupby("exchange_name").agg(count=("amount","size"), volume=("amount","sum")).reset_index()
            cw = [2.0*inch, 0.8*inch, 1.5*inch]
            elems.append(_df_to_table(summary, cw))
        elems.append(Spacer(1,6))

    if chg is not None and isinstance(chg, pd.DataFrame) and not chg.empty:
        elems += _subsection(f"Change Address Candidates ({len(chg)})", styles)
        cols = [c for c in ["likely_change_address","from_address","change_amount","confidence"] if c in chg.columns]
        cw   = [1.8,1.8,1.0,0.9][:len(cols)]
        elems.append(_df_to_table(chg[cols].head(20), [w*inch for w in cw]))

    return elems


def _section_velocity(sections: list, styles) -> List:
    vel = _ss("vel_df")
    if vel is None or not isinstance(vel, pd.DataFrame): return []
    sections.append("Velocity Analysis")
    elems = _next_section("Velocity Analysis — Time-to-Forward", styles)
    instant = vel[vel.get("velocity_class","").str.contains("INSTANT", na=False)] if "velocity_class" in vel.columns else pd.DataFrame()
    rapid   = vel[vel.get("velocity_class","").str.contains("RAPID",   na=False)] if "velocity_class" in vel.columns else pd.DataFrame()
    elems.append(_metric_table({
        "Addresses Analyzed": len(vel),
        "Instant (<15min)":   len(instant),
        "Rapid (<1hr)":       len(rapid),
        "Median TTF":         f"{vel['ttf_hours'].median():.1f}h" if "ttf_hours" in vel.columns else "—",
    }, 4))
    elems.append(Spacer(1,6))
    high_vel = vel.head(20)
    cols = [c for c in ["address","ttf_minutes","velocity_class","velocity_score","volume_sent"] if c in high_vel.columns]
    cw   = [1.8,0.8,1.2,0.8,1.3][:len(cols)]
    elems.append(_df_to_table(high_vel[cols], [w*inch for w in cw]))
    return elems


def _section_tornado(sections: list, styles) -> List:
    tc = _ss("tc_df")
    if tc is None or not isinstance(tc, pd.DataFrame): return []
    sections.append(f"Tornado Cash Statistical Links ({len(tc)} pairs)")
    elems = _next_section("Tornado Cash Deposit→Withdrawal Statistical Links", styles)
    elems.append(Paragraph(
        "⚠️ OFAC sanctioned since August 2022. Statistical links below are probabilistic — "
        "suitable for investigative leads, not standalone evidence.",
        styles["warn"]))
    elems.append(Spacer(1,6))
    cols = [c for c in ["confidence","deposit_from","withdrawal_to","denomination","token",
                          "hours_elapsed","anonymity_set_size"] if c in tc.columns]
    cw   = [0.85,1.35,1.35,0.7,0.45,0.65,0.65][:len(cols)]
    elems.append(_df_to_table(tc[cols].head(30), [w*inch for w in cw]))
    return elems


def _section_atomic_swaps(sections: list, styles) -> List:
    sw = _ss("swap_df")
    pr = _ss("priv_df")
    if sw is None and pr is None: return []
    sections.append("Atomic Swaps & Privacy Coins")
    elems = _next_section("Atomic Swaps & Privacy Coin Activity", styles)

    if sw is not None and isinstance(sw, pd.DataFrame) and not sw.empty:
        elems += _subsection(f"Atomic Swap / Cross-chain DEX ({len(sw)} events)", styles)
        cols = [c for c in ["date","pattern","protocol","risk","from_address","amount","token"] if c in sw.columns]
        cw   = [0.85,1.0,1.0,0.55,1.35,0.7,0.55][:len(cols)]
        elems.append(_df_to_table(sw[cols].head(25), [w*inch for w in cw]))
        elems.append(Spacer(1,6))

    if pr is not None and isinstance(pr, pd.DataFrame) and not pr.empty:
        elems += _subsection(f"Privacy Coin Activity ({len(pr)} events)", styles)
        elems.append(Paragraph(
            "🔴 Funds entering a privacy coin are PERMANENTLY UNTRACEABLE beyond this point.",
            styles["warn"]))
        elems.append(Spacer(1,4))
        cols = [c for c in ["type","coin","from_address","to_address","amount","date"] if c in pr.columns]
        cw   = [1.0,0.55,1.35,1.35,0.7,1.05][:len(cols)]
        elems.append(_df_to_table(pr[cols].head(20), [w*inch for w in cw]))

    return elems


def _section_gnn(sections: list, styles) -> List:
    gnn = _ss("gnn_df")
    if gnn is None or not isinstance(gnn, pd.DataFrame): return []
    sections.append("GNN Address Clustering")
    elems = _next_section("Graph Neural Network Address Clustering", styles)
    n_clusters = gnn["spectral_cluster"].nunique() if "spectral_cluster" in gnn.columns else 0
    elems.append(Paragraph(
        f"{len(gnn)} addresses grouped into {n_clusters} behavioral clusters using spectral "
        "graph clustering on PageRank, degree, volume, and clustering coefficient features.",
        styles["body"]))
    elems.append(Spacer(1,6))
    cols = [c for c in ["spectral_cluster","address","type","pagerank","out_volume","risk_level"] if c in gnn.columns]
    cw   = [0.8,1.8,1.0,0.8,1.0,0.7][:len(cols)]
    elems.append(_df_to_table(gnn[cols].head(40), [w*inch for w in cw]))
    return elems


def _section_time_series(sections: list, styles) -> List:
    ts = _ss("ts_r")
    if not ts: return []
    ramp = ts.get("ramp",[])
    cycl = ts.get("cycl",[])
    dorm = ts.get("dorm",[])
    if not any([ramp, cycl, dorm]): return []
    sections.append("Time Series ML Analysis")
    elems = _next_section("Time Series ML — Adaptive Laundering Detection", styles)

    if ramp:
        elems += _subsection(f"Ramping Patterns ({len(ramp)})", styles)
        elems += _flag_table(ramp[:10], "address", "description", "severity", styles)
        elems.append(Spacer(1,4))

    if cycl:
        elems += _subsection(f"Cyclical / Bot Patterns ({len(cycl)})", styles)
        elems += _flag_table(cycl[:10], "address", "description", "severity", styles)
        elems.append(Spacer(1,4))

    if dorm:
        elems += _subsection(f"Dormant Reactivation ({len(dorm)})", styles)
        dorm_df = pd.DataFrame(dorm)
        cols    = [c for c in ["address","gap_days","reactivation_date","volume_after","severity"] if c in dorm_df.columns]
        cw      = [1.8,0.7,1.0,0.9,0.6][:len(cols)]
        elems.append(_df_to_table(dorm_df[cols].head(15), [w*inch for w in cw]))

    return elems


def _section_advanced(sections: list, styles) -> List:
    wash = _ss("wash_df")
    farm = _ss("farm_df")
    safe = _ss("safe_info")
    if wash is None and farm is None and (safe is None or not safe.get("is_multisig")):
        return []
    sections.append("Advanced Analysis")
    elems = _next_section("Advanced Analysis", styles)

    if wash is not None and isinstance(wash, pd.DataFrame) and not wash.empty:
        elems += _subsection(f"NFT Wash Trading ({len(wash)} patterns)", styles)
        cols = [c for c in ["pattern","token","wash_address","buy_price","sell_price","hold_hours","severity"] if c in wash.columns]
        cw   = [1.0,0.8,1.5,0.8,0.8,0.6,0.5][:len(cols)]
        elems.append(_df_to_table(wash[cols].head(20), [w*inch for w in cw]))
        elems.append(Spacer(1,6))

    if farm is not None and isinstance(farm, pd.DataFrame) and not farm.empty:
        elems += _subsection(f"Airdrop Farming Suspects ({len(farm)})", styles)
        cols = [c for c in ["address","unique_protocols","tx_count","avg_tx_amount","severity"] if c in farm.columns]
        cw   = [1.8,1.0,0.7,1.0,0.7][:len(cols)]
        elems.append(_df_to_table(farm[cols].head(15), [w*inch for w in cw]))
        elems.append(Spacer(1,6))

    if safe and safe.get("is_multisig"):
        elems += _subsection("Multi-Signature Wallet Analysis", styles)
        elems.append(Paragraph(
            f"Address: {safe.get('address','')}\n"
            f"Threshold: {safe.get('threshold',0)}-of-{len(safe.get('owners',[]))}\n"
            f"Historical transactions: {safe.get('historical_tx_count',0)}",
            styles["body"]))
        owners = safe.get("owners",[])
        if owners:
            elems.append(Paragraph("Signers (each is a separate investigative lead):", styles["h3"]))
            for j, owner in enumerate(owners):
                elems.append(Paragraph(f"Signer {j+1}: {owner}", styles["code"]))

    return elems


def _section_hop_trace(sections: list, styles) -> List:
    summary = _ss("trace_summary")
    if not summary: return []
    sections.append("Multi-hop Fund Trace")
    elems = _next_section("Multi-hop Fund Trace", styles)
    for line in summary.split("\n")[:50]:
        if line.strip():
            elems.append(Paragraph(line.strip(), styles["code"]))
    return elems


def _section_usd(sections: list, styles) -> List:
    usd = _ss("usd_df")
    if usd is None or not isinstance(usd, pd.DataFrame): return []
    sections.append("Historical USD Valuation")
    elems = _next_section("Historical USD Valuation", styles)
    elems.append(_metric_table({
        "Total USD Value": f"${usd['usd_value'].sum():,.2f}",
        "Avg Tx USD":      f"${usd['usd_value'].mean():,.2f}",
        "Max Single Tx":   f"${usd['usd_value'].max():,.2f}",
        "Priced Txs":      str(usd["usd_value"].notna().sum()),
    }, 4))
    elems.append(Spacer(1,6))
    cols = [c for c in ["date","from_address","to_address","amount","token","usd_value","risk_level"] if c in usd.columns]
    cw   = [0.85,1.35,1.35,0.6,0.45,0.95,0.45][:len(cols)]
    elems.append(_df_to_table(usd[cols].nlargest(30, "usd_value"), [w*inch for w in cw]))
    return elems


def _section_ai(sections: list, styles) -> List:
    ai = _ss("ai_result")
    if not ai: return []
    sections.append("AI Forensics Analysis (Claude)")
    elems = _next_section("AI Forensics Analysis — Claude Anthropic", styles)
    for para in ai.split("\n\n")[:40]:
        if para.strip():
            elems.append(Paragraph(para.strip()[:600], styles["body"]))
            elems.append(Spacer(1, 4))
    return elems


def _section_sar(sections: list, styles) -> List:
    sar = _ss("sar_narrative")
    if not sar: return []
    sections.append("SAR Narrative (Draft)")
    elems = _next_section("Suspicious Activity Report Narrative (DRAFT)", styles)
    elems.append(Paragraph(
        "⚠️ DRAFT — Requires review and signature by BSA Officer before FinCEN submission.",
        styles["warn"]))
    elems.append(Spacer(1,6))
    for line in sar.split("\n")[:80]:
        elems.append(Paragraph(line if line.strip() else " ", styles["body"]))
    return elems


def _section_evidence_log(sections: list, styles) -> List:
    log_file = Path("evidence_audit_log.jsonl")
    if not log_file.exists(): return []
    rows = []
    try:
        with open(log_file) as f:
            for line in f:
                try: rows.append(json.loads(line.strip()))
                except: pass
    except Exception:
        return []
    if not rows: return []
    sections.append(f"Evidence Audit Log ({len(rows)} entries)")
    elems = _next_section("Evidence Audit Log — Chain of Custody", styles)
    log_df = pd.DataFrame(rows)
    cols   = [c for c in ["timestamp","action","analyst","details","entry_hash"] if c in log_df.columns]
    cw     = [1.2,1.2,0.9,2.5,0.7][:len(cols)]
    elems.append(_df_to_table(log_df[cols].head(30), [w*inch for w in cw]))
    return elems


def _section_case_notes(sections: list, styles) -> List:
    notes_file = Path("case_notes.json")
    if not notes_file.exists(): return []
    try:
        notes_data = json.loads(notes_file.read_text())
    except Exception:
        return []
    cases = notes_data.get("cases",{})
    tags  = notes_data.get("address_tags",{})
    if not cases and not tags: return []
    sections.append("Case Notes & Address Tags")
    elems = _next_section("Case Notes & Address Tags", styles)

    for case_id, case in list(cases.items())[:5]:
        elems += _subsection(f"Case: {case_id}", styles)
        elems.append(Paragraph(case.get("summary","")[:300], styles["body"]))
        for note in case.get("notes",[])[-10:]:
            elems.append(Paragraph(f"[{note.get('timestamp','')}] {note.get('tag','')} — {note.get('text','')[:200]}", styles["small"]))
        elems.append(Spacer(1,4))

    if tags:
        elems += _subsection(f"Tagged Addresses ({len(tags)})", styles)
        tag_rows = [["Address","Label","Note","Tagged At"]]
        for addr, info in list(tags.items())[:30]:
            tag_rows.append([addr[:30], info.get("label",""), info.get("note","")[:40], info.get("tagged_at","")[:10]])
        t = _std_table(tag_rows, [2.0*inch,1.2*inch,1.8*inch,0.8*inch])
        elems.append(t)

    return elems


def _section_certificate(sections: list, styles) -> List:
    cert = _ss("certificate")
    if not cert: return []
    sections.append("EIP-712 Evidence Certificate")
    elems = _next_section("EIP-712 Cryptographic Evidence Certificate", styles)
    for line in cert.split("\n"):
        elems.append(Paragraph(line if line.strip() else " ", styles["code"]))
    return elems


# ─────────────────────────────────────────────────────────────
# MAIN REPORT GENERATOR
# ─────────────────────────────────────────────────────────────


def _section_honeypot(sections: list, styles) -> List:
    hp = _ss("hp_batch")
    if hp is None or not isinstance(hp, pd.DataFrame): return []
    honeypots = hp[hp.get("is_honeypot", pd.Series(False)) == True] if "is_honeypot" in hp.columns else pd.DataFrame()
    sections.append(f"Honeypot Screening ({len(honeypots)} confirmed)")
    elems = _next_section("Honeypot Contract Screening (honeypot.is)", styles)
    elems.append(Paragraph(
        f"{'🚨 ' + str(len(honeypots)) + ' HONEYPOT CONTRACTS CONFIRMED — tokens cannot be sold.' if not honeypots.empty else '✅ No honeypot contracts detected.'}",
        styles["warn"] if not honeypots.empty else styles["body"]))
    elems.append(Spacer(1, 6))
    cols = [c for c in ["address","is_honeypot","buy_tax","sell_tax","risk_level"] if c in hp.columns]
    cw   = [2.0,0.8,0.7,0.7,0.9][:len(cols)]
    elems.append(_df_to_table(hp[cols].head(20), [w*inch for w in cw]))
    return elems


def _section_travel_rule(sections: list, styles) -> List:
    tr = _ss("tr_df")
    if tr is None or not isinstance(tr, pd.DataFrame): return []
    required = tr[tr.get("travel_rule_required", pd.Series(False)) == True] if "travel_rule_required" in tr.columns else pd.DataFrame()
    if required.empty: return []
    sections.append(f"FATF Travel Rule ({len(required)} transactions)")
    elems = _next_section("FATF Travel Rule Compliance (Recommendation 16)", styles)
    elems.append(Paragraph(
        f"{len(required)} transactions exceed the $1,000 Travel Rule threshold and require "
        "VASP-to-VASP originator/beneficiary information sharing. "
        "FATF R.16 is now mandatory in 60+ jurisdictions.",
        styles["body"]))
    elems.append(Spacer(1, 6))
    cols = [c for c in ["date","from_address","to_address","amount","token","jurisdiction_note"] if c in required.columns]
    cw   = [0.85,1.35,1.35,0.6,0.45,2.4][:len(cols)]
    elems.append(_df_to_table(required[cols].head(30), [w*inch for w in cw]))
    # CTR check
    ctr_hits = required[required["amount"] >= 10000] if "amount" in required.columns else pd.DataFrame()
    if not ctr_hits.empty:
        elems.append(Spacer(1, 6))
        elems.append(Paragraph(
            f"⚠️ CTR REQUIRED: {len(ctr_hits)} transactions ≥ $10,000 require Currency Transaction Report filing within 15 days.",
            styles["warn"]))
    return elems


def _section_portfolio(sections: list, styles) -> List:
    port = _ss("port_df")
    if port is None or not isinstance(port, pd.DataFrame): return []
    non_zero = port[port.get("balance", pd.Series(0)) > 0] if "balance" in port.columns else port
    if non_zero.empty: return []
    sections.append(f"Portfolio Balances ({len(non_zero)} addresses with funds)")
    elems = _next_section("Current Portfolio Balances — Asset Seizure Reference", styles)
    total = port["balance"].sum() if "balance" in port.columns else 0
    elems.append(Paragraph(
        f"⚠️ SEIZURE REFERENCE: {len(non_zero)} addresses hold active balances totalling "
        f"{total:,.4f} tokens. This section should be included in any asset freeze application.",
        styles["warn"]))
    elems.append(Spacer(1, 6))
    elems.append(_metric_table({
        "Addresses Checked": len(port),
        "Non-zero Wallets":  len(non_zero),
        "Total Balance":     f"{total:,.4f}",
        "Chain":             port["chain"].iloc[0] if "chain" in port.columns and len(port) else "—",
    }, 4))
    elems.append(Spacer(1, 6))
    cols = [c for c in ["address","chain","balance","token","status"] if c in non_zero.columns]
    cw   = [2.0,0.8,0.9,0.6,0.9][:len(cols)]
    elems.append(_df_to_table(non_zero.sort_values("balance", ascending=False)[cols].head(30),
                               [w*inch for w in cw]))
    return elems


def _section_l2_chains(sections: list, styles) -> List:
    l2 = _ss("l2_results")
    if not l2 or not isinstance(l2, dict): return []
    sections.append(f"Layer 2 Chain Activity ({len(l2)} chains)")
    elems = _next_section("Layer 2 Chain Activity", styles)
    elems.append(Paragraph(
        "Transactions found on Ethereum Layer 2 networks. Funds that bridge to L2 "
        "continue with lower fees and reduced mainnet visibility.",
        styles["body"]))
    elems.append(Spacer(1, 6))
    for chain_name, chain_data in l2.items():
        if isinstance(chain_data, dict) and "transactions" in chain_data:
            chain_df = chain_data["transactions"]
            if isinstance(chain_df, pd.DataFrame) and not chain_df.empty:
                elems += _subsection(f"{chain_name.title()} — {len(chain_df)} transactions, "
                                      f"{_fmt_crypto(chain_df['amount'].sum())} {chain_data.get('native_token','ETH')} volume", styles)
                cols = [c for c in ["date","from_address","to_address","amount","token","tx_hash"] if c in chain_df.columns]
                cw   = [0.85,1.35,1.35,0.6,0.45,1.4][:len(cols)]
                elems.append(_df_to_table(chain_df[cols].head(10), [w*inch for w in cw]))
                elems.append(Spacer(1, 4))
    return elems


def _section_solana(sections: list, styles) -> List:
    sol = _ss("sol_df")
    if sol is None or not isinstance(sol, pd.DataFrame): return []
    sections.append(f"Solana Chain Analysis ({len(sol)} transactions)")
    elems = _next_section("Solana Chain Analysis", styles)
    elems.append(Paragraph(
        f"{len(sol)} Solana transactions fetched. "
        f"Tokens: {sol['token'].nunique() if 'token' in sol.columns else 0}. "
        f"Programs: {sol['program_name'].nunique() if 'program_name' in sol.columns else 0}.",
        styles["body"]))
    elems.append(Spacer(1, 6))
    if "program_name" in sol.columns:
        prog_sum = sol.groupby("program_name").agg(
            tx_count=("amount","size"), volume=("amount","sum")
        ).reset_index().sort_values("volume", ascending=False)
        elems += _subsection("Program Interactions", styles)
        cw = [2.2*inch, 0.9*inch, 1.4*inch]
        elems.append(_df_to_table(prog_sum.head(15), cw))
        elems.append(Spacer(1, 6))
    cols = [c for c in ["date","from_address","to_address","amount","token","program_name"] if c in sol.columns]
    cw   = [0.85,1.35,1.35,0.6,0.45,1.4][:len(cols)]
    elems.append(_df_to_table(sol[cols].head(30), [w*inch for w in cw]))
    return elems


def _section_geolocation(sections: list, styles) -> List:
    # Geolocation data is per-query in session, stored as last result
    # We store it under "geo_result" when the user runs it
    geo = st.session_state.get("geo_last_result")
    if not geo or "error" in geo: return []
    sections.append("Geolocation Approximation")
    elems = _next_section("Geolocation Approximation (Transaction Timing Analysis)", styles)
    elems.append(Paragraph(
        "⚠️ Probabilistic estimate from transaction timing patterns only. "
        "Not admissible as definitive location evidence.",
        styles["small"]))
    elems.append(Spacer(1, 6))
    elems.append(_metric_table({
        "Address":            geo.get("address","")[:20]+"…",
        "Peak Hour (UTC)":    f"{geo.get('peak_activity_hour',0):02d}:00",
        "Est. UTC Offset":    f"UTC{geo.get('estimated_utc_offset',0):+d}",
        "Jurisdiction":       geo.get("estimated_jurisdiction","Unknown"),
        "Automation":         "Bot likely" if geo.get("is_automated") else "Human operator",
        "Uniformity":         f"{geo.get('activity_uniformity',0):.0%}",
        "Active Hours":       str(geo.get("active_hours",0)),
        "Total Tx Analyzed":  str(geo.get("total_transactions",0)),
    }, 4))
    return elems



def _section_offchain_evidence(sections: list, styles) -> List:
    """Off-chain payment evidence and attached files from case dashboard."""
    # Load cases from disk
    cases_file = Path("regulatory_cases.json")
    if not cases_file.exists():
        return []
    try:
        cases = json.loads(cases_file.read_text())
    except Exception:
        return []

    # Collect all payments and files across all cases
    all_payments = []
    all_files    = []
    for case in cases:
        cid = case.get("case_id","?")
        for pay in case.get("offchain_payments",[]):
            all_payments.append({**pay, "_case_id": cid})
        for ev in case.get("evidence_files",[]):
            all_files.append({**ev, "_case_id": cid})

    if not all_payments and not all_files:
        return []

    sections.append(f"Off-chain Payment Evidence ({len(all_payments)} payments, {len(all_files)} files)")
    elems = _next_section("Off-chain Payment Evidence", styles)
    elems.append(Paragraph(
        "Fiat payment records (Zelle, PayPal, CashApp, Venmo, wire transfers, etc.) "
        "linked to this investigation. Screenshots and attachments noted below.",
        styles["body"]))
    elems.append(Spacer(1, 8))

    # ── Payment records table ─────────────────────────────────
    if all_payments:
        elems += _subsection(f"Off-chain Payment Records ({len(all_payments)})", styles)
        pay_rows = [["Case","Platform","Date","Sender","Receiver","Amount","Linked Address"]]
        for pay in all_payments[:50]:
            pay_rows.append([
                pay.get("_case_id","")[:12],
                pay.get("platform",""),
                pay.get("payment_date",""),
                f"{pay.get('sender_name','')} ({pay.get('sender_account','')})"[:25],
                f"{pay.get('receiver_name','')} ({pay.get('receiver_account','')})"[:25],
                f"${pay.get('amount',0):,.2f} {pay.get('currency','USD')}",
                (pay.get("linked_crypto_address","") or "")[:20],
            ])
        cw = [0.75,0.75,0.65,1.35,1.35,0.95,0.9]
        elems.append(_std_table(pay_rows, [w*inch for w in cw]))

        # Investigator notes per payment
        notes_present = [(p.get("_case_id"),p.get("notes")) for p in all_payments if p.get("notes")]
        if notes_present:
            elems.append(Spacer(1, 6))
            elems += _subsection("Payment Investigator Notes", styles)
            for cid, note in notes_present[:20]:
                elems.append(Paragraph(f"[{cid}] {note}", styles["body"]))
                elems.append(Spacer(1, 2))

        # Payment descriptions
        descs = [(p.get("_case_id"),p.get("platform"),p.get("description"))
                 for p in all_payments if p.get("description")]
        if descs:
            elems.append(Spacer(1, 6))
            elems += _subsection("Payment Descriptions / Memos", styles)
            for cid, plat, desc in descs[:20]:
                elems.append(Paragraph(f"[{cid} · {plat}] {desc}", styles["small"]))

        # Screenshots embedded in PDF
        screenshots = [(p.get("_case_id"), p.get("platform"),
                        p.get("screenshot"), p.get("screenshot_name",""),
                        p.get("screenshot_type",""))
                       for p in all_payments
                       if p.get("screenshot") and str(p.get("screenshot_type","")).startswith("image/")]
        if screenshots:
            elems.append(Spacer(1, 8))
            elems += _subsection(f"Payment Screenshots ({len(screenshots)} attached)", styles)
            try:
                import base64 as _b64
                from reportlab.platypus import Image as RLImage
                for cid, plat, b64data, fname, ftype in screenshots[:10]:
                    try:
                        img_bytes = _b64.b64decode(b64data.encode())
                        img_io    = io.BytesIO(img_bytes)
                        rl_img    = RLImage(img_io, width=5.5*inch, height=3.5*inch, kind="proportional")
                        caption   = Paragraph(f"{plat} screenshot — Case {cid} — {fname}", styles["small"])
                        elems.append(caption)
                        elems.append(rl_img)
                        elems.append(Spacer(1, 8))
                    except Exception as img_err:
                        elems.append(Paragraph(f"⚠️ {fname} — could not embed: {img_err}", styles["small"]))
            except ImportError:
                elems.append(Paragraph("Screenshot embedding requires reportlab.", styles["small"]))

    # ── Attached evidence files ───────────────────────────────
    if all_files:
        elems.append(Spacer(1, 8))
        elems += _subsection(f"Attached Evidence Files ({len(all_files)})", styles)

        # Image evidence embedded
        img_files = [(f.get("_case_id"), f.get("filename",""), f.get("description",""),
                      f.get("data",""), f.get("file_type",""))
                     for f in all_files if str(f.get("file_type","")).startswith("image/")]
        if img_files:
            try:
                import base64 as _b64
                from reportlab.platypus import Image as RLImage
                for cid, fname, desc, b64data, ftype in img_files[:15]:
                    try:
                        img_bytes = _b64.b64decode(b64data.encode())
                        img_io    = io.BytesIO(img_bytes)
                        rl_img    = RLImage(img_io, width=5.5*inch, height=3.5*inch, kind="proportional")
                        caption   = Paragraph(f"Case {cid} — {fname}: {desc}", styles["small"])
                        elems.append(caption)
                        elems.append(rl_img)
                        elems.append(Spacer(1, 8))
                    except Exception as img_err:
                        elems.append(Paragraph(f"⚠️ {fname} — {img_err}", styles["small"]))
            except ImportError:
                pass

        # Non-image file listing
        doc_files = [f for f in all_files if not str(f.get("file_type","")).startswith("image/")]
        if doc_files:
            elems += _subsection("Document Evidence Index", styles)
            doc_rows = [["Case","Filename","Type","Size","Description","Linked Address"]]
            for f in doc_files[:30]:
                size_kb = f.get("size_bytes",0) / 1024
                doc_rows.append([
                    f.get("_case_id","")[:12],
                    f.get("filename","")[:25],
                    f.get("file_type","")[:15],
                    f"{size_kb:.1f} KB",
                    f.get("description","")[:30],
                    (f.get("linked_address","") or "")[:18],
                ])
            cw = [0.75,1.3,0.9,0.55,1.5,1.0]
            elems.append(_std_table(doc_rows, [w*inch for w in cw]))

    return elems


def generate_full_report(
    df: pd.DataFrame,
    case_id: str = "",
    analyst: str = "",
    classification: str = "CONFIDENTIAL",
) -> io.BytesIO:
    """
    Generate a comprehensive investigation PDF covering every analysis module.
    Dynamically includes only sections where data exists in session_state.
    """
    SECTION_NUM[0] = 0   # Reset counter

    buf     = io.BytesIO()
    styles  = _build_styles()
    case_id = case_id or f"CASE-{datetime.now().strftime('%Y%m%d-%H%M')}"
    analyst = analyst or "Crypto Forensics Analyzer"

    doc = BaseDocTemplate(
        buf, pagesize=letter,
        topMargin=0.65*inch, bottomMargin=0.5*inch,
        leftMargin=0.6*inch,  rightMargin=0.6*inch,
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="main")
    template = PageTemplate(id="main", frames=[frame], onPage=_header_footer)
    doc.addPageTemplates([template])

    # ── Collect all elements dynamically ─────────────────────
    all_elems = []
    sections  = []

    # Cover page
    all_elems += _cover_page(case_id, analyst, classification, df, styles)

    # Build body sections (each checks session_state before building)
    body_sections = [
        _section_executive_summary(df, sections, styles),
        _section_dataset(df, sections, styles),
        _section_ofac(sections, styles),
        _section_ransomware(sections, styles),
        _section_honeypot(sections, styles),
        _section_pattern_intel(sections, styles),
        _section_mev(sections, styles),
        _section_osint(sections, styles),
        _section_address_intel(sections, styles),
        _section_velocity(sections, styles),
        _section_tornado(sections, styles),
        _section_atomic_swaps(sections, styles),
        _section_gnn(sections, styles),
        _section_time_series(sections, styles),
        _section_advanced(sections, styles),
        _section_geolocation(sections, styles),
        _section_hop_trace(sections, styles),
        _section_usd(sections, styles),
        _section_travel_rule(sections, styles),
        _section_portfolio(sections, styles),
        _section_l2_chains(sections, styles),
        _section_solana(sections, styles),
        _section_ai(sections, styles),
        _section_sar(sections, styles),
        _section_evidence_log(sections, styles),
        _section_offchain_evidence(sections, styles),
        _section_case_notes(sections, styles),
        _section_certificate(sections, styles),
    ]

    # Insert dynamic TOC after cover (before body)
    toc_elems = _toc(sections, styles)

    all_elems += toc_elems
    for section_elems in body_sections:
        all_elems += section_elems

    doc.build(all_elems)
    buf.seek(0)
    return buf


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_pdf_ui(df: pd.DataFrame):
    """Full PDF report generation UI."""
    st.markdown("### 📄 Complete Investigation PDF Report")
    st.caption(
        "Generates a comprehensive report covering every analysis that was run. "
        "Only sections with actual data are included — empty analyses are skipped automatically."
    )

    # Show what's available
    available = {
        "Basic dataset & risk scoring": True,
        "OFAC SDN screening":           _has("ofac_df"),
        "Ransomware screening":         _has("rw_df"),
        "Honeypot screening":           _has("hp_batch"),
        "Pattern intelligence":         _has("pattern_results"),
        "MEV / market manipulation":    _has("mev_df") or _has("rug_df"),
        "Coordinated dumps":            _has("dump_df"),
        "OSINT (protocols, darknet)":   _has("proto_df") or _has("dark_df"),
        "Dust attacks & flash loans":   _has("dust_df") or _has("flash_df"),
        "Address intelligence":         _has("class_df") or _has("exc_df"),
        "Co-spending clusters":         _has("cio_summary"),
        "Change addresses":             _has("chg_df"),
        "Velocity analysis":            _has("vel_df"),
        "Tornado Cash links":           _has("tc_df"),
        "Atomic swaps":                 _has("swap_df"),
        "Privacy coins":                _has("priv_df"),
        "GNN clusters":                 _has("gnn_df"),
        "Time series ML":               _has("ts_r"),
        "NFT wash trading":             _has("wash_df"),
        "Airdrop farming":              _has("farm_df"),
        "Multi-sig analysis":           bool(st.session_state.get("safe_info",{}).get("is_multisig")),
        "Geolocation":                  bool(st.session_state.get("geo_last_result")),
        "Multi-hop trace":              _has("trace_summary"),
        "Historical USD values":        _has("usd_df"),
        "FATF Travel Rule":             _has("tr_df"),
        "Portfolio balances":           _has("port_df"),
        "Layer 2 chains":               _has("l2_results"),
        "Solana analysis":              _has("sol_df"),
        "AI forensics analysis":        _has("ai_result"),
        "SAR narrative":                _has("sar_narrative"),
        "Evidence audit log":           Path("evidence_audit_log.jsonl").exists(),
        "Case notes & tags":            Path("case_notes.json").exists(),
        "Off-chain payment evidence":   Path("regulatory_cases.json").exists(),
        "EIP-712 certificate":          _has("certificate"),
    }

    st.markdown("**Sections that will be included:**")
    cols = st.columns(3)
    items = list(available.items())
    per_col = len(items) // 3 + 1
    for i, (name, avail) in enumerate(items):
        cols[i // per_col].markdown(
            f"{'✅' if avail else '⬜'} {name}"
        )

    included = sum(1 for v in available.values() if v)
    st.info(f"**{included} of {len(available)}** sections will be included in the report.")

    st.divider()

    c1, c2, c3 = st.columns(3)
    case_id_input  = c1.text_input("Case ID",
        value=st.session_state.get("sar_meta",{}).get("case_id", f"CASE-{datetime.now().strftime('%Y%m%d')}"),
        key="pdf_case_id")
    analyst_input  = c2.text_input("Analyst Name", key="pdf_analyst")
    classification = c3.selectbox("Classification",
        ["CONFIDENTIAL","RESTRICTED","UNCLASSIFIED","TOP SECRET"], key="pdf_class")

    if st.button("📄 Generate Complete Investigation Report", type="primary", key="gen_full_pdf"):
        with st.spinner(f"Building comprehensive report — {included} sections…"):
            try:
                pdf_buf = generate_full_report(
                    df=df,
                    case_id=case_id_input,
                    analyst=analyst_input,
                    classification=classification,
                )
                fname = f"investigation_{case_id_input}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
                st.download_button(
                    label="📥 Download Complete Investigation Report",
                    data=pdf_buf.getvalue(),
                    file_name=fname,
                    mime="application/pdf",
                    type="primary",
                )
                st.success(f"✅ Report ready: {fname} — {included} sections included")
            except Exception as e:
                st.error(f"Report generation failed: {e}")
                import traceback
                st.code(traceback.format_exc())

    st.caption(
        "Tip: Run all analysis modules (OFAC, pattern detection, AI analysis, etc.) "
        "before generating the report to maximize coverage."
    )
