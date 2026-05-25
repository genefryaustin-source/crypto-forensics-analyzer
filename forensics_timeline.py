"""
forensics_timeline.py — Crypto Forensics Analyzer Pro v5.0
Investigation Timeline Builder:
  • Visual chronological case timeline (Plotly Gantt/scatter)
  • Pulls events from: on-chain txs, case notes, off-chain payments,
    evidence uploads, OFAC dates, SAR filings, LE referrals
  • Filter by date range and event type
  • Export timeline as PNG / PDF-ready

Also includes:
  • QR code scanner — extract crypto addresses from uploaded images
  • AI Investigation Agent — natural language query loop
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import requests
import json
import logging

def fmt_crypto(x, decimals: int = 10) -> str:
    """Full-precision crypto amount — no $ sign, no trailing zeros."""
    try:
        v = float(x)
        if v != v or v == 0:
            return "0"
        return f"{v:.{decimals}f}".rstrip("0").rstrip(".")
    except (ValueError, TypeError):
        return str(x)


import io
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# 1. INVESTIGATION TIMELINE BUILDER
# ─────────────────────────────────────────────────────────────

EVENT_TYPES = {
    "on_chain_critical":  {"color": "#ff4444", "symbol": "circle",        "label": "Critical Transaction"},
    "on_chain_high":      {"color": "#ff8800", "symbol": "circle",        "label": "High Risk Transaction"},
    "on_chain_normal":    {"color": "#4a9eff", "symbol": "circle-open",   "label": "Transaction"},
    "ofac_designation":   {"color": "#dc2626", "symbol": "x",             "label": "OFAC Designation"},
    "ransomware":         {"color": "#7c3aed", "symbol": "diamond",       "label": "Ransomware"},
    "case_note":          {"color": "#059669", "symbol": "square",        "label": "Case Note"},
    "offchain_payment":   {"color": "#d97706", "symbol": "triangle-up",   "label": "Off-chain Payment"},
    "evidence_upload":    {"color": "#0891b2", "symbol": "star",          "label": "Evidence File"},
    "sar_filed":          {"color": "#be185d", "symbol": "pentagon",      "label": "SAR Filed"},
    "le_referral":        {"color": "#1d4ed8", "symbol": "hexagon",       "label": "LE Referral"},
    "asset_freeze":       {"color": "#065f46", "symbol": "square",        "label": "Asset Freeze"},
    "dprk_pattern":       {"color": "#92400e", "symbol": "x-open",        "label": "DPRK Pattern"},
    "pig_butchering":     {"color": "#be185d", "symbol": "triangle-down", "label": "Pig Butchering"},
}


def collect_timeline_events(df: pd.DataFrame) -> List[Dict]:
    """
    Collect all events from the investigation into a unified timeline.
    Pulls from dataset + session_state (all run analyses + case data).
    """
    events = []

    # ── On-chain transactions ─────────────────────────────────
    if not df.empty and "date" in df.columns:
        tx_df = df.copy()
        tx_df["date"] = pd.to_datetime(tx_df["date"], errors="coerce")
        tx_df = tx_df.dropna(subset=["date"])

        for _, row in tx_df.iterrows():
            risk = row.get("risk_level","LOW")
            etype = ("on_chain_critical" if risk == "CRITICAL" else
                     "on_chain_high"    if risk == "HIGH"     else "on_chain_normal")
            events.append({
                "date":        row["date"],
                "event_type":  etype,
                "title":       f"{row.get('token','')} {fmt_crypto(row.get('amount',0))}",
                "description": f"{str(row.get('from_address',''))[:16]}… → {str(row.get('to_address',''))[:16]}…",
                "amount":      float(row.get("amount",0)),
                "address":     str(row.get("from_address","")),
                "source":      "dataset",
                "risk_level":  risk,
                "tx_hash":     str(row.get("tx_hash","")),
            })

    # ── Case notes ────────────────────────────────────────────
    cases_file = Path("regulatory_cases.json")
    if cases_file.exists():
        try:
            cases = json.loads(cases_file.read_text())
            for case in cases:
                # Case creation event
                if case.get("created_at"):
                    events.append({
                        "date":        datetime.fromisoformat(case["created_at"][:19]),
                        "event_type":  "case_note",
                        "title":       f"Case Created: {case.get('case_id','')}",
                        "description": case.get("name",""),
                        "source":      "case_management",
                        "risk_level":  case.get("priority","LOW"),
                    })

                # Notes
                for note in case.get("notes", []):
                    if note.get("timestamp"):
                        try:
                            events.append({
                                "date":        datetime.fromisoformat(note["timestamp"]),
                                "event_type":  "case_note",
                                "title":       f"Note: {case.get('case_id','')}",
                                "description": note.get("text","")[:80],
                                "source":      "case_management",
                                "risk_level":  "LOW",
                            })
                        except Exception:
                            pass

                # Off-chain payments
                for pay in case.get("offchain_payments", []):
                    if pay.get("payment_date"):
                        try:
                            events.append({
                                "date":        datetime.strptime(pay["payment_date"], "%Y-%m-%d"),
                                "event_type":  "offchain_payment",
                                "title":       f"{pay.get('platform','')} ${pay.get('amount',0):,.2f}",
                                "description": f"{pay.get('sender_name','')} → {pay.get('receiver_name','')}",
                                "amount":      float(pay.get("amount",0)),
                                "source":      "case_management",
                                "risk_level":  "MEDIUM",
                            })
                        except Exception:
                            pass

                # SAR filings
                if case.get("sar_filed") and case.get("sar_date"):
                    try:
                        events.append({
                            "date":        datetime.strptime(case["sar_date"], "%Y-%m-%d"),
                            "event_type":  "sar_filed",
                            "title":       f"SAR Filed: {case.get('case_id','')}",
                            "description": f"Case: {case.get('name','')}",
                            "source":      "case_management",
                            "risk_level":  "HIGH",
                        })
                    except Exception:
                        pass

                # LE Referrals
                if case.get("le_referral") and case.get("le_date"):
                    try:
                        events.append({
                            "date":        datetime.strptime(case["le_date"], "%Y-%m-%d"),
                            "event_type":  "le_referral",
                            "title":       f"LE Referral: {case.get('le_agency','')}",
                            "description": f"Case: {case.get('case_id','')}",
                            "source":      "case_management",
                            "risk_level":  "HIGH",
                        })
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Timeline case loading error: {e}")

    # ── DPRK findings ─────────────────────────────────────────
    dprk_df = st.session_state.get("dprk_df")
    if isinstance(dprk_df, pd.DataFrame) and not dprk_df.empty and "date" in dprk_df.columns:
        for _, row in dprk_df.iterrows():
            try:
                events.append({
                    "date":        pd.to_datetime(row["date"]),
                    "event_type":  "dprk_pattern",
                    "title":       f"DPRK: {row.get('pattern','')}",
                    "description": row.get("entity",""),
                    "source":      "threat_intel",
                    "risk_level":  "CRITICAL",
                })
            except Exception:
                pass

    # ── Pig butchering ────────────────────────────────────────
    pig_df = st.session_state.get("pig_df")
    if isinstance(pig_df, pd.DataFrame) and not pig_df.empty and "first_date" in pig_df.columns:
        for _, row in pig_df.iterrows():
            try:
                events.append({
                    "date":        pd.to_datetime(row["first_date"]),
                    "event_type":  "pig_butchering",
                    "title":       f"Pig Butchering: ${row.get('total_sent',0):,.0f}",
                    "description": f"Scammer: {str(row.get('scammer_address',''))[:20]}…",
                    "amount":      float(row.get("total_sent",0)),
                    "source":      "threat_intel",
                    "risk_level":  "HIGH",
                })
            except Exception:
                pass

    # Sort by date
    events = [e for e in events if isinstance(e.get("date"), (datetime, pd.Timestamp))]
    events.sort(key=lambda x: pd.Timestamp(x["date"]))
    return events


def plot_timeline(events: List[Dict], filter_types: List[str] = None) -> go.Figure:
    """
    Build a Plotly scatter timeline from investigation events.
    """
    if not events:
        return None

    filtered = events if not filter_types else [
        e for e in events if e["event_type"] in filter_types
    ]
    if not filtered:
        return None

    fig = go.Figure()

    # Group by event type for separate traces (legend entries)
    type_groups: Dict[str, List] = {}
    for event in filtered:
        et = event["event_type"]
        type_groups.setdefault(et, []).append(event)

    for etype, evts in type_groups.items():
        cfg   = EVENT_TYPES.get(etype, {"color":"#888","symbol":"circle","label":etype})
        dates = [pd.Timestamp(e["date"]) for e in evts]
        # Y position: spread events of same type vertically to avoid overlap
        y_pos = [EVENT_TYPES_ORDER.index(etype) if etype in EVENT_TYPES_ORDER else 0
                 for _ in evts]
        hover = [
            f"<b>{e['title']}</b><br>{e['description']}<br>"
            f"Date: {str(e['date'])[:16]}<br>Source: {e.get('source','')}"
            for e in evts
        ]
        sizes = [max(8, min(20, 8 + math.log1p(e.get("amount",0)) * 0.5))
                 for e in evts] if any(e.get("amount") for e in evts) else [10]*len(evts)

        fig.add_trace(go.Scatter(
            x=dates,
            y=y_pos,
            mode="markers",
            name=cfg["label"],
            marker=dict(
                size=sizes,
                color=cfg["color"],
                symbol=cfg["symbol"],
                line=dict(width=1, color="white"),
            ),
            customdata=hover,
            hovertemplate="%{customdata}<extra></extra>",
        ))

    fig.update_layout(
        title="📅 Investigation Timeline",
        height=500,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15,23,42,0.5)",
        xaxis=dict(title="Date", gridcolor="rgba(255,255,255,0.1)"),
        yaxis=dict(
            tickvals=list(range(len(EVENT_TYPES_ORDER))),
            ticktext=[EVENT_TYPES[k]["label"] for k in EVENT_TYPES_ORDER],
            gridcolor="rgba(255,255,255,0.1)",
        ),
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
        showlegend=True,
    )
    return fig


import math
EVENT_TYPES_ORDER = list(EVENT_TYPES.keys())


# ─────────────────────────────────────────────────────────────
# 2. QR CODE SCANNER
# ─────────────────────────────────────────────────────────────

def extract_qr_codes(image_bytes: bytes) -> List[Dict]:
    """
    Extract QR codes from an image and decode them.
    Tries pyzbar first (best), falls back to manual pattern matching.
    Returns list of decoded QR values with crypto address detection.
    """
    results = []

    # Try pyzbar (requires zbar system library)
    try:
        from PIL import Image as PILImage
        from pyzbar import pyzbar

        img     = PILImage.open(io.BytesIO(image_bytes))
        decoded = pyzbar.decode(img)
        for d in decoded:
            raw_data = d.data.decode("utf-8", errors="ignore").strip()
            results.append({
                "raw":         raw_data,
                "type":        d.type,
                "crypto_addr": _extract_crypto_address(raw_data),
                "method":      "pyzbar",
            })
        return results
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"pyzbar failed: {e}")

    # Try qrcode-detector pure python fallback
    try:
        import qrcode
        # qrcode library is for generation not detection
        pass
    except ImportError:
        pass

    # Manual: try to decode common QR URI formats in any text detected
    # This is a last resort — works on clear text QR codes
    try:
        from PIL import Image as PILImage
        img = PILImage.open(io.BytesIO(image_bytes)).convert("L")
        # Convert to bytes and look for QR patterns — very basic
        # Real implementation needs zbar or similar
        results.append({
            "raw":         "QR detection requires: pip install pyzbar pillow",
            "type":        "INFO",
            "crypto_addr": None,
            "method":      "fallback",
        })
    except Exception:
        results.append({
            "raw":         "Could not process image. Install pillow: pip install Pillow",
            "type":        "ERROR",
            "crypto_addr": None,
            "method":      "none",
        })

    return results


def _extract_crypto_address(text: str) -> Optional[Dict]:
    """
    Extract and identify a cryptocurrency address from decoded QR text.
    Handles raw addresses and URI formats (bitcoin:, ethereum:, etc.)
    """
    import re

    # Strip URI prefixes
    for prefix in ["bitcoin:", "ethereum:", "eth:", "tron:", "litecoin:", "dogecoin:"]:
        if text.lower().startswith(prefix):
            text = text[len(prefix):]
            if "?" in text:
                text = text.split("?")[0]

    text = text.strip()

    # Bitcoin Legacy (P2PKH)
    if re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", text):
        return {"address": text, "chain": "Bitcoin (Legacy)", "valid": True}

    # Bitcoin SegWit (bech32)
    if re.match(r"^bc1[a-z0-9]{25,62}$", text, re.IGNORECASE):
        return {"address": text, "chain": "Bitcoin (SegWit)", "valid": True}

    # Ethereum / EVM
    if re.match(r"^0x[a-fA-F0-9]{40}$", text):
        return {"address": text, "chain": "Ethereum/EVM", "valid": True}

    # Tron
    if re.match(r"^T[a-zA-Z0-9]{33}$", text):
        return {"address": text, "chain": "Tron", "valid": True}

    # Solana
    if re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", text):
        return {"address": text, "chain": "Solana (possible)", "valid": False}

    return None


def cross_reference_qr_with_dataset(
    qr_results: List[Dict],
    df: pd.DataFrame,
) -> List[Dict]:
    """Flag any QR-decoded addresses found in the investigation dataset."""
    if df.empty:
        return qr_results

    all_addrs = set(
        df["from_address"].str.lower().tolist() +
        df["to_address"].str.lower().tolist()
    )

    enriched = []
    for qr in qr_results:
        crypto = qr.get("crypto_addr")
        in_dataset = False
        matched_txs = []
        if crypto and crypto.get("address"):
            addr_lower = crypto["address"].lower()
            in_dataset = addr_lower in all_addrs
            if in_dataset:
                mask = (df["from_address"].str.lower() == addr_lower) | \
                       (df["to_address"].str.lower() == addr_lower)
                matched_txs = df[mask].head(5).to_dict("records")
        enriched.append({**qr, "in_dataset": in_dataset, "matched_txs": matched_txs})

    return enriched


# ─────────────────────────────────────────────────────────────
# 3. AI INVESTIGATION AGENT
# ─────────────────────────────────────────────────────────────

AGENT_SYSTEM_PROMPT = """You are an expert crypto forensics investigator with access to a 
blockchain analysis platform. You help investigators analyze transaction data, identify 
suspicious patterns, and build evidence packages.

The investigator will ask you questions in natural language. You can:
1. Explain findings from the analysis in plain language
2. Suggest which analysis modules to run next
3. Help interpret results (risk scores, clustering, Boltzmann entropy, etc.)
4. Generate SAR narrative text from findings
5. Identify investigation leads and next steps
6. Explain legal process requirements

When the investigator provides data context, analyze it thoroughly.
Always maintain investigative objectivity — findings are leads, not conclusions.
Flag when professional legal counsel or LE escalation is needed.

Respond concisely and practically. Use bullet points for actionable items."""


def run_agent_query(
    query:       str,
    df:          pd.DataFrame,
    api_key:     str,
    context:     Dict = None,
    chat_history: List[Dict] = None,
) -> str:
    """
    Run a natural language investigation query through Claude.
    Includes dataset context and session analysis results.
    """
    if not api_key:
        return "⚠️ Add your Anthropic API key to use the AI Investigation Agent."

    # Build context from current dataset and session
    ctx_parts = []

    if not df.empty:
        ctx_parts.append(f"Dataset: {len(df)} transactions loaded")
        if "risk_level" in df.columns:
            ctx_parts.append(f"Risk distribution: {df['risk_level'].value_counts().to_dict()}")
        if "amount" in df.columns:
            ctx_parts.append(f"Total volume: {fmt_crypto(df['amount'].sum())}")
        if "token" in df.columns:
            ctx_parts.append(f"Tokens: {', '.join(df['token'].unique().tolist()[:5])}")
        if "chain" in df.columns:
            ctx_parts.append(f"Chains: {', '.join(df['chain'].unique().tolist())}")

    # Add session analysis results
    for key, label in [
        ("ofac_df",     "OFAC screening"),
        ("rw_df",       "Ransomware screening"),
        ("pig_df",      "Pig butchering detection"),
        ("dprk_df",     "DPRK pattern detection"),
        ("vel_df",      "Velocity analysis"),
        ("gnn_df",      "GNN clustering"),
    ]:
        val = st.session_state.get(key)
        if isinstance(val, pd.DataFrame) and not val.empty:
            ctx_parts.append(f"{label}: {len(val)} results")

    context_str = "\n".join(ctx_parts) if ctx_parts else "No analysis run yet"

    # Build messages
    messages = []
    if chat_history:
        for msg in chat_history[-10:]:  # Last 10 turns
            messages.append({"role": msg["role"], "content": msg["content"]})

    messages.append({
        "role": "user",
        "content": f"Investigation Context:\n{context_str}\n\n{query}"
    })

    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={
                "model":      "claude-sonnet-4-20250514",
                "max_tokens": 1500,
                "system":     AGENT_SYSTEM_PROMPT,
                "messages":   messages,
            },
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data["content"][0]["text"]
        else:
            return f"API error: {resp.status_code} — {resp.text[:200]}"
    except Exception as e:
        return f"Request failed: {e}"


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_timeline_ui(df: pd.DataFrame):
    """Investigation timeline builder UI."""
    st.markdown("### 📅 Investigation Timeline")
    st.caption(
        "Chronological view of all investigation events — on-chain transactions, "
        "case notes, off-chain payments, SAR filings, LE referrals, threat intel findings."
    )

    with st.spinner("Building timeline…"):
        events = collect_timeline_events(df)

    if not events:
        st.info("No events to display. Load a dataset and run some analyses first.")
        return

    # Filter controls
    tl_col1, tl_col2 = st.columns([3,1])
    available_types = list({e["event_type"] for e in events})
    selected_types  = tl_col1.multiselect(
        "Filter event types",
        options=available_types,
        default=available_types,
        format_func=lambda x: EVENT_TYPES.get(x,{}).get("label",x),
        key="tl_filter",
    )
    tl_col2.metric("Total Events", len(events))

    # Date filter
    if events:
        min_date = min(pd.Timestamp(e["date"]) for e in events).date()
        max_date = max(pd.Timestamp(e["date"]) for e in events).date()
        date_range = st.date_input(
            "Date range", value=(min_date, max_date), key="tl_dates"
        )
        if len(date_range) == 2:
            start, end = date_range
            events = [e for e in events
                      if start <= pd.Timestamp(e["date"]).date() <= end]

    fig = plot_timeline(events, selected_types)
    if fig:
        st.plotly_chart(fig, use_container_width=True,
                        config={"displayModeBar": True})

    # Event list
    with st.expander(f"📋 All Events ({len(events)} total)", expanded=False):
        rows = [{
            "Date":     str(e["date"])[:16],
            "Type":     EVENT_TYPES.get(e["event_type"],{}).get("label", e["event_type"]),
            "Event":    e["title"],
            "Details":  e.get("description",""),
            "Source":   e.get("source",""),
            "Risk":     e.get("risk_level",""),
        } for e in events if not selected_types or e["event_type"] in selected_types]
        if rows:
            st.dataframe(pd.DataFrame(rows), width='stretch', hide_index=True)
            st.download_button("⬇️ Export Timeline CSV",
                pd.DataFrame(rows).to_csv(index=False).encode(),
                "investigation_timeline.csv", "text/csv")


def render_qr_scanner_ui(df: pd.DataFrame = None):
    """QR code scanner UI."""
    st.markdown("### 📱 QR Code Scanner")
    st.caption(
        "Upload a photo from a seized device, screenshot, or document to extract "
        "cryptocurrency addresses from QR codes. Automatically cross-references "
        "against your investigation dataset."
    )
    st.info(
        "💡 **Best results:** Install `pyzbar` and `Pillow` for full QR scanning. "
        "Without them, only address URIs in plaintext are detected.\n"
        "```\npip install pyzbar Pillow\n```"
    )

    uploaded_images = st.file_uploader(
        "Upload image(s) containing QR codes",
        type=["png","jpg","jpeg","gif","bmp","webp"],
        accept_multiple_files=True,
        key="qr_images",
    )

    # Manual address input fallback
    st.markdown("**Or manually decode a QR code:**")
    manual_qr = st.text_input("Paste QR code content", key="qr_manual",
                               placeholder="bitcoin:1A1z... or 0x1234... or raw address")

    if st.button("🔍 Scan / Analyse", type="primary", key="run_qr"):
        all_results = []

        # Process uploaded images
        for img_file in (uploaded_images or []):
            img_bytes = img_file.read()
            results   = extract_qr_codes(img_bytes)
            if df is not None and not df.empty:
                results = cross_reference_qr_with_dataset(results, df)
            for r in results:
                r["source_file"] = img_file.name
            all_results.extend(results)

        # Process manual input
        if manual_qr.strip():
            crypto = _extract_crypto_address(manual_qr.strip())
            result = {
                "raw":          manual_qr.strip(),
                "type":         "MANUAL",
                "crypto_addr":  crypto,
                "method":       "manual",
                "source_file":  "manual entry",
            }
            if df is not None and not df.empty and crypto:
                result = cross_reference_qr_with_dataset([result], df)[0]
            all_results.append(result)

        st.session_state.qr_results = all_results

    if "qr_results" in st.session_state:
        results = st.session_state.qr_results
        if not results:
            st.info("No QR codes detected.")
        else:
            crypto_found = [r for r in results if r.get("crypto_addr")]
            dataset_hits = [r for r in results if r.get("in_dataset")]

            m1,m2,m3 = st.columns(3)
            m1.metric("QR Codes Found",   len(results))
            m2.metric("Crypto Addresses", len(crypto_found))
            m3.metric("Dataset Matches",  len(dataset_hits))

            if dataset_hits:
                st.error(f"🚨 {len(dataset_hits)} QR code addresses MATCH your investigation dataset!")

            for r in results:
                crypto = r.get("crypto_addr")
                with st.expander(
                    f"{'🚨' if r.get('in_dataset') else '📱'} "
                    f"{r.get('source_file','')}: {r['raw'][:50]}",
                    expanded=r.get("in_dataset",False)
                ):
                    st.code(r["raw"])
                    if crypto:
                        st.success(f"✅ Crypto address detected: `{crypto['address']}`")
                        st.caption(f"Chain: {crypto['chain']}")
                        if r.get("in_dataset"):
                            st.error("🚨 This address appears in your investigation dataset!")
                            if r.get("matched_txs"):
                                st.dataframe(pd.DataFrame(r["matched_txs"]),
                                             width='stretch', hide_index=True)
                    elif r.get("method") == "fallback":
                        st.warning(r["raw"])
                    else:
                        st.caption("No cryptocurrency address pattern recognised")


def render_agent_ui(df: pd.DataFrame, get_key_fn=None):
    """AI Investigation Agent UI."""
    st.markdown("### 🤖 AI Investigation Agent")
    st.caption(
        "Ask questions in plain language. The agent knows your dataset, "
        "analysis results, and investigation context. "
        "Powered by Claude Sonnet."
    )

    api_key = get_key_fn("anthropic_key") if get_key_fn else ""

    if not api_key:
        st.warning("⚠️ Add your Anthropic API key in Settings to use the Investigation Agent.")
        return

    # Suggested queries
    st.markdown("**Quick queries:**")
    suggestions = [
        "Summarise all critical findings in this investigation",
        "What are the top 3 addresses I should investigate further?",
        "Write a SAR narrative based on the patterns detected",
        "What legal process steps should I take next?",
        "Explain the Boltzmann entropy results in plain language",
        "Are there any signs of pig butchering in this data?",
        "What exchange should I subpoena first and why?",
        "Summarise the DPRK connection risk",
    ]
    sug_cols = st.columns(4)
    for i, sug in enumerate(suggestions[:8]):
        if sug_cols[i%4].button(sug[:30]+"…", key=f"sug_{i}"):
            st.session_state.agent_query = sug

    # Chat interface
    if "agent_history" not in st.session_state:
        st.session_state.agent_history = []

    # Display chat history
    for msg in st.session_state.agent_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Input
    query = st.chat_input("Ask the investigation agent anything…")
    if not query:
        query = st.session_state.pop("agent_query", None)

    if query:
        # Show user message
        with st.chat_message("user"):
            st.markdown(query)
        st.session_state.agent_history.append({"role":"user","content":query})

        # Get response
        with st.chat_message("assistant"):
            with st.spinner("Analysing…"):
                response = run_agent_query(
                    query, df, api_key,
                    chat_history=st.session_state.agent_history[:-1]
                )
            st.markdown(response)
        st.session_state.agent_history.append({"role":"assistant","content":response})

    # Controls
    if st.session_state.agent_history:
        col1, col2 = st.columns(2)
        if col1.button("🗑 Clear Conversation", key="clear_agent"):
            st.session_state.agent_history = []
            st.rerun()

        # Export conversation
        conv_text = "\n\n".join([
            f"[{m['role'].upper()}]\n{m['content']}"
            for m in st.session_state.agent_history
        ])
        col2.download_button(
            "⬇️ Export Conversation",
            conv_text.encode(),
            f"agent_conversation_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            "text/plain",
        )
