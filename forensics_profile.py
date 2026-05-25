"""
forensics_profile.py — Crypto Forensics Analyzer Pro v5.0
360° Suspect Profile:
  Aggregates ALL intelligence on a single address/entity into
  one comprehensive, court-ready profile page.
  Covers: identity, on-chain history, sanctions, threat intel,
  counterparty analysis, risk scoring, legal process guidance.
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import requests
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# DATA COLLECTION — pull from session_state and live APIs
# ─────────────────────────────────────────────────────────────

def _safe_get(key: str, default=None):
    """Safe session_state accessor."""
    val = st.session_state.get(key, default)
    if isinstance(val, pd.DataFrame) and val.empty:
        return default
    return val


def collect_address_profile(
    address:    str,
    df:         pd.DataFrame,
    api_key:    str = "",
    chain:      str = "ethereum",
) -> Dict:
    """
    Aggregate all available intelligence on a single address.
    Pulls from session_state (already-run analyses) and live APIs.
    """
    addr_lower = address.lower()
    profile    = {
        "address":           address,
        "chain":             chain,
        "generated_at":      datetime.now().isoformat(),
        "sections":          {},
        "overall_risk_score": 0,
        "risk_level":        "LOW",
        "flags":             [],
    }

    score = 0

    # ── 1. On-chain Activity from Dataset ────────────────────
    sent_txs = df[df["from_address"].str.lower() == addr_lower]
    recv_txs = df[df["to_address"].str.lower() == addr_lower]
    all_txs  = pd.concat([sent_txs, recv_txs])

    if not df.empty:
        profile["sections"]["on_chain"] = {
            "total_transactions":  len(all_txs),
            "transactions_sent":   len(sent_txs),
            "transactions_received": len(recv_txs),
            "total_sent":          float(sent_txs["amount"].sum()) if not sent_txs.empty else 0,
            "total_received":      float(recv_txs["amount"].sum()) if not recv_txs.empty else 0,
            "unique_counterparties": int(pd.concat([
                sent_txs["to_address"], recv_txs["from_address"]
            ]).nunique()) if not all_txs.empty else 0,
            "tokens_used":         all_txs["token"].unique().tolist() if not all_txs.empty else [],
            "first_seen":          str(all_txs["date"].min())[:10] if "date" in all_txs.columns and not all_txs.empty else "Unknown",
            "last_seen":           str(all_txs["date"].max())[:10] if "date" in all_txs.columns and not all_txs.empty else "Unknown",
            "risk_levels":         all_txs["risk_level"].value_counts().to_dict() if "risk_level" in all_txs.columns else {},
        }
        critical_txs = int((all_txs.get("risk_level","") == "CRITICAL").sum()) if "risk_level" in all_txs.columns else 0
        score += min(40, critical_txs * 10)

    # ── 2. OFAC Screening ────────────────────────────────────
    ofac_df = _safe_get("ofac_df")
    if isinstance(ofac_df, pd.DataFrame) and not ofac_df.empty and "ofac_hit" in ofac_df.columns:
        addr_ofac = ofac_df[
            (ofac_df["from_address"].str.lower() == addr_lower) |
            (ofac_df["to_address"].str.lower() == addr_lower)
        ]
        ofac_hit = addr_ofac["ofac_hit"].any() if not addr_ofac.empty else False
        profile["sections"]["ofac"] = {
            "screened": True,
            "hit":      bool(ofac_hit),
            "entity":   addr_ofac["ofac_entity"].iloc[0] if ofac_hit and not addr_ofac.empty else "",
        }
        if ofac_hit:
            score += 100
            profile["flags"].append("🚨 OFAC SDN MATCH — SANCTIONED ENTITY")

    # ── 3. Ransomware Screening ───────────────────────────────
    rw_df = _safe_get("rw_df")
    if isinstance(rw_df, pd.DataFrame) and not rw_df.empty and "ransomware_hit" in rw_df.columns:
        addr_rw = rw_df[
            (rw_df["from_address"].str.lower() == addr_lower) |
            (rw_df["to_address"].str.lower() == addr_lower)
        ]
        rw_hit = addr_rw["ransomware_hit"].any() if not addr_rw.empty else False
        profile["sections"]["ransomware"] = {
            "screened": True,
            "hit":      bool(rw_hit),
            "family":   addr_rw["ransomware_family"].iloc[0] if rw_hit and not addr_rw.empty else "",
            "paid":     float(addr_rw["ransomware_paid"].iloc[0]) if rw_hit and not addr_rw.empty else 0,
            "source":   addr_rw.get("ransomware_source","").iloc[0] if rw_hit and not addr_rw.empty else "",
        }
        if rw_hit:
            score += 95
            fam = profile["sections"]["ransomware"]["family"]
            profile["flags"].append(f"☠️ RANSOMWARE ADDRESS — {fam}")

    # ── 4. GoPlus / Intel Screening ──────────────────────────
    intel_df = _safe_get("intel_df")
    if isinstance(intel_df, pd.DataFrame) and not intel_df.empty and "intel_hit" in intel_df.columns:
        addr_intel = intel_df[
            (intel_df["from_address"].str.lower() == addr_lower) |
            (intel_df["to_address"].str.lower() == addr_lower)
        ]
        intel_hit = addr_intel["intel_hit"].any() if not addr_intel.empty else False
        profile["sections"]["intel"] = {
            "screened":     True,
            "hit":          bool(intel_hit),
            "goplus_flags": addr_intel["goplus_labels"].iloc[0] if intel_hit and not addr_intel.empty else "",
            "usdc_frozen":  bool(addr_intel["usdc_frozen"].any()) if "usdc_frozen" in addr_intel else False,
            "usdt_frozen":  bool(addr_intel["usdt_frozen"].any()) if "usdt_frozen" in addr_intel else False,
            "sources":      addr_intel["intel_sources"].iloc[0] if intel_hit and not addr_intel.empty else "",
        }
        if intel_hit:
            score += 50
            profile["flags"].append(f"🔍 Intelligence hit: {profile['sections']['intel']['sources']}")

    # ── 5. Address Classification ─────────────────────────────
    class_df = _safe_get("class_df")
    if isinstance(class_df, pd.DataFrame) and not class_df.empty:
        addr_class = class_df[class_df["address"].str.lower() == addr_lower]
        if not addr_class.empty:
            profile["sections"]["classification"] = {
                "type":        addr_class["type"].iloc[0],
                "label":       addr_class["label"].iloc[0],
                "confidence":  int(addr_class["confidence"].iloc[0]),
                "tx_count":    int(addr_class.get("tx_count", pd.Series([0])).iloc[0]),
                "out_volume":  float(addr_class.get("out_volume", pd.Series([0])).iloc[0]),
            }

    # ── 6. Exchange Endpoints ─────────────────────────────────
    exc_df = _safe_get("exc_df")
    if isinstance(exc_df, pd.DataFrame) and not exc_df.empty and "exchange_endpoint" in exc_df.columns:
        addr_exc = exc_df[
            (exc_df["from_address"].str.lower() == addr_lower) |
            (exc_df["to_address"].str.lower() == addr_lower)
        ]
        if not addr_exc.empty and "exchange_name" in addr_exc.columns:
            exchanges = addr_exc["exchange_name"].dropna().unique().tolist()
            profile["sections"]["exchange_endpoints"] = {
                "exchanges": exchanges,
                "tx_count":  len(addr_exc),
                "note":      "Funds reached exchange — serve legal process to obtain KYC identity",
            }
            if exchanges:
                profile["flags"].append(f"🏦 Funds reached exchange: {', '.join(exchanges)}")

    # ── 7. Top Counterparties ─────────────────────────────────
    if not all_txs.empty:
        top_sent = sent_txs.groupby("to_address")["amount"].sum().nlargest(5).to_dict()
        top_recv = recv_txs.groupby("from_address")["amount"].sum().nlargest(5).to_dict()
        profile["sections"]["counterparties"] = {
            "top_sent_to":      top_sent,
            "top_received_from": top_recv,
        }

    # ── 8. Live Balance (Etherscan) ───────────────────────────
    if api_key and chain in ("ethereum","bsc","polygon"):
        chain_ids = {"ethereum":1,"bsc":56,"polygon":137}
        try:
            resp = requests.get(
                "https://api.etherscan.io/v2/api",
                params={"chainid":chain_ids[chain],"module":"account",
                        "action":"balance","address":address,
                        "tag":"latest","apikey":api_key},
                timeout=8,
            ).json()
            if resp.get("status") == "1":
                balance = int(resp["result"]) / 1e18
                profile["sections"]["live_balance"] = {
                    "balance": balance,
                    "chain":   chain,
                    "note":    "Current on-chain balance — use for asset freeze application",
                }
                if balance > 0:
                    profile["flags"].append(f"💰 Active balance: {balance:.4f} (seizure opportunity)")
        except Exception:
            pass

    # ── 9. Pig Butchering / Scam Patterns ─────────────────────
    pig_df = _safe_get("pig_df")
    if isinstance(pig_df, pd.DataFrame) and not pig_df.empty:

        victim_series = (
            pig_df["victim_address"]
            if "victim_address" in pig_df.columns
            else pd.Series("", index=pig_df.index)
        )

        scammer_series = (
            pig_df["scammer_address"]
            if "scammer_address" in pig_df.columns
            else pd.Series("", index=pig_df.index)
        )

        addr_pig = pig_df[
            (
                    victim_series
                    .astype(str)
                    .str.lower()
                    == addr_lower
            )
            |
            (
                    scammer_series
                    .astype(str)
                    .str.lower()
                    == addr_lower
            )
            ]

        if not addr_pig.empty:
            score += 70

            profile["flags"].append(
                "🐷 Pig butchering / investment scam pattern"
            )

            profile["sections"]["scam_patterns"] = (
                addr_pig.to_dict("records")
            )

    # ── 10. DPRK / Lazarus ───────────────────────────────────
    dprk_df = _safe_get("dprk_df")
    if isinstance(dprk_df, pd.DataFrame) and not dprk_df.empty:
        addr_dprk = dprk_df[
            (dprk_df["from_address"].str.lower() == addr_lower) |
            (dprk_df["to_address"].str.lower() == addr_lower)
        ]
        if not addr_dprk.empty:
            score += 90
            profile["flags"].append("🇰🇵 DPRK/Lazarus Group connection")
            profile["sections"]["dprk"] = addr_dprk.to_dict("records")

    # ── Overall Risk ──────────────────────────────────────────
    profile["overall_risk_score"] = min(100, score)
    if score >= 85:   profile["risk_level"] = "CRITICAL"
    elif score >= 60: profile["risk_level"] = "HIGH"
    elif score >= 35: profile["risk_level"] = "MEDIUM"
    else:             profile["risk_level"] = "LOW"

    return profile


# ─────────────────────────────────────────────────────────────
# LEGAL PROCESS GUIDANCE
# ─────────────────────────────────────────────────────────────

def generate_legal_guidance(profile: Dict) -> List[Dict]:
    """
    Generate actionable legal process recommendations
    based on the intelligence gathered in the profile.
    """
    actions = []

    sec = profile.get("sections", {})

    if sec.get("ofac", {}).get("hit"):
        actions.append({
            "priority": "IMMEDIATE",
            "action":   "Report OFAC SDN match to compliance officer and legal counsel",
            "authority":"31 CFR Part 501 — mandatory reporting",
            "deadline": "Immediately",
        })

    if sec.get("exchange_endpoints", {}).get("exchanges"):
        for exchange in sec["exchange_endpoints"]["exchanges"]:
            actions.append({
                "priority": "HIGH",
                "action":   f"Serve legal process on {exchange} to obtain KYC identity",
                "authority":"Grand jury subpoena, 18 USC 2703, or equivalent",
                "deadline": "Within 30 days",
            })

    if sec.get("live_balance", {}).get("balance", 0) > 0:
        bal = sec["live_balance"]["balance"]
        actions.append({
            "priority": "HIGH",
            "action":   f"Apply for asset freeze order — {bal:.4f} available for seizure",
            "authority":"Court-ordered freeze via DOJ/FBI or civil forfeiture",
            "deadline": "Before funds are moved",
        })

    if sec.get("ransomware", {}).get("hit"):
        actions.append({
            "priority": "HIGH",
            "action":   "File report with FBI IC3 and CISA — ransomware groups are federal targets",
            "authority":"IC3.gov / CISA Reporting / 18 USC 1030",
            "deadline": "Within 72 hours of discovery",
        })

    on_chain = sec.get("on_chain", {})
    if on_chain.get("total_sent", 0) > 10000:
        actions.append({
            "priority": "MEDIUM",
            "action":   "File Suspicious Activity Report (SAR) with FinCEN",
            "authority":"31 USC 5318(g) — mandatory for financial institutions",
            "deadline": "Within 30 days of detection",
        })

    return actions


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_profile_ui(df: pd.DataFrame, get_key_fn=None):
    """360° suspect profile UI."""
    st.markdown("### 👤 360° Suspect Profile")
    st.caption(
        "Aggregate ALL available intelligence on a single address into one definitive view. "
        "Pulls from every analysis module that has been run in this session."
    )

    api_key = get_key_fn("etherscan_key") if get_key_fn else ""

    p1, p2 = st.columns([3,1])
    profile_addr  = p1.text_input("Address to profile", key="profile_addr",
                                   placeholder="Paste any address from the investigation")
    profile_chain = p2.selectbox("Chain", ["ethereum","bsc","polygon","tron","bitcoin"],
                                  key="profile_chain")

    if st.button("👤 Generate Full Profile", type="primary", key="run_profile"):
        if not profile_addr.strip():
            st.warning("Enter an address first.")
            st.stop()

        with st.spinner("Aggregating intelligence from all modules…"):
            profile = collect_address_profile(
                profile_addr.strip(), df, api_key, profile_chain
            )
            st.session_state.current_profile = profile

    if "current_profile" not in st.session_state:
        st.info("Enter an address above and click Generate Full Profile.")
        return

    profile = st.session_state.current_profile
    sec     = profile.get("sections", {})

    # ── Risk Banner ───────────────────────────────────────────
    risk_colors = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    risk_icon   = risk_colors.get(profile["risk_level"],"⚪")
    score       = profile["overall_risk_score"]

    banner_col = {"CRITICAL":"#ff4444","HIGH":"#ff8800","MEDIUM":"#f59e0b","LOW":"#22c55e"}
    risk_bg  = banner_col.get(profile['risk_level'], '#888888')
    risk_lvl = profile['risk_level']
    addr_txt = profile['address']
    st.markdown(
        "<div style='background:" + risk_bg + ";padding:16px;border-radius:8px;"
        "color:white;font-size:18px;font-weight:bold;'>"
        + risk_icon + " " + risk_lvl + " RISK — Score: " + str(score) + "/100 — "
        "<code style='background:rgba(0,0,0,0.2);padding:4px 8px;border-radius:4px'>"
        + addr_txt + "</code></div>",
        unsafe_allow_html=True
    )
    st.markdown("")

    # ── Intelligence Flags ────────────────────────────────────
    if profile["flags"]:
        st.markdown("**⚑ Intelligence Flags:**")
        for flag in profile["flags"]:
            st.markdown(f"- {flag}")

    st.divider()

    # ── Profile Sections in tabs ──────────────────────────────
    prof_tabs = st.tabs([
        "📊 On-chain",     "🔴 Sanctions",    "🏷️ Classification",
        "🏦 Endpoints",    "👥 Counterparties","💰 Balance",
        "⚖️ Legal Actions"
    ])

    with prof_tabs[0]:
        oc = sec.get("on_chain", {})
        if oc:
            m1,m2,m3,m4 = st.columns(4)
            m1.metric("Total Transactions",  oc.get("total_transactions",0))
            m2.metric("Total Sent",          f"${oc.get('total_sent',0):,.2f}")
            m3.metric("Total Received",      f"${oc.get('total_received',0):,.2f}")
            m4.metric("Counterparties",      oc.get("unique_counterparties",0))
            m5,m6,m7,m8 = st.columns(4)
            m5.metric("First Seen",          oc.get("first_seen","—"))
            m6.metric("Last Seen",           oc.get("last_seen","—"))
            m7.metric("Tokens Used",         len(oc.get("tokens_used",[])))
            m8.metric("Risk Levels",         str(oc.get("risk_levels",{})))

            # Show recent transactions
            addr_lower = profile["address"].lower()
            addr_txs = df[
                (df["from_address"].str.lower() == addr_lower) |
                (df["to_address"].str.lower() == addr_lower)
            ]
            if not addr_txs.empty:
                show = [c for c in ["date","from_address","to_address","amount",
                                     "token","risk_level"] if c in addr_txs.columns]
                st.dataframe(addr_txs[show].head(20), use_container_width=True,
    hide_index=True,
    column_config={
        col: st.column_config.TextColumn(
            col,
            width="medium"
        )
        for col in df.columns
    }
)
        else:
            st.info("Address not found in current dataset.")

    with prof_tabs[1]:
        ofac = sec.get("ofac", {})
        rw   = sec.get("ransomware", {})
        intel = sec.get("intel", {})

        if ofac.get("hit"):
            st.error(f"🚨 **OFAC SDN MATCH** — Entity: {ofac.get('entity','Unknown')}")
        elif ofac.get("screened"):
            st.success("✅ OFAC: No match")
        else:
            st.info("OFAC screening not yet run — go to OSINT Intelligence to run it")

        if rw.get("hit"):
            st.error(
                f"☠️ **RANSOMWARE MATCH** — Family: {rw.get('family','Unknown')} "
                f"| Total paid: ${rw.get('paid',0):,.2f} BTC | Source: {rw.get('source','')}"
            )
        elif rw.get("screened"):
            st.success("✅ Ransomwhere + ThreatFox + CISA: No match")
        else:
            st.info("Ransomware screening not yet run — go to OSINT Intelligence")

        if intel.get("hit"):
            st.warning(f"🔍 **Intelligence hit:** {intel.get('sources','')}")
            if intel.get("usdc_frozen"): st.error("💵 USDC FROZEN by Circle")
            if intel.get("usdt_frozen"): st.error("💵 USDT FROZEN by Tether")
        elif intel.get("screened"):
            st.success("✅ GoPlus + Stablecoins + Hop: No match")
        else:
            st.info("Intel screening not yet run — go to Address Intelligence")

    with prof_tabs[2]:
        cls = sec.get("classification", {})
        if cls:
            m1,m2,m3 = st.columns(3)
            m1.metric("Address Type",  cls.get("type","—"))
            m2.metric("Label",         cls.get("label","—"))
            m3.metric("Confidence",    f"{cls.get('confidence',0)}%")
        else:
            st.info("Address classification not yet run — go to Address Intelligence")

    with prof_tabs[3]:
        exc = sec.get("exchange_endpoints", {})
        if exc and exc.get("exchanges"):
            st.success(
                f"🏦 Funds reached **{', '.join(exc['exchanges'])}** "
                f"({exc.get('tx_count',0)} transactions)"
            )
            st.info(exc.get("note",""))
            st.markdown("**Next step:** Serve subpoena/legal process to obtain KYC identity of account holder")
        else:
            st.info("No known exchange endpoints detected, or exchange detection not yet run.")

    with prof_tabs[4]:
        cp = sec.get("counterparties", {})
        if cp:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Top Recipients (sent to):**")
                for addr, vol in list(cp.get("top_sent_to",{}).items())[:5]:
                    st.markdown(f"`{addr[:20]}…` — ${vol:,.2f}")
            with c2:
                st.markdown("**Top Senders (received from):**")
                for addr, vol in list(cp.get("top_received_from",{}).items())[:5]:
                    st.markdown(f"`{addr[:20]}…` — ${vol:,.2f}")
        else:
            st.info("No counterparty data available.")

    with prof_tabs[5]:
        bal = sec.get("live_balance", {})
        if bal:
            b1, b2 = st.columns(2)
            b1.metric("Current Balance", f"{bal.get('balance',0):.6f}")
            b2.metric("Chain",           bal.get("chain",""))
            if bal.get("balance",0) > 0:
                st.warning(f"💰 {bal.get('note','')}")
        else:
            if not api_key:
                st.info("Add Etherscan API key to check live balance.")
            else:
                st.info("Balance check will run when profile is generated.")

    with prof_tabs[6]:
        actions = generate_legal_guidance(profile)
        if actions:
            priority_colors = {"IMMEDIATE":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
            for action in sorted(actions, key=lambda x: ["IMMEDIATE","HIGH","MEDIUM","LOW"].index(x["priority"])):
                icon = priority_colors.get(action["priority"],"⚪")
                with st.expander(f"{icon} **{action['priority']}** — {action['action'][:60]}…"):
                    st.markdown(f"**Action:** {action['action']}")
                    st.markdown(f"**Legal Authority:** {action['authority']}")
                    st.markdown(f"**Deadline:** {action['deadline']}")
        else:
            st.info("No specific legal actions recommended based on current intelligence.")

    st.divider()
    # Export profile as JSON
    profile_json = json.dumps(profile, indent=2, default=str)
    st.download_button(
        "⬇️ Export Full Profile JSON",
        profile_json.encode(),
        f"profile_{profile['address'][:16]}_{datetime.now().strftime('%Y%m%d')}.json",
        "application/json",
    )
