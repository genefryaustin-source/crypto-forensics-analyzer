"""
Crypto Forensics Analyzer Pro v4.0
Features: Bitquery · Breadcrumbs · Claude AI · Sankey · ML Anomaly · Multi-hop Tracing · OFAC · PDF
Enhanced with free multi-chain API support and deep hop tracing
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import io
import json
import requests
import time
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from sklearn.ensemble import IsolationForest
import logging

# Import custom modules
try:
    from blockchain_apis import (
        lookup_address, validate_address, get_chain_from_address,
        get_evm_transactions, get_bitcoin_transactions_blockchain,
        EXPLORER_APIS
    )
    from hop_tracer import HopTracer
    from forensics_patterns import (
        cluster_addresses_by_behavior, analyze_cluster_characteristics,
        detect_circular_flows, classify_circular_flow,
        detect_behavioral_anomalies, detect_mixer_patterns,
    )
    from forensics_export import (
        export_alerts_json, export_alerts_csv, export_alerts_pdf,
        generate_email_alert, export_to_siem,
    )
    from forensics_intel import (
        detect_structuring, analyze_velocity, plot_velocity_distribution,
        build_network_graph, profile_wallet, render_wallet_profile,
        detect_peeling_chains, detect_cross_chain_hops,
        analyze_stablecoin_flows, render_case_notes, STABLECOINS,
    )
except ImportError as e:
    st.error(f"Missing module: {e}. Ensure all .py files are in the same directory.")
    st.stop()

# ── Optional modules — imported individually so a missing file
#    disables only that feature instead of crashing the whole app ──
_OPTIONAL_MISSING = []

try:
    from forensics_fullreport import render_pdf_ui as render_full_pdf_ui, generate_full_report
except ImportError:
    _OPTIONAL_MISSING.append("forensics_fullreport")
    def render_full_pdf_ui(df): st.info("Add forensics_fullreport.py to your app folder.")
    def generate_full_report(df, **kw): return None

try:
    from forensics_lightning import render_lightning_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_lightning")
    def render_lightning_ui(df=None): st.info("Add forensics_lightning.py to enable Lightning Network forensics.")

try:
    from forensics_stablecoin import render_stablecoin_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_stablecoin")
    def render_stablecoin_ui(df=None): st.info("Add forensics_stablecoin.py to enable stablecoin depeg forensics.")

try:
    from forensics_newsfeed import render_newsfeed_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_newsfeed")
    def render_newsfeed_ui(df=None): st.info("Add forensics_newsfeed.py to enable crypto crime news feed.")

try:
    from forensics_social import render_social_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_social")
    def render_social_ui(df=None, get_key_fn=None):
        st.info("Add forensics_social.py to your app folder to enable social media intelligence.")

try:
    from forensics_netinfra import render_netinfra_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_netinfra")
    def render_netinfra_ui(df=None):
        st.info("Add forensics_netinfra.py to your app folder to enable infrastructure clustering.")

try:
    from forensics_seedphrase import render_seedphrase_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_seedphrase")
    def render_seedphrase_ui(df=None, get_key_fn=None):
        st.info("Add forensics_seedphrase.py to your app folder to enable seed phrase analysis.")

try:
    from forensics_scams import render_scams_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_scams")
    def render_scams_ui(df=None):
        st.info("Add forensics_scams.py to your app folder to enable threat intelligence.")

try:
    from forensics_profile import render_profile_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_profile")
    def render_profile_ui(df=None, get_key_fn=None):
        st.info("Add forensics_profile.py to your app folder to enable suspect profiling.")

try:
    from forensics_timeline import render_timeline_ui, render_qr_scanner_ui, render_agent_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_timeline")
    def render_timeline_ui(df=None): st.info("Add forensics_timeline.py to your app folder.")
    def render_qr_scanner_ui(df=None): st.info("Add forensics_timeline.py to your app folder.")
    def render_agent_ui(df=None, get_key_fn=None): st.info("Add forensics_timeline.py to your app folder.")

try:
    from forensics_export import render_export_ui
except ImportError:
    def render_export_ui(df=None, findings=None, get_key_fn=None):
        st.info("Export UI not available.")

try:
    from forensics_compliance2 import render_mica_compliance_ui
except ImportError:
    def render_mica_compliance_ui(df=None, get_key_fn=None):
        st.info("Add forensics_compliance2.py to enable MiCA compliance.")

try:
    from forensics_solana import render_solana_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_solana")
    def render_solana_ui():
        st.info("Add forensics_solana.py to your app folder to enable Solana support.")

try:
    from forensics_advanced2 import render_advanced2_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_advanced2")
    def render_advanced2_ui(df, get_key_fn=None):
        st.info("Add forensics_advanced2.py to your app folder.")

try:
    from forensics_api import render_api_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_api")
    def render_api_ui():
        st.info("Add forensics_api.py and run: pip install fastapi uvicorn[standard]")

try:
    from forensics_mev import render_mev_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_mev")
    def render_mev_ui(df):
        st.info("Add forensics_mev.py to your app folder.")

try:
    from forensics_compliance2 import render_compliance2_ui, render_case_dashboard
except ImportError:
    _OPTIONAL_MISSING.append("forensics_compliance2")
    def render_compliance2_ui(df, get_key_fn=None):
        st.info("Add forensics_compliance2.py to your app folder.")
    def render_case_dashboard():
        st.info("Add forensics_compliance2.py to your app folder.")

try:
    from forensics_address_intel import render_address_intel_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_address_intel")
    def render_address_intel_ui(df):
        st.info("Add forensics_address_intel.py to your app folder.")

try:
    from forensics_advanced import render_advanced_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_advanced")
    def render_advanced_ui(df, get_key_fn=None):
        st.info("Add forensics_advanced.py to your app folder.")

try:
    from forensics_osint import render_osint_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_osint")
    def render_osint_ui(df, get_key_fn=None):
        st.info("Add forensics_osint.py to your app folder to enable OFAC screening, "
                "ransomware detection, USD valuation, contract intel, and graph export.")

try:
    from forensics_timeseries import (
        detect_adaptive_laundering, detect_cyclical_patterns,
        detect_dormant_reactivation, plot_address_timeline,
    )
except ImportError:
    _OPTIONAL_MISSING.append("forensics_timeseries")
    def detect_adaptive_laundering(df, windows=None): return []
    def detect_cyclical_patterns(df): return []
    def detect_dormant_reactivation(df, dormant_days=180): return []
    def plot_address_timeline(df, address): return None

try:
    from forensics_compliance import render_compliance_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_compliance")
    def render_compliance_ui(df=None):
        st.info("Add forensics_compliance.py to your app folder to enable SAR/CTR filing.")

try:
    from forensics_crypto import render_signing_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_crypto")
    def render_signing_ui(findings=None):
        st.info("Add forensics_crypto.py to your app folder to enable EIP-712 signing.")

try:
    from forensics_ens import render_ens_lookup, enrich_dataframe_with_ens
except ImportError:
    _OPTIONAL_MISSING.append("forensics_ens")
    def render_ens_lookup():
        st.info("Add forensics_ens.py to your app folder to enable ENS resolution.")
    def enrich_dataframe_with_ens(df, max_lookups=20): return df

try:
    from forensics_alerts import render_alerts_ui
except ImportError:
    _OPTIONAL_MISSING.append("forensics_alerts")
    def render_alerts_ui(get_key_fn=None):
        st.info("Add forensics_alerts.py to your app folder to enable push alerts & monitoring.")

try:
    from forensics_zkp import ZKProofGenerator
except ImportError:
    _OPTIONAL_MISSING.append("forensics_zkp")
    class ZKProofGenerator:
        def generate_amount_proof(self, *a, **k): return {"error": "forensics_zkp.py not installed"}
        def generate_cluster_membership_proof(self, *a, **k): return {"error": "forensics_zkp.py not installed"}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Crypto Forensics Pro",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
.risk-critical { background:#ff4444; color:white; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:12px; }
.risk-high     { background:#ff8800; color:white; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:12px; }
.risk-medium   { background:#ffcc00; color:#333;  padding:2px 8px; border-radius:4px; font-weight:bold; font-size:12px; }
.risk-low      { background:#22c55e; color:white; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:12px; }
.metric-box    { background:#1e1e2e; border-radius:8px; padding:16px; text-align:center; }
.section-hdr   { font-size:13px; font-weight:600; color:#888; text-transform:uppercase; letter-spacing:1px; margin:12px 0 6px 0; }
.flag-box      { background:#1a1a2e; border-left:4px solid #ff4444; padding:10px 14px; border-radius:4px; margin:6px 0; }
.flag-box.high { border-left-color:#ff8800; }
.flag-box.med  { border-left-color:#ffcc00; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Crypto Forensics Analyzer Pro")
st.markdown("**Claude AI · Multi-chain APIs · Deep Hop Tracing · ML Anomaly · Sankey Flows · PDF Report**")

# ─────────────────────────────────────────────────────────────
# API KEY RESOLUTION
# Priority: secrets.toml  →  sidebar manual entry
#
# DESIGN: get_key() reads st.secrets LIVE on every call.
# No session_state seeding, no key= / value= conflicts.
# Sidebar widgets use "sb_" prefix keys so they never
# interfere with secrets lookup.
# ─────────────────────────────────────────────────────────────

KEY_NAMES = [
    "anthropic_key", "etherscan_key", "bscscan_key", "polygonscan_key",
    "snowtrace_key", "ftmscan_key", "arbiscan_key", "optimismscan_key",
    "bitquery_key", "breadcrumbs_key","tron_key",
]

def _read_secret(name: str) -> str:
    """
    Read one key from st.secrets. Checks every common layout:
      1. Top-level flat key   ->  anthropic_key = "..."  (correct format)
      2. [default] section    ->  was causing the keys-not-loading bug
      3. [api_keys] section   ->  alternative grouping
    Also handles legacy alias: open_ai -> openai_key
    Returns "" if missing or value looks like a placeholder.
    """
    ALIASES = {
        "openai_key":    ["openai_key", "open_ai", "OPENAI_API_KEY"],
        "anthropic_key": ["anthropic_key", "ANTHROPIC_API_KEY"],
    }
    candidates = ALIASES.get(name, [name])

    for section in [None, "default", "api_keys"]:
        for candidate in candidates:
            try:
                if section is None:
                    val = st.secrets[candidate]
                else:
                    val = st.secrets[section][candidate]
                val = str(val).strip()
                if val and "PASTE_YOUR" not in val and val != "":
                    return val
            except Exception:
                pass
    return ""


def get_key(name: str) -> str:
    """
    Return the active API key for `name`.
    Priority: secrets.toml (read live) > sidebar manual entry (sb_ prefix).
    Reading secrets live avoids all session_state timing/conflict issues.
    """
    secret = _read_secret(name)
    if secret:
        return secret
    # Fall back to what the user typed in the sidebar
    return st.session_state.get(f"sb_{name}", "")

# ─────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────
st.sidebar.header("🔑 API Keys")

# ─────────────────────────────────────────────────────────────
# SIDEBAR NAVIGATION  (replaces overflow tab bar)
# ─────────────────────────────────────────────────────────────
with st.sidebar:
    st.divider()
    st.markdown("### 🗂 Navigation")
    if "nav_page" not in st.session_state:
        st.session_state.nav_page = "📊 Overview"

    NAV_GROUPS = {
        "📊 Analysis":      ["📊 Overview","📋 Transactions","💸 Sankey Flow","📅 Timeline"],
        "🔍 Intelligence":  ["🔗 Multi-hop Tracer","🧩 Pattern Intel","⚡ Velocity","🕸 Network Graph","🏗️ Infrastructure"],
        "📡 SOCMINT":        ["📡 Social Media Intel"],
        "🤖 AI & ML":       ["🤖 Claude AI","📈 Time Series ML"],
        "⚖️ Compliance":    ["📋 SAR / CTR Filing","🔐 EIP-712 Signing","🔏 ZK Proofs"],
        "🌐 On-chain":      ["🌐 ENS Resolution","🔔 Alerts & Monitoring"],
        "🔎 OSINT":         ["🔎 OSINT Intelligence"],
        "🏷️ Address Intel": ["🏷️ Address Intelligence"],
        "⚔️ Market Intel":  ["⚔️ MEV & Market Manipulation","🎯 Threat Intel","🤝 P2P & ATMs"],
        "👤 Profiles":       ["👤 Suspect Profile","🌱 Seed Phrase","📅 Investigation Timeline","📱 QR Scanner","🤖 Investigation Agent"],
        "🔬 Advanced":      ["🖼 NFT & Airdrop","🌍 Geolocation","💾 Save/Restore","💼 Portfolio","📈 Price Ticker"],
        "📋 Regulatory":    ["✈️ FATF Travel Rule","🔵 L2 Chains","🔐 Multi-sig","🔒 Privacy Coins","📊 Case Dashboard","🇪🇺 MiCA Compliance"],
        "◎ Solana":          ["◎ Solana Analysis"],
        "🔬 Deep Analytics": ["🌪️ Tornado Linking","🧠 GNN Clustering","⏳ Mempool Monitor","🔀 Atomic Swaps","⚡ Lightning Network"],
        "📰 Crime Intel":     ["📰 Crypto Crime News","💹 Stablecoin Depeg"],
        "🔌 API":             ["🔌 REST API"],
        "📤 Reports":       ["📄 PDF Report","📤 Export & SIEM","🕸 Maltego Export","📁 Case Notes"],
        "⚙️ Settings":      ["⚙️ Configuration"],
    }
    for group, pages in NAV_GROUPS.items():
        st.markdown(f"**{group}**")
        for pg in pages:
            if st.button(pg, key=f"nav_{pg}", use_container_width=True,
                         type="primary" if st.session_state.nav_page == pg else "secondary"):
                st.session_state.nav_page = pg
                st.rerun()


# Helper: show ✅ / ⬜ status next to each label
def _key_label(display_name: str, key_name: str) -> str:
    return f"{'✅' if get_key(key_name) else '⬜'} {display_name}"

with st.sidebar.expander("🔑 Manage API Keys", expanded=not any(get_key(k) for k in KEY_NAMES)):
    st.caption(
        "Keys load automatically from `.streamlit/secrets.toml`. "
        "Paste here to override or add missing keys. "
        "Changes apply immediately and persist for this session."
    )

    # Widgets use "sb_" prefix keys — completely separate from secrets lookup.
    # get_key() reads st.secrets live first; sb_ values are manual overrides.
    st.markdown("**Premium APIs**")
    st.text_input(_key_label("Anthropic (Claude)",  "anthropic_key"),
                  type="password", key="sb_anthropic_key",
                  placeholder="auto-loaded from secrets.toml if set",
                  help="api.anthropic.com — AI forensics")
    st.text_input(_key_label("Bitquery",            "bitquery_key"),
                  type="password", key="sb_bitquery_key",
                  placeholder="auto-loaded from secrets.toml if set",
                  help="bitquery.io — on-chain GraphQL")
    st.text_input(_key_label("Breadcrumbs",         "breadcrumbs_key"),
                  type="password", key="sb_breadcrumbs_key",
                  placeholder="auto-loaded from secrets.toml if set",
                  help="breadcrumbs.app — address profiling")

    st.markdown("**Blockchain Explorers** — free keys at each link")
    st.text_input(_key_label("Etherscan (ETH)",     "etherscan_key"),
                  type="password", key="sb_etherscan_key",
                  placeholder="auto-loaded from secrets.toml if set",
                  help="https://etherscan.io/apis")
    st.text_input(_key_label("BscScan (BNB)",       "bscscan_key"),
                  type="password", key="sb_bscscan_key",
                  placeholder="auto-loaded from secrets.toml if set",
                  help="https://bscscan.com/apis")
    st.text_input(_key_label("PolygonScan (MATIC)", "polygonscan_key"),
                  type="password", key="sb_polygonscan_key",
                  placeholder="auto-loaded from secrets.toml if set",
                  help="https://polygonscan.com/apis")
    st.text_input(_key_label("Snowtrace (AVAX)",    "snowtrace_key"),
                  type="password", key="sb_snowtrace_key",
                  placeholder="auto-loaded from secrets.toml if set",
                  help="https://snowtrace.io/apis")
    st.text_input(_key_label("FTMScan (FTM)",       "ftmscan_key"),
                  type="password", key="sb_ftmscan_key",
                  placeholder="auto-loaded from secrets.toml if set",
                  help="https://ftmscan.com/apis")
    st.text_input(_key_label("TronScan (TR)", "tron_key"),
                  type="password", key="sb_tron_key",
                  placeholder="auto-loaded from secrets.toml if set",
                  help="https://tronscan.com/apis")

    # Status: show how many keys are active (from secrets or manual entry)
    secrets_loaded = [k for k in KEY_NAMES if _read_secret(k)]
    manual_active  = [k for k in KEY_NAMES if st.session_state.get(f"sb_{k}")]
    total_active   = len(set([k for k in KEY_NAMES if get_key(k)]))
    if secrets_loaded:
        st.success(
                f"✅ {len(secrets_loaded)} key(s) loaded from secrets.toml"
                + (f"  +  {len(manual_active)} manual override(s)" if manual_active else "")
        )
    elif manual_active:
        st.info(f"⌨️ {len(manual_active)} key(s) entered manually (no secrets.toml)")
    else:
        st.warning(
                "⚠️ Keys not loading from secrets.toml. Check that:\n"
                "1. File is at `.streamlit/secrets.toml` (in the .streamlit folder next to your app)\n"
                "2. Keys are at TOP LEVEL — no [default] or [api_keys] section header\n"
                "3. App was restarted after editing the file"
        )
        st.markdown("📄 **secrets.toml template** — save as `.streamlit/secrets.toml`")
        st.code(
"""# .streamlit/secrets.toml
# Create the .streamlit folder next to your app file if it does not exist

anthropic_key    = \"sk-ant-api03-...\"
etherscan_key    = \"YOUR_ETHERSCAN_KEY\"
bscscan_key      = \"YOUR_BSCSCAN_KEY\"
polygonscan_key  = \"YOUR_POLYGONSCAN_KEY\"
snowtrace_key    = \"YOUR_SNOWTRACE_KEY\"
ftmscan_key      = \"YOUR_FTMSCAN_KEY\"
arbiscan_key     = \"YOUR_ARBISCAN_KEY\"
optimismscan_key = \"YOUR_OPTIMISM_KEY\"
bitquery_key     = \"YOUR_BITQUERY_KEY\"
breadcrumbs_key  = \"YOUR_BREADCRUMBS_KEY\"
""",
            language="toml",
        )

st.sidebar.divider()
st.sidebar.header("📂 Data Source")
uploaded_file = st.sidebar.file_uploader("Upload Transaction CSV", type=["csv"])

# Clear data button — resets session so a new file can be loaded
if st.session_state.get("processed_df") is not None:
    col_clr1, col_clr2 = st.sidebar.columns(2)
    rows = len(st.session_state.processed_df)
    col_clr1.caption(f"📂 {rows:,} rows loaded")
    if col_clr2.button("🗑 Clear", key="clear_data", help="Remove loaded data and start fresh"):
        for _k in ["processed_df", "raw_df", "_src_hash", "live_df", "_live_df_hash",
                   "pattern_results", "vel_df", "ng_fig", "ts_r", "ai_result",
                   "trace_hops", "trace_df", "trace_summary"]:
            st.session_state.pop(_k, None)
        st.rerun()
if st.sidebar.button("Load Sample Data (BSC/DeFi)", use_container_width=True):
    st.session_state.sample = True
if st.sidebar.button("Load Sample Data (Bitcoin)", use_container_width=True):
    st.session_state.sample_btc = True

st.sidebar.divider()
st.sidebar.header("🔍 On-chain Lookup")
lookup_address_input = st.sidebar.text_input("Address / Tx Hash", placeholder="0x... or 1A1zP...")
lookup_chain_select  = st.sidebar.selectbox("Chain", ["ethereum", "bsc", "polygon", "avalanche", "fantom", "arbitrum", "optimism", "tron", "bitcoin"])

col_lookup1, col_lookup2 = st.sidebar.columns(2)
with col_lookup1:
    if st.button("🔍 Lookup", use_container_width=True):
        st.session_state.do_lookup = True
with col_lookup2:
    if st.button("🔗 Both Directions", use_container_width=True):
        st.session_state.do_lookup_both = True



# ─────────────────────────────────────────────────────────────
# SAMPLE DATA
# ─────────────────────────────────────────────────────────────
SAMPLE_BSC = """date,from_address,to_address,amount,token,tx_hash,chain
2023-07-01,0xb06dd9dD6808F5935,0xe62e359809d1d239,5669.45,BSC-USD,0xabc1,BSC
2023-07-02,0xe62e359809d1d239,0xb06dd9dD6808F5935,1770.44,BSB,0xabc2,BSC
2023-07-06,0xb06dd9dD6808F5935,Multichain_Bridge,1525329.85,anyUSDT,0xabc3,BSC
2023-07-06,Multichain_Bridge,0xef3ede3f84624247,1524800.00,USDT,0xabc4,Ethereum
2023-07-07,0xef3ede3f84624247,Tornado_Cash,500000,USDT,0xabc5,Ethereum
2023-07-07,0xef3ede3f84624247,FixedFloat,300000,USDT,0xabc6,Ethereum
2023-07-08,Tornado_Cash,0xnewaddr1fresh,498000,ETH,0xabc7,Ethereum
2023-07-09,FixedFloat,0xnewaddr2fresh,299500,USDT,0xabc8,Ethereum
2023-07-10,0xadedafd06cc16dec,0xb06dd9dD6808F5935,487.42,USDC,0xabc9,BSC
2023-07-11,0xb06dd9dD6808F5935,PancakeSwap_V3,487.42,USDC,0xabc10,BSC
2023-07-12,PancakeSwap_V3,0xb06dd9dD6808F5935,490.10,BNB,0xabc11,BSC
2023-07-13,0xb06dd9dD6808F5935,Binance_Deposit,490.00,BNB,0xabc12,BSC
2023-07-14,0xef3ede3f84624247,0xnewaddr3,200000,USDT,0xabc13,Ethereum
2023-07-15,0xnewaddr3,Uniswap_V3,199000,USDT,0xabc14,Ethereum
2023-07-16,Uniswap_V3,0xnewaddr3,198500,ETH,0xabc15,Ethereum"""

SAMPLE_BTC = """date,from_address,to_address,amount,token,tx_hash,chain
2024-01-05,1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf,1BpEi6DfDAUFd153wiGrvkiKW9UNqKD2dq,0.5,BTC,abc123def456,Bitcoin
2024-01-06,1BpEi6DfDAUFd153wiGrvkiKW9UNqKD2dq,bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh,1.2,BTC,def789ghi012,Bitcoin
2024-01-07,bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh,ChipMixer_wallet,0.8,BTC,ghi345jkl678,Bitcoin
2024-01-08,ChipMixer_wallet,1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF,0.79,BTC,jkl901mno234,Bitcoin
2024-01-09,1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF,Binance_hot_wallet,0.5,BTC,mno567pqr890,Bitcoin
2024-01-10,Binance_hot_wallet,1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s,0.48,BTC,pqr123stu456,Bitcoin
2024-01-11,1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s,1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v,2.1,BTC,stu789vwx012,Bitcoin
2024-01-12,1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v,Wasabi_CoinJoin,1.9,BTC,vwx345yza678,Bitcoin
2024-01-13,Wasabi_CoinJoin,1GkQmKAmHtNfnD3LZyCB7QT8vBFVxA2Bdz,0.95,BTC,yza901bcd234,Bitcoin
2024-01-13,Wasabi_CoinJoin,1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY,0.94,BTC,bcd567efg890,Bitcoin
2024-01-15,1GkQmKAmHtNfnD3LZyCB7QT8vBFVxA2Bdz,Kraken_deposit,0.9,BTC,efg123hij456,Bitcoin
2024-01-16,1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY,LocalBitcoins,0.88,BTC,hij789klm012,Bitcoin"""


# ─────────────────────────────────────────────────────────────
# KNOWN RISK PATTERNS
# ─────────────────────────────────────────────────────────────
HIGH_RISK_PATTERNS = {
    "Tornado Cash":     ["tornado", "tornadocash"],
    "ChipMixer":        ["chipmixer"],
    "Wasabi/CoinJoin":  ["wasabi", "coinjoin", "samurai", "whirlpool"],
    "Darknet Market":   ["hydra", "omgomg", "alphabay", "darknet", "silkroad"],
    "Sanctioned":       ["ofac", "sanctioned", "sdn"],
    "Mixer":            ["mixer", "blender", "sinbad"],
    "FixedFloat":       ["fixedfloat"],
    "LocalBitcoins":    ["localbitcoin"],
}

BRIDGE_PATTERNS     = ["multichain", "anyswap", "bridge", "renbridge", "wormhole", "stargate", "hop protocol"]
EXCHANGE_PATTERNS   = ["binance", "kraken", "coinbase", "okx", "bybit", "pancakeswap", "uniswap", "ftx", "huobi", "kucoin"]
DEFI_PATTERNS       = ["aave", "compound", "curve", "yearn", "sushiswap", "1inch"]

OFAC_SAMPLE = [
    "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c",
    "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b",
    "Tornado_Cash", "FixedFloat",
]


# ─────────────────────────────────────────────────────────────
# DATA NORMALIZATION
# ─────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    # Normalize address columns safely
    for col in ["from_address", "to_address"]:
        if col in df.columns:
            df[col] = (
                df[col]
                .fillna("")
                .astype(str)
                .str.strip()
            )

    # Normalize token safely
    if "token" in df.columns:
        df["token"] = (
            df["token"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    # Normalize risk safely
    if "risk_level" in df.columns:
        df["risk_level"] = (
            df["risk_level"]
            .fillna("LOW")
            .astype(str)
            .str.upper()
        )

    # Normalize amount safely
    if "amount" in df.columns:
        df["amount"] = pd.to_numeric(
            df["amount"],
            errors="coerce"
        ).fillna(0)
    # Drop unnamed index columns produced by some exporters
    df = df.loc[:, ~df.columns.str.match(r'^Unnamed')]

    # amount
    for col in df.columns:
        if any(x in col.lower() for x in ['amount', 'value', 'amt', 'vol', 'quantity']):
            df['amount'] = pd.to_numeric(df[col], errors='coerce').fillna(0)
            break
    else:
        df['amount'] = 0.0

    # addresses
    for col in df.columns:
        cl = col.lower()
        if any(x in cl for x in ['from', 'sender', 'source']):
            df['from_address'] = df[col].astype(str)
        if any(x in cl for x in ['to', 'receiver', 'dest', 'recipient']):
            df['to_address'] = df[col].astype(str)

    for c in ['from_address', 'to_address']:
        if c not in df.columns:
            df[c] = 'Unknown'

    # token / chain / date
    for col in df.columns:
        cl = col.lower()
        if 'token' in cl or 'currency' in cl or 'asset' in cl:
            df['token'] = df[col].astype(str)
            break
    else:
        df['token'] = 'UNKNOWN'

    for col in df.columns:
        if 'chain' in col.lower() or 'network' in col.lower():
            df['chain'] = df[col].astype(str)
            break
    else:
        df['chain'] = 'Unknown'

    for col in df.columns:
        if 'date' in col.lower() or 'time' in col.lower():
            df['date'] = pd.to_datetime(df[col], errors='coerce')
            break
    else:
        df['date'] = pd.NaT

    if 'tx_hash' not in df.columns:
        df['tx_hash'] = [f"TX{i:04d}" for i in range(len(df))]

    return df


# ─────────────────────────────────────────────────────────────
# RISK SCORING  — fully vectorized for large datasets
# Row-by-row df.apply() is ~100x slower on 10k+ rows.
# All operations here use pandas Series methods (str.contains,
# np.select, clip) so they run in C, not Python loops.
# ─────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def calculate_risk_vectorized(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    # Normalize address columns safely
    for col in ["from_address", "to_address"]:
        if col in df.columns:
            df[col] = (
                df[col]
                .fillna("")
                .astype(str)
                .str.strip()
            )

    # Normalize token safely
    if "token" in df.columns:
        df["token"] = (
            df["token"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    # Normalize risk safely
    if "risk_level" in df.columns:
        df["risk_level"] = (
            df["risk_level"]
            .fillna("LOW")
            .astype(str)
            .str.upper()
        )

    # Normalize amount safely
    if "amount" in df.columns:
        df["amount"] = pd.to_numeric(
            df["amount"],
            errors="coerce"
        ).fillna(0)

    # Build a single lower-case combined address string per row (vectorized)
    combined = (
        df["from_address"].astype(str).str.lower()
        + " "
        + df["to_address"].astype(str).str.lower()
    )
    amt = df["amount"].fillna(0)

    score   = pd.Series(0, index=df.index, dtype=int)
    reasons = pd.Series("", index=df.index, dtype=str)

    # ── High-risk entity patterns ─────────────────────────────
    for label, patterns in HIGH_RISK_PATTERNS.items():
        regex = "|".join(patterns)
        mask  = combined.str.contains(regex, regex=True, na=False)
        score   = score.where(~mask, score + 85)
        reasons = reasons.where(~mask, reasons + label + "; ")

    # ── OFAC sanctions ────────────────────────────────────────
    ofac_regex = "|".join(s.lower() for s in OFAC_SAMPLE)
    ofac_mask  = combined.str.contains(ofac_regex, regex=True, na=False)
    score   = score.where(~ofac_mask, score + 90)
    reasons = reasons.where(~ofac_mask, reasons + "OFAC Sanctions Match; ")

    # ── Bridge patterns ───────────────────────────────────────
    bridge_regex = "|".join(BRIDGE_PATTERNS)
    bridge_mask  = combined.str.contains(bridge_regex, regex=True, na=False)
    score   = score.where(~bridge_mask, score + 35)
    reasons = reasons.where(~bridge_mask, reasons + "Cross-chain Bridge; ")

    # ── Volume thresholds ─────────────────────────────────────
    vol_1m  = amt >= 1_000_000
    vol_100k= (amt >= 100_000) & ~vol_1m
    vol_10k = (amt >= 10_000)  & ~vol_100k & ~vol_1m
    score   = score + np.where(vol_1m, 50, np.where(vol_100k, 30, np.where(vol_10k, 10, 0)))
    reasons = (
        reasons
        + np.where(vol_1m,   "Volume ≥ $1M; ", "")
        + np.where(vol_100k, "Volume ≥ $100K; ", "")
        + np.where(vol_10k,  "Volume ≥ $10K; ", "")
    )

    # ── Round-number heuristic ────────────────────────────────
    round_mask = (amt > 0) & (amt == (amt / 1000).round() * 1000)
    score   = score.where(~round_mask, score + 10)
    reasons = reasons.where(~round_mask, reasons + "Round-number; ")

    # ── Finalise ──────────────────────────────────────────────
    score = score.clip(upper=100)
    conditions  = [score >= 85, score >= 60, score >= 35]
    choices     = ["CRITICAL", "HIGH", "MEDIUM"]
    df["risk_level"]   = np.select(conditions, choices, default="LOW")
    df["risk_score"]   = score
    df["risk_reasons"] = reasons.str.strip("; ").replace("", "Clean")
    df["confidence"]   = (score + 20).clip(upper=95)
    return df


# Keep single-row version for hop tracer compatibility
def calculate_risk(row):
    tmp = pd.DataFrame([row])
    out = calculate_risk_vectorized(tmp)
    r = out.iloc[0]
    return r["risk_level"], int(r["risk_score"]), r["risk_reasons"], int(r["confidence"])


# ─────────────────────────────────────────────────────────────
# ML ANOMALY DETECTION
# ─────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    # Normalize address columns safely
    for col in ["from_address", "to_address"]:
        if col in df.columns:
            df[col] = (
                df[col]
                .fillna("")
                .astype(str)
                .str.strip()
            )

    # Normalize token safely
    if "token" in df.columns:
        df["token"] = (
            df["token"]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    # Normalize risk safely
    if "risk_level" in df.columns:
        df["risk_level"] = (
            df["risk_level"]
            .fillna("LOW")
            .astype(str)
            .str.upper()
        )

    # Normalize amount safely
    if "amount" in df.columns:
        df["amount"] = pd.to_numeric(
            df["amount"],
            errors="coerce"
        ).fillna(0)
    if len(df) < 5:
        df['is_anomaly'] = False
        return df
    feat = np.log1p(df[['amount']].fillna(0).values)
    # Reduce n_estimators for speed on large datasets
    n_est = 50 if len(df) > 5000 else 100
    df['is_anomaly'] = IsolationForest(
        contamination=0.15, random_state=42, n_estimators=n_est
    ).fit_predict(feat) == -1
    return df


# ─────────────────────────────────────────────────────────────
# SANKEY DIAGRAM
# ─────────────────────────────────────────────────────────────
def create_sankey(df, top_n=100):

    if df is None or df.empty:
        return None

    try:

        # SAFE COPY
        df2 = df.copy()

        # CLEAN DATA
        df2 = df2.dropna(
            subset=["from_address", "to_address", "amount"]
        )

        # NORMALIZE
        for col in ["from_address", "to_address"]:
            df2[col] = (
                df2[col]
                .astype(str)
                .str.strip()
            )

        df2["amount"] = (
            df2["amount"]
            .astype(str)
            .str.replace(",", "", regex=False)
            .str.replace("$", "", regex=False)
            .str.strip()
        )

        df2["amount"] = pd.to_numeric(
            df2["amount"],
            errors="coerce"
        )

        # REMOVE INVALIDS
        invalid_vals = ["", "nan", "none", "null"]

        # Address normalization
        address_map = {
            "from_address": [
                "from_address",
                "from",
                "sender",
                "source"
            ],
            "to_address": [
                "to_address",
                "to",
                "receiver",
                "recipient",
                "destination"
            ]
        }

        for target_col, aliases in address_map.items():

            found = None

            for col in df.columns:

                cl = col.lower().strip()

                if cl in aliases:
                    found = col
                    break

            if found:
                df[target_col] = (
                    df[found]
                    .fillna("")
                    .astype(str)
                    .str.strip()
                )
            else:
                df[target_col] = ""

        # REMOVE SELF TRANSFERS
        df2 = df2[
            df2["from_address"].str.lower()
            !=
            df2["to_address"].str.lower()
        ]

        # KEEP NONZERO FLOWS
        df2 = df2[df2["amount"] > 0]

        # BUILD FLOWS
        flows = (
            df2.groupby(
                ["from_address", "to_address"],
                as_index=False
            )["amount"]
            .sum()
        )

        flows = flows.nlargest(top_n, "amount")

        # DEBUG
        st.write("Sankey flow count:", len(flows))

        if flows.empty:
            st.warning("Flows dataframe empty after filtering.")
            return None

        # Build node list — deduplicated, deterministic order
        src_nodes  = flows["from_address"].tolist()
        tgt_nodes  = flows["to_address"].tolist()
        all_nodes  = list(dict.fromkeys(src_nodes + tgt_nodes))  # preserves order, deduplicates
        node_idx   = {n: i for i, n in enumerate(all_nodes)}

        # Risk colour map (vectorized — avoids slow iterrows on large df)
        RCOL = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#22c55e"}
        risk_map = {}
        if "risk_level" in df.columns:
            for addr_col in ["from_address", "to_address"]:
                addr_risk = df.groupby(addr_col)["risk_level"].agg(
                    lambda x: x.mode()[0] if len(x) else "LOW"
                ).to_dict()
                for addr, risk in addr_risk.items():
                    # Keep highest risk seen for this address
                    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    if order.get(risk, 0) > order.get(risk_map.get(addr, "LOW"), 0):
                        risk_map[addr] = risk

        def _hex_rgba(hex_col: str, alpha: float = 0.4) -> str:
            h = hex_col.lstrip("#")
            if len(h) != 6:
                return f"rgba(136,136,136,{alpha})"
            try:
                r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
                return f"rgba({r},{g},{b},{alpha})"
            except ValueError:
                return f"rgba(136,136,136,{alpha})"

        # Node colours and labels
        node_colors = [RCOL.get(risk_map.get(n, "LOW"), "#888888") for n in all_nodes]
        node_labels = [
            (str(n)[:14] + "…" if len(str(n)) > 14 else str(n))
            for n in all_nodes
        ]

        # Link colours (by source node risk)
        link_colors = [
            _hex_rgba(RCOL.get(risk_map.get(r["from_address"], "LOW"), "#888888"))
            for _, r in flows.iterrows()
        ]

        # Build custom hover data for links (Plotly >=4.x compatible)
        link_hover = [
            f"{node_labels[node_idx[r['from_address']]]} → "
            f"{node_labels[node_idx[r['to_address']]]}<br>"
            f"${r['amount']:,.2f}"
            for _, r in flows.iterrows()
        ]

        # Node volume totals for hover (compute manually — don't rely on Plotly internals)
        node_vol = {}
        for _, r in flows.iterrows():
            node_vol[r["from_address"]] = node_vol.get(r["from_address"], 0) + r["amount"]
            node_vol[r["to_address"]]   = node_vol.get(r["to_address"],   0) + r["amount"]

        node_hover = [
            f"{node_labels[i]}<br>Risk: {risk_map.get(n,'LOW')}<br>Volume: ${node_vol.get(n,0):,.2f}"
            for i, n in enumerate(all_nodes)
        ]

        # ── Build Sankey ─────────────────────────────────────────
        # NOTE: No arrangement="snap" — not supported in Plotly <5.12
        # NOTE: Node hovertemplate uses only safe variables (%{customdata})
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=18,
                thickness=16,
                line=dict(color="rgba(0,0,0,0.25)", width=0.5),
                label=node_labels,
                color=node_colors,
                customdata=node_hover,
                hovertemplate="%{customdata}<extra></extra>",
            ),
            link=dict(
                source=[node_idx[r["from_address"]] for _, r in flows.iterrows()],
                target=[node_idx[r["to_address"]]   for _, r in flows.iterrows()],
                value=flows["amount"].tolist(),
                color=link_colors,
                customdata=link_hover,
                hovertemplate="%{customdata}<extra></extra>",
            ),
        )])

        fig.update_layout(
            title_text="💸 Fund Flow Sankey — node colour = risk level",
            height=680,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(size=10),
            margin=dict(l=20, r=20, t=50, b=20),
        )
        return fig

    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Sankey build failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────
# TIMELINE CHART
# ─────────────────────────────────────────────────────────────
def create_timeline(df):
    df2 = df.dropna(subset=['date']).copy()
    if df2.empty:
        return None
    risk_color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#22c55e"}
    df2['color'] = df2['risk_level'].map(risk_color).fillna('#888')
    fig = px.scatter(
        df2, x='date', y='amount', color='risk_level',
        color_discrete_map=risk_color,
        size='amount', size_max=40,
        hover_data=['from_address','to_address','token','tx_hash'],
        title="📅 Transaction Timeline — bubble size = value"
    )
    fig.update_layout(height=420, paper_bgcolor='rgba(0,0,0,0)')
    return fig


# ─────────────────────────────────────────────────────────────
# CLAUDE AI ANALYSIS
# ─────────────────────────────────────────────────────────────
def run_claude_analysis(df, api_key, extra_context=""):
    critical = df[df['risk_level'] == 'CRITICAL']
    high     = df[df['risk_level'] == 'HIGH']
    total_vol= df['amount'].sum()
    chains   = df['chain'].unique().tolist()
    tokens   = df['token'].unique().tolist()
    anomalies= df[df.get('is_anomaly', False) == True] if 'is_anomaly' in df.columns else pd.DataFrame()

    summary = f"""
TRANSACTION SUMMARY
===================
Total transactions: {len(df)}
Total volume: ${total_vol:,.2f}
Chains: {', '.join(str(c) for c in chains)}
Tokens: {', '.join(str(t) for t in tokens)}
Critical-risk transactions: {len(critical)}
High-risk transactions: {len(high)}
ML-flagged anomalies: {len(anomalies)}

TOP RISK TRANSACTIONS (up to 15):
{df.nlargest(15,'risk_score')[['date','from_address','to_address','amount','token','risk_level','risk_reasons']].to_string(index=False)}

ALL TRANSACTIONS (up to 30):
{df.head(30)[['date','from_address','to_address','amount','token','chain','risk_level']].to_string(index=False)}

{extra_context}
"""

    payload = {
        "model": "claude-opus-4-5",
        "max_tokens": 2000,
        "system": (
            "You are a senior blockchain forensics and AML compliance expert with deep knowledge of "
            "crypto crime typologies, FATF guidance, and FinCEN SAR requirements. "
            "Analyze the provided transaction data and return a comprehensive structured report covering: "
            "1) Executive summary with overall risk verdict "
            "2) Specific red flags with addresses "
            "3) Detected typologies (layering, structuring, chain-hopping, mixing) "
            "4) Likely fund origin and destination "
            "5) Recommended actions (SAR filing, OFAC screening, account freeze) "
            "6) SAR narrative paragraph ready for submission. "
            "Be specific, cite addresses and amounts."
        ),
        "messages": [{"role": "user", "content": f"Analyze for AML/forensics risk:\n\n{summary}"}]
    }

    headers = {
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json"
    }

    try:
        resp = requests.post("https://api.anthropic.com/v1/messages",
                             json=payload, headers=headers, timeout=60)
        if resp.status_code == 200:
            data = resp.json()
            return data["content"][0]["text"]
        return f"API Error {resp.status_code}: {resp.text[:300]}"
    except Exception as e:
        return f"Request failed: {e}"


# ─────────────────────────────────────────────────────────────
# PDF REPORT
# ─────────────────────────────────────────────────────────────
def generate_pdf(df, ai_analysis=""):
    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=letter,
                                topMargin=0.75*inch, bottomMargin=0.75*inch,
                                leftMargin=0.75*inch, rightMargin=0.75*inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title2', parent=styles['Title'], fontSize=18, spaceAfter=6)
    h1_style    = ParagraphStyle('H1',     parent=styles['Heading1'], fontSize=13, spaceBefore=12, spaceAfter=4)
    h2_style    = ParagraphStyle('H2',     parent=styles['Heading2'], fontSize=11, spaceBefore=8,  spaceAfter=3)
    body_style  = ParagraphStyle('Body',   parent=styles['Normal'],   fontSize=9,  leading=13)
    code_style  = ParagraphStyle('Code',   parent=styles['Code'],     fontSize=7,  leading=10, fontName='Courier')

    risk_palette = {
        "CRITICAL": colors.HexColor("#ff4444"),
        "HIGH":     colors.HexColor("#ff8800"),
        "MEDIUM":   colors.HexColor("#ffcc00"),
        "LOW":      colors.HexColor("#22c55e"),
    }

    elements = []

    # Header
    elements.append(Paragraph("CRYPTO FORENSICS INVESTIGATION REPORT", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp; "
        f"Crypto Forensics Pro v4.0",
        ParagraphStyle('sub', parent=styles['Normal'], fontSize=9, textColor=colors.grey)
    ))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#ff4444"), spaceAfter=12))

    # Summary metrics
    elements.append(Paragraph("Executive Summary", h1_style))
    total_vol = df['amount'].sum()
    critical  = len(df[df['risk_level'] == 'CRITICAL'])
    high      = len(df[df['risk_level'] == 'HIGH'])
    anomalies = len(df[df['is_anomaly']]) if 'is_anomaly' in df.columns else 0

    summary_data = [
        ["Metric", "Value"],
        ["Total Transactions",     str(len(df))],
        ["Total Volume",           f"${total_vol:,.2f}"],
        ["Unique Chains",          str(df['chain'].nunique())],
        ["Unique Tokens",          str(df['token'].nunique())],
        ["CRITICAL Risk",          str(critical)],
        ["HIGH Risk",              str(high)],
        ["ML Anomalies Detected",  str(anomalies)],
        ["Report Date",            datetime.now().strftime('%Y-%m-%d')],
    ]
    t = Table(summary_data, colWidths=[2.8*inch, 3.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,0),  colors.HexColor("#1e1e2e")),
        ('TEXTCOLOR',   (0,0), (-1,0),  colors.white),
        ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#f5f5f5"), colors.white]),
        ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING',(0,0), (-1,-1), 8),
        ('TOPPADDING',  (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0),(-1,-1), 5),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 14))

    # Transaction table
    elements.append(Paragraph("Transaction Ledger", h1_style))
    cols = ['date', 'from_address', 'to_address', 'amount', 'token', 'risk_level', 'risk_score']
    cols = [c for c in cols if c in df.columns]
    display_df = df[cols].head(40).copy()
    display_df['amount'] = display_df['amount'].apply(lambda x: f"${x:,.2f}" if pd.notna(x) else "")
    display_df['date']   = display_df['date'].astype(str).str[:10]

    col_headers = [c.replace('_', ' ').title() for c in cols]
    table_data  = [col_headers] + display_df.values.tolist()

    col_w = [1.0, 1.6, 1.6, 0.9, 0.7, 0.8, 0.6][:len(cols)]
    tx_table = Table(table_data, colWidths=[w*inch for w in col_w], repeatRows=1)

    ts = TableStyle([
        ('BACKGROUND',   (0,0),  (-1,0),  colors.HexColor("#1e1e2e")),
        ('TEXTCOLOR',    (0,0),  (-1,0),  colors.white),
        ('FONTNAME',     (0,0),  (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0),  (-1,-1), 7),
        ('FONTNAME',     (0,1),  (-1,-1), 'Courier'),
        ('GRID',         (0,0),  (-1,-1), 0.3, colors.HexColor("#dddddd")),
        ('LEFTPADDING',  (0,0),  (-1,-1), 4),
        ('RIGHTPADDING', (0,0),  (-1,-1), 4),
        ('TOPPADDING',   (0,0),  (-1,-1), 3),
        ('BOTTOMPADDING',(0,0),  (-1,-1), 3),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [colors.HexColor("#fafafa"), colors.white]),
        ('WORDWRAP',     (0,0),  (-1,-1), True),
    ])

    risk_col_idx = cols.index('risk_level') if 'risk_level' in cols else -1
    for i, row in enumerate(df.head(40).itertuples(), start=1):
        if risk_col_idx >= 0:
            lvl = getattr(row, 'risk_level', 'LOW')
            bg  = risk_palette.get(lvl, colors.white)
            ts.add('BACKGROUND', (risk_col_idx, i), (risk_col_idx, i), bg)
            ts.add('TEXTCOLOR',  (risk_col_idx, i), (risk_col_idx, i),
                   colors.white if lvl in ("CRITICAL","HIGH") else colors.black)

    tx_table.setStyle(ts)
    elements.append(tx_table)
    elements.append(Spacer(1, 14))

    # Risk flag summary
    elements.append(Paragraph("Intelligence Flags", h1_style))
    flagged = df[df['risk_level'].isin(['CRITICAL', 'HIGH'])].head(20)
    for _, row in flagged.iterrows():
        lvl   = row.get('risk_level','')
        score = row.get('risk_score', 0)
        amt   = row.get('amount', 0)
        frm   = str(row.get('from_address',''))[:40]
        to    = str(row.get('to_address',''))[:40]
        rsn   = str(row.get('risk_reasons',''))
        color = colors.HexColor("#ff4444") if lvl == "CRITICAL" else colors.HexColor("#ff8800")
        elements.append(Paragraph(
            f'<font color="#{color.hexval()[2:]}" size="9"><b>[{lvl}] Score {score}/100</b></font> — '
            f'{frm} → {to} | ${amt:,.2f} | {rsn}',
            body_style
        ))

    elements.append(Spacer(1, 14))

    # AI analysis
    if ai_analysis:
        elements.append(Paragraph("AI Forensics Analysis (Claude)", h1_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#444"), spaceAfter=8))
        for para in ai_analysis.split('\n\n'):
            if para.strip():
                elements.append(Paragraph(para.strip(), body_style))
                elements.append(Spacer(1, 6))

    # Footer
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    elements.append(Paragraph(
        "CONFIDENTIAL — For authorized investigative use only. "
        "This report is generated by automated analysis and should be verified by a qualified analyst.",
        ParagraphStyle('footer', parent=styles['Normal'], fontSize=7, textColor=colors.grey)
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer


# ─────────────────────────────────────────────────────────────
# HIGHLIGHT RISK TABLE
# ─────────────────────────────────────────────────────────────
def highlight_risk(val):
    colors_map = {
        "CRITICAL": "background-color:#ff4444;color:white;font-weight:bold",
        "HIGH":     "background-color:#ff8800;color:white;font-weight:bold",
        "MEDIUM":   "background-color:#ffcc00;color:#333;font-weight:bold",
        "LOW":      "background-color:#22c55e;color:white",
    }
    return colors_map.get(val, "")


# ═════════════════════════════════════════════════════════════
# MAIN APP
# ═════════════════════════════════════════════════════════════

# ── On-chain lookup (sidebar-triggered) ──────────────────────
if (st.session_state.get("do_lookup") or st.session_state.get("do_lookup_both")) and lookup_address_input:
    st.session_state.do_lookup = False
    st.session_state.do_lookup_both = False

    with st.expander("🔍 On-chain Address Lookup", expanded=True):
        # Validate address
        is_valid, msg = validate_address(lookup_address_input, lookup_chain_select)
        if not is_valid:
            st.error(f"Address validation failed: {msg}")
        else:
            st.success(msg)

            # Get the appropriate API key based on chain selection.
            # Always use get_key() — pulls from session_state, which is seeded
            # from secrets.toml at startup and updated live by the sidebar widgets.
            CHAIN_KEY_MAP = {
                "ethereum":  "etherscan_key",
                "bsc":       "bscscan_key",
                "polygon":   "polygonscan_key",
                "avalanche": "snowtrace_key",
                "fantom":    "ftmscan_key",
                "arbitrum":  "arbiscan_key",
                "optimism":  "optimismscan_key",
                "tron":      "tron_key",
                "bitcoin":   "",   # Bitcoin APIs are keyless
            }
            key_name  = CHAIN_KEY_MAP.get(lookup_chain_select, "")
            chain_key = get_key(key_name) if key_name else ""
            if not chain_key and lookup_chain_select != "bitcoin":
                st.warning(
                    f"No API key found for **{lookup_chain_select}**. "
                    f"Add `{key_name}` to `.streamlit/secrets.toml` or paste it "
                    f"into the 🔑 Manage API Keys panel in the sidebar."
                )

            # Fetch data with API key
            with st.spinner(f"Fetching {lookup_chain_select.upper()} data for {lookup_address_input[:16]}..."):
                result = lookup_address(lookup_address_input, lookup_chain_select, include_tokens=True, api_key=chain_key)

            if result["success"]:
                st.success(f"✅ Loaded {result['total_txs']} transactions")
                st.info(f"**Sources:** {', '.join(result['sources'])}")

                # Combine all transactions
                all_txs = pd.concat([result['native_txs'], result['token_txs']], ignore_index=True)

                if not all_txs.empty:
                    st.dataframe(all_txs.head(5000), use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)

                    if st.button("➕ Add to dataset"):
                        if "loaded_data" not in st.session_state:
                            st.session_state.loaded_data = all_txs
                        else:
                            st.session_state.loaded_data = pd.concat(
                                [st.session_state.loaded_data, all_txs], ignore_index=True
                            )
                        st.success("Data added to dataset!")
                        st.rerun()
            else:
                st.error(f"Lookup failed: {', '.join(result['errors'])}")


# ── Data loading with session_state persistence ──────────────
#
# ROOT CAUSE OF BLANK-PAGE BUG:
#   When a sidebar nav button fires st.rerun(), Streamlit re-executes
#   the script from the top. uploaded_file becomes None (file not
#   re-uploaded), so df = None, and every page renders blank.
#
# FIX:
#   1. When new data arrives (upload / sample / on-chain), store the
#      RAW dataframe in st.session_state.raw_df and clear processed_df.
#   2. Run the expensive pipeline once and save to st.session_state.processed_df.
#   3. On every subsequent rerun (nav clicks, widget changes), skip
#      straight to processed_df — no reprocessing, instant page switch.
# ─────────────────────────────────────────────────────────────

def _detect_new_source() -> bool:
    """Return True if a genuinely new data source was provided this run."""
    global uploaded_file
    if uploaded_file is not None:
        # Hash by name + size so re-uploading the same file still triggers a refresh
        fhash = f"{uploaded_file.name}_{uploaded_file.size}"
        if st.session_state.get("_src_hash") != fhash:
            st.session_state._src_hash = fhash
            raw = pd.read_csv(uploaded_file)
            st.session_state.raw_df = raw
            st.session_state.pop("processed_df", None)
            return True
        return False

    if st.session_state.pop("sample", False):
        st.session_state.raw_df = pd.read_csv(io.StringIO(SAMPLE_BSC))
        st.session_state._src_hash = "sample_bsc"
        st.session_state.pop("processed_df", None)
        return True

    if st.session_state.pop("sample_btc", False):
        st.session_state.raw_df = pd.read_csv(io.StringIO(SAMPLE_BTC))
        st.session_state._src_hash = "sample_btc"
        st.session_state.pop("processed_df", None)
        return True

    # On-chain lookup data written by the lookup block
    if "live_df" in st.session_state:
        live_hash = f"live_{len(st.session_state.live_df)}"
        if st.session_state.get("_src_hash") != live_hash:
            st.session_state._src_hash = live_hash
            st.session_state.raw_df = st.session_state.live_df
            st.session_state.pop("processed_df", None)
            return True

    return False

_detect_new_source()   # check and store raw data if anything new arrived

# ── Process raw → processed (only when needed) ────────────────
if "processed_df" not in st.session_state and "raw_df" in st.session_state:
    _raw = st.session_state.raw_df
    prog_bar = st.progress(0, text="Loading data…")
    prog_bar.progress(10, text="Normalizing columns…")
    _df = normalize_dataframe(_raw)
    prog_bar.progress(40, text=f"Scoring risk on {len(_df):,} transactions…")
    _df = calculate_risk_vectorized(_df)
    prog_bar.progress(80, text="Running ML anomaly detection…")
    _df = detect_anomalies(_df)
    prog_bar.progress(100, text="Done ✅")
    prog_bar.empty()
    st.session_state.processed_df = _df   # ← persists across all reruns

# ── All pages read from session_state — never None after first load ──
df = st.session_state.get("processed_df", None)

if df is not None:
    st.caption(
        f"✅ {len(df):,} transactions loaded · "
        f"🔴 {(df['risk_level']=='CRITICAL').sum()} critical · "
        f"🟠 {(df['risk_level']=='HIGH').sum()} high · "
        f"⚠️ {df['is_anomaly'].sum()} anomalies"
    )
    if _OPTIONAL_MISSING:
        with st.sidebar.expander("⚠️ Optional modules not found", expanded=False):
            st.caption(
                "These feature files are missing from your app folder. "
                "Download them from the session and place them next to CryptoAnalyzerApp.py:"
            )
            for _m in _OPTIONAL_MISSING:
                st.code(f"{_m}.py")

    # ── Page-based navigation (sidebar buttons set st.session_state.nav_page) ──
    page = st.session_state.get('nav_page', '📊 Overview')
    st.markdown(f'## {page}')
    st.divider()


    # ── TAB 1: Overview ──────────────────────────────────────
    if page == '📊 Overview':
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Transactions", len(df))
        c2.metric("Total Volume",       f"${df['amount'].sum():,.2f}")
        c3.metric("Critical",           len(df[df['risk_level'] == 'CRITICAL']),
                  delta="⚠️ flags" if len(df[df['risk_level'] == 'CRITICAL']) else None,
                  delta_color="inverse")
        c4.metric("High Risk",          len(df[df['risk_level'] == 'HIGH']))
        c5.metric("ML Anomalies",       len(df[df['is_anomaly']]))

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("**Risk Distribution**")
            risk_counts = df['risk_level'].value_counts().reset_index()
            risk_counts.columns = ['Risk Level', 'Count']
            fig_pie = px.pie(risk_counts, names='Risk Level', values='Count',
                             color='Risk Level',
                             color_discrete_map={"CRITICAL":"#ff4444","HIGH":"#ff8800",
                                                 "MEDIUM":"#ffcc00","LOW":"#22c55e"})
            fig_pie.update_layout(height=300, margin=dict(t=10,b=10))
            st.plotly_chart(fig_pie, use_container_width=True)

        with col_b:
            st.markdown("**Volume by Token**")
            vol_token = df.groupby('token')['amount'].sum().reset_index().nlargest(8, 'amount')
            fig_bar = px.bar(vol_token, x='token', y='amount',
                             color='amount', color_continuous_scale='Reds')
            fig_bar.update_layout(height=300, margin=dict(t=10,b=10))
            st.plotly_chart(fig_bar, width=True)

        # Top flagged addresses
        st.markdown("**Top Flagged Addresses**")
        addr_risk = pd.concat([
            df[['from_address','risk_score']].rename(columns={'from_address':'address'}),
            df[['to_address','risk_score']].rename(columns={'to_address':'address'})
        ]).groupby('address')['risk_score'].max().reset_index().nlargest(10, 'risk_score')
        st.dataframe(addr_risk, use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)

    # ── TAB 2: Transactions ──────────────────────────────────
    elif page == '📋 Transactions':
        st.subheader("Color-Coded Transaction Ledger")

        # Filters
        fc1, fc2, fc3, fc4 = st.columns([2, 2, 2, 1])
        with fc1:
            risk_filter = st.multiselect("Risk", ["CRITICAL","HIGH","MEDIUM","LOW"],
                                          default=["CRITICAL","HIGH","MEDIUM","LOW"])
        with fc2:
            min_amt = st.number_input("Min Amount ($)", value=0.0, step=1000.0)
        with fc3:
            token_opts = df['token'].unique().tolist()
            token_filter = st.multiselect("Token", token_opts, default=token_opts)
        with fc4:
            page_size = st.selectbox("Rows/page", [50, 100, 250, 500], index=0)

        filtered = df[
            df['risk_level'].isin(risk_filter) &
            (df['amount'] >= min_amt) &
            df['token'].isin(token_filter)
        ].reset_index(drop=True)

        total_pages = max(1, (len(filtered) - 1) // page_size + 1)

        # Page selector
        pcol1, pcol2, pcol3 = st.columns([1, 2, 1])
        with pcol2:
            page = st.number_input(
                f"Page (1 – {total_pages})",
                min_value=1, max_value=total_pages, value=1, step=1
            )

        start = (page - 1) * page_size
        end   = start + page_size
        page_df = filtered.iloc[start:end]

        display_cols = ['date','from_address','to_address','amount','token',
                        'chain','risk_level','risk_score','risk_reasons','is_anomaly']
        display_cols = [c for c in display_cols if c in page_df.columns]

        # Only style the page slice — styling 15k rows at once is slow
        styled = page_df[display_cols].style.map(
            highlight_risk, subset=['risk_level']
        ).format({'amount': '${:,.2f}', 'risk_score': '{:.0f}'})

        st.dataframe(styled, use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)
        st.caption(
                f"Showing rows {start+1}–{min(end, len(filtered))} "
                f"of {len(filtered):,} filtered  |  {len(df):,} total  |  "
                f"Page {page}/{total_pages}"
        )

        # Download filtered set
        csv_bytes = filtered[display_cols].to_csv(index=False).encode()
        st.download_button(
                "⬇️ Download filtered CSV",
                csv_bytes,
                f"forensics_filtered_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                "text/csv",
        )

    # ── Sankey Flow ───────────────────────────────────────
    elif page == '💸 Sankey Flow':
        st.subheader("💸 Fund Flow Sankey Diagram")
        st.caption(
            "Shows fund flows between top addresses. Node colour = risk level. "
            "Link colour = source risk. Hover for address details."
        )

        top_n = st.slider("Max flows to display", 5, 100, 20, key="sankey_top_n")

        # Auto-generate on first visit; regenerate when slider changes or button clicked
        sankey_key = f"sankey_fig_{top_n}_{len(df)}"
        if st.button("🔄 Generate / Refresh Sankey", type="primary", key="gen_sankey") or                 "sankey_fig" not in st.session_state or                 st.session_state.get("sankey_key") != sankey_key:

            with st.spinner("Building Sankey diagram…"):
                fig_s = create_sankey(df, top_n)

            if fig_s is not None:
                st.session_state.sankey_fig = fig_s
                st.session_state.sankey_key = sankey_key
            else:
                st.session_state.pop("sankey_fig", None)
                st.warning(
                    "Not enough data to generate Sankey. "
                    "Dataset needs at least 2 unique addresses with transactions between them."
                )

        # Render from session_state — survives nav clicks and reruns
        if "sankey_fig" in st.session_state:
            try:
                st.plotly_chart(
                    st.session_state.sankey_fig,
                    width=True,
                    config={"displayModeBar": True, "scrollZoom": False},
                )
            except Exception as e:
                st.error(f"Sankey render error: {e}")
                st.info(
                    "If this error persists on Streamlit Cloud, check that plotly>=5.0.0 "
                    "is in your requirements.txt"
                )

    # ── TAB 4: Timeline ──────────────────────────────────────
    elif page == '📅 Timeline':
        st.subheader("📅 Transaction Timeline")
        fig_tl = create_timeline(df)
        if fig_tl:
            st.plotly_chart(fig_tl, width=True)
        else:
            st.info("No date column detected in dataset.")

        # Volume over time bar
        if df['date'].notna().any():
            df_dated = df.dropna(subset=['date']).copy()
            df_dated['week'] = df_dated['date'].dt.to_period('W').astype(str)
            weekly = df_dated.groupby('week')['amount'].sum().reset_index()
            fig_weekly = px.bar(weekly, x='week', y='amount', title="Weekly Volume")
            fig_weekly.update_layout(height=280)
            st.plotly_chart(fig_weekly, width=True)

    # ── TAB 5: Multi-hop ─────────────────────────────────────
    elif page == '🔗 Multi-hop Tracer':
        st.subheader("🔗 Multi-hop Fund Tracing (Up to 20 Hops)")
        st.caption("Advanced tracing using HopTracer engine - trace funds forward, backward, or both directions")

        col_h1, col_h2, col_h3 = st.columns([2, 1, 1])
        with col_h1:
            start_addr = st.text_input("Starting Address", placeholder="0x... or 1A1zP...")
        with col_h2:
            max_hops = st.selectbox("Max Hops", [5, 10, 15, 20], index=1)
        with col_h3:
            trace_direction = st.selectbox("Direction", ["Forward", "Backward", "Both"])

        col_trace1, col_trace2, col_trace3 = st.columns(3)
        with col_trace1:
            if st.button("🔍 Trace", type="primary", use_container_width=True) and start_addr:
                with st.spinner(f"Tracing {trace_direction.lower()} up to {max_hops} hops…"):
                    tracer = HopTracer(
                        df,
                        max_hops=max_hops,
                        max_addresses_per_hop=100
                    )

                    if trace_direction == "Forward":
                        trace_result = tracer.trace_forward(start_addr)
                    elif trace_direction == "Backward":
                        trace_result = tracer.trace_backward(start_addr)
                    else:
                        trace_result = tracer.trace_both_directions(start_addr)

                    st.session_state.trace_result = trace_result
                    st.session_state.tracer = tracer

        if "trace_result" in st.session_state:
            trace_result = st.session_state.trace_result
            tracer = st.session_state.tracer

            # Summary
            st.markdown(tracer.get_trace_summary(trace_result))

            # Tabs for results
            result_tabs = st.tabs(["Summary", "Hop Details", "Address Risk", "Visual"])

            with result_tabs[0]:
                st.info("Trace completed successfully!")

            with result_tabs[1]:
                if "forward" in trace_result:
                    fwd_tabs = st.tabs(["Forward Hops", "Backward Hops"])
                    with fwd_tabs[0]:
                        for hop_num, txs in trace_result["forward"]["hops"].items():
                            with st.expander(f"Hop {hop_num} ({len(txs)} txs)", expanded=hop_num==1):
                                hop_df = pd.DataFrame(txs)
                                styled = hop_df.style.map(highlight_risk, subset=['risk_level'])
                                st.dataframe(styled, use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)
                    with fwd_tabs[1]:
                        for hop_num, txs in trace_result["backward"]["hops"].items():
                            with st.expander(f"Hop {hop_num} ({len(txs)} txs)", expanded=hop_num==1):
                                hop_df = pd.DataFrame(txs)
                                styled = hop_df.style.map(highlight_risk, subset=['risk_level'])
                                st.dataframe(styled, use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)
                else:
                    for hop_num, txs in trace_result["hops"].items():
                        with st.expander(f"Hop {hop_num} ({len(txs)} txs)", expanded=hop_num==1):
                            hop_df = pd.DataFrame(txs)
                            styled = hop_df.style.map(highlight_risk, subset=['risk_level'])
                            st.dataframe(styled, use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)

            with result_tabs[2]:
                addr_summary = tracer.get_address_risk_summary(trace_result)
                st.dataframe(addr_summary, width=True)

            with result_tabs[3]:
                # Create Sankey from trace
                all_txs_list = []
                if "forward" in trace_result:
                    for hops_list in list(trace_result["forward"]["hops"].values()) + list(trace_result["backward"]["hops"].values()):
                        all_txs_list.extend(hops_list)
                else:
                    for hops_list in trace_result["hops"].values():
                        all_txs_list.extend(hops_list)

                if all_txs_list:
                    trace_df = pd.DataFrame(all_txs_list)
                    fig_trace = create_sankey(trace_df, top_n=50)
                    if fig_trace:
                        st.plotly_chart(fig_trace, width=True)

    # ── TAB 6: AI Analysis ───────────────────────────────────
    elif page == '🤖 Claude AI':
        st.subheader("🤖 Claude AI Forensics Analysis")

        extra_ctx = st.text_area("Additional context for Claude (optional)",
                                  placeholder="e.g. 'This is a SAR investigation for case #2024-XXX. Focus on the Tornado Cash flows.'",
                                  height=80)

        col_ai1, col_ai2 = st.columns(2)
        with col_ai1:
            run_ai = st.button("▶ Run Claude Analysis", type="primary",
                                disabled=not bool(get_key("anthropic_key")))
            if not get_key("anthropic_key"):
                st.caption("Enter Anthropic API key in the 🔑 Manage API Keys panel in the sidebar.")

        if run_ai and get_key("anthropic_key"):
            with st.spinner("Claude is analyzing your transactions…"):
                result = run_claude_analysis(df, get_key("anthropic_key"), extra_ctx)
                st.session_state.ai_result = result

        if "ai_result" in st.session_state:
            st.markdown("---")
            st.markdown(st.session_state.ai_result)

            # Quick action buttons
            st.markdown("---")
            st.markdown("**Quick follow-up prompts:**")
            qa_cols = st.columns(3)
            with qa_cols[0]:
                if st.button("📋 Draft SAR Narrative"):
                    with st.spinner("Drafting SAR…"):
                        sar = run_claude_analysis(df, get_key("anthropic_key"),
                                                   "Focus ONLY on writing a complete SAR narrative paragraph "
                                                   "suitable for FinCEN submission. Include all mandatory fields.")
                        st.markdown("**SAR Narrative:**")
                        st.markdown(sar)
            with qa_cols[1]:
                if st.button("🔎 OFAC Screen"):
                    addrs = list(set(df['from_address'].tolist() + df['to_address'].tolist()))[:30]
                    with st.spinner("Screening addresses…"):
                        ofac_result = run_claude_analysis(df, get_key("anthropic_key"),
                                                           f"Check these addresses against OFAC SDN list characteristics "
                                                           f"and known sanctioned entities:\n{json.dumps(addrs)}")
                        st.markdown(ofac_result)
            with qa_cols[2]:
                if st.button("📊 Typology Report"):
                    with st.spinner("Generating typology report…"):
                        typo = run_claude_analysis(df, get_key("anthropic_key"),
                                                    "Focus on identifying specific FATF/FinCEN money laundering "
                                                    "typologies: layering, smurfing, chain-hopping, mixing. "
                                                    "Map each typology to specific transactions with amounts.")
                        st.markdown(typo)

    # ── TAB 7: PDF ───────────────────────────────────────────
    elif page == '📄 PDF Report':
        render_full_pdf_ui(df)

    # ── TAB 8: Configuration ─────────────────────────────────
    elif page == '⚙️ Configuration':
        st.subheader("⚙️ App Configuration & API Status")

        # ── Live API key status table ─────────────────────────
        st.markdown("### API Key Status")
        st.caption(
                "Keys are loaded in priority order: "
                "**secrets.toml** → **sidebar entry** → not set. "
                "Green = active and ready. Red = missing."
        )

        KEY_DISPLAY = [
            ("anthropic_key",    "Anthropic (Claude)",   "https://console.anthropic.com",      "AI forensics analysis"),
            ("etherscan_key",    "Etherscan (ETH)",       "https://etherscan.io/apis",           "Ethereum on-chain data"),
            ("bscscan_key",      "BscScan (BNB)",         "https://bscscan.com/apis",            "BSC on-chain data"),
            ("polygonscan_key",  "PolygonScan (MATIC)",   "https://polygonscan.com/apis",        "Polygon on-chain data"),
            ("snowtrace_key",    "Snowtrace (AVAX)",      "https://snowtrace.io/apis",           "Avalanche on-chain data"),
            ("ftmscan_key",      "FTMScan (FTM)",         "https://ftmscan.com/apis",            "Fantom on-chain data"),
            ("arbiscan_key",     "Arbiscan (ARB)",        "https://arbiscan.io/apis",            "Arbitrum on-chain data"),
            ("optimismscan_key", "Optimism Scan",         "https://optimistic.etherscan.io/apis","Optimism on-chain data"),
            ("bitquery_key",     "Bitquery",              "https://bitquery.io",                 "Multi-chain GraphQL"),
            ("breadcrumbs_key",  "Breadcrumbs",           "https://breadcrumbs.app",             "Address profiling"),
            ("tron_key",          "Tron",                 "https://apilist.tronscanapi.com/api", "Tron on-chain data"),
        ]

        rows = []
        for key_name, label, signup_url, purpose in KEY_DISPLAY:
            val         = get_key(key_name)
            from_secret = bool(_read_secret(key_name))
            rows.append({
                "Service":    label,
                "Status":     "✅ Ready"        if val else "❌ Not set",
                "Source":     "secrets.toml"    if from_secret and val
                              else "Sidebar entry" if val
                              else "—",
                "Purpose":    purpose,
                "Get Key":    signup_url,
            })

        status_df = pd.DataFrame(rows)
        st.dataframe(
                status_df.style.map(
                    lambda v: "color:green;font-weight:bold" if "✅" in str(v)
                              else "color:red" if "❌" in str(v) else "",
                    subset=["Status"]
                ),
                width=True,
                hide_index=True,
        )

        ready   = sum(1 for r in rows if "✅" in r["Status"])
        missing = len(rows) - ready
        if missing == 0:
            st.success("All API keys configured ✅")
        else:
            st.warning(
                f"{ready}/{len(rows)} keys configured. "
                f"Add missing keys to `.streamlit/secrets.toml` (preferred) "
                f"or via the 🔑 panel in the sidebar."
            )

        # ── secrets.toml help ────────────────────────────────
        st.markdown("### secrets.toml Setup")
        col_path, col_tip = st.columns([1, 2])
        with col_path:
            st.markdown("**File location:**")
            st.code(
"""YourApp/
├── CryptoAnalyzerApp.py
├── blockchain_apis.py
├── hop_tracer.py
└── .streamlit/
    └── secrets.toml""",
                language="text",
            )
        with col_tip:
            st.markdown("**Common reasons keys don't load:**")
            st.markdown("""
- ❌ `secrets.toml` is in the wrong folder
- ❌ Key names don't match exactly (case-sensitive)
- ❌ Values not quoted: use `key = "value"` not `key = value`
- ❌ Keys nested under a section: use top-level flat keys
- ❌ App not restarted after editing the file
""")

        st.markdown("**Full secrets.toml template:**")
        st.code("""# .streamlit/secrets.toml  — flat top-level keys, no sections needed

anthropic_key    = "YOUR_ANTHROPIC_KEY"
etherscan_key    = "YOUR_ETHERSCAN_KEY"
bscscan_key      = "YOUR_BSCSCAN_KEY"
polygonscan_key  = "YOUR_POLYGONSCAN_KEY"
snowtrace_key    = "YOUR_SNOWTRACE_KEY"
ftmscan_key      = "YOUR_FTMSCAN_KEY"
arbiscan_key     = "YOUR_ARBISCAN_KEY"
optimismscan_key = "YOUR_OPTIMISM_KEY"
bitquery_key     = "YOUR_BITQUERY_KEY"
breadcrumbs_key  = "YOUR_BREADCRUMBS_KEY"
""", language="toml")

        # ── TAB 9: EXPORT & SHARE ──────────────────────────────────

        # ── Current dataset summary ───────────────────────────
        st.divider()
        st.markdown('### 📂 Current Dataset')
        _dc1, _dc2, _dc3, _dc4 = st.columns(4)
        _dc1.metric('Transactions',     len(df))
        _dc2.metric('Total Volume',     f"${df['amount'].sum():,.2f}")
        _dc3.metric('Unique Addresses', len(set(df['from_address'].tolist() + df['to_address'].tolist())))
        _dc4.metric('Chains',           df['chain'].nunique())
        if df['date'].notna().any():
            st.caption(f"Date range: {df['date'].min()} → {df['date'].max()}")

    elif page == '📤 Export & SIEM':
        st.subheader("📤 Export & Share Findings")

        export_tabs = st.tabs([
            "📋 JSON Alert", "📊 CSV Reports", "📄 PDF Report",
            "📧 Email Alert", "🔗 SIEM Export"
        ])

        # Collect findings from session state
        findings = {
            "clusters": st.session_state.get("cluster_profiles", []),
            "circular_flows": st.session_state.get("circular_flows", []),
            "anomalies": st.session_state.get("behavioral_anomalies", []),
            "mixers": st.session_state.get("mixer_candidates", []),
        }

        has_findings = any(findings.values())

        # ── JSON ALERT ──────────────────────────────────────────
        with export_tabs[0]:
            st.markdown("### JSON Alert Export")
            st.caption("Structured format for automation, API integration, SIEM webhooks")

            col_json1, col_json2 = st.columns(2)
            with col_json1:
                case_id_json = st.text_input("Case ID", value="FORENSICS_" + datetime.now().strftime('%Y%m%d_%H%M'))
                investigator_json = st.text_input("Investigator Name", value="Crypto Forensics Analyzer")
            with col_json2:
                severity_filter_json = st.slider("Min Severity to Include", 0, 100, 50)

            if st.button("📥 Generate JSON", type="primary", key="json_export") and has_findings:
                with st.spinner("Generating JSON export..."):
                    json_bytes = export_alerts_json(
                        clusters=findings["clusters"],
                        circular_flows=findings["circular_flows"],
                        anomalies=findings["anomalies"],
                        mixers=findings["mixers"],
                        case_id=case_id_json,
                        investigator=investigator_json
                    )

                st.download_button(
                    label="⬇️ Download JSON",
                    data=json_bytes,
                    file_name=f"forensics_alert_{case_id_json}.json",
                    mime="application/json",
                    type="primary"
                )

                # Preview
                with st.expander("👁️ Preview JSON Structure", expanded=False):
                    st.code(json_bytes.decode('utf-8')[:1500] + "...", language="json")
            elif not has_findings:
                st.warning("⚠️ No findings detected. Run pattern analysis first.")

        # ── CSV REPORTS ─────────────────────────────────────────
        with export_tabs[1]:
            st.markdown("### CSV Reports Export")
            st.caption("Multi-sheet ZIP with clusters, flows, anomalies, mixers")

            st.info(
                "📊 Includes:\n"
                "- clusters.csv: Address groupings and profiles\n"
                "- circular_flows.csv: Suspicious cycle transactions\n"
                "- behavioral_anomalies.csv: Address behavior shifts\n"
                "- mixer_candidates.csv: Mixer/tumbler patterns"
            )

            if st.button("📥 Generate CSV ZIP", type="primary", key="csv_export") and has_findings:
                with st.spinner("Generating CSV reports..."):
                    csv_zip = export_alerts_csv(
                        clusters=findings["clusters"],
                        circular_flows=findings["circular_flows"],
                        anomalies=findings["anomalies"],
                        mixers=findings["mixers"]
                    )

                st.download_button(
                    label="⬇️ Download CSV ZIP",
                    data=csv_zip,
                    file_name=f"forensics_reports_{datetime.now().strftime('%Y%m%d_%H%M')}.zip",
                    mime="application/zip",
                    type="primary"
                )

                # Summary
                col_csv1, col_csv2, col_csv3, col_csv4 = st.columns(4)
                col_csv1.metric("Clusters", len(findings["clusters"]))
                col_csv2.metric("Flows", len(findings["circular_flows"]))
                col_csv3.metric("Anomalies", len(findings["anomalies"]))
                col_csv4.metric("Mixers", len(findings["mixers"]))
            elif not has_findings:
                st.warning("⚠️ No findings detected. Run pattern analysis first.")

        # ── PDF REPORT ──────────────────────────────────────────
        with export_tabs[2]:
            st.markdown("### Professional PDF Alert Report")
            st.caption("Landscape format, suitable for regulatory submission and briefings")

            col_pdf1, col_pdf2 = st.columns(2)
            with col_pdf1:
                case_id_pdf = st.text_input("Case ID", value="FORENSICS_" + datetime.now().strftime('%Y%m%d_%H%M'),
                                            key="pdf_case")
                investigator_pdf = st.text_input("Investigator", value="Crypto Forensics Analyzer",
                                                 key="pdf_invest")
            with col_pdf2:
                institution_pdf = st.text_input("Institution", value="Compliance Department")

            if st.button("📥 Generate Full Investigation PDF", type="primary", key="pdf_export"):
                with st.spinner("Building comprehensive PDF — all analysis sections…"):
                    pdf_buf = generate_full_report(df, case_id=case_id_pdf, analyst=investigator_pdf)
                st.download_button(
                    label="⬇️ Download Full Investigation Report",
                    data=pdf_buf.getvalue(),
                    file_name=f"investigation_{case_id_pdf}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    type="primary",
                )
                st.success("✅ Report generated — includes all analysis modules that have been run.")

        # ── EMAIL ALERT ─────────────────────────────────────────
        with export_tabs[3]:
            st.markdown("### Email Alert Template")
            st.caption("Generate HTML email for stakeholder notification")

            col_email1, col_email2 = st.columns(2)
            with col_email1:
                email_recipient = st.text_input("Recipient Email", value="security@institution.com")
                email_case = st.text_input("Case ID", value="FORENSICS_" + datetime.now().strftime('%Y%m%d'),
                                           key="email_case")
            with col_email2:
                email_cc = st.text_input("CC (comma-separated, optional)", value="")

            if st.button("📧 Generate Email", type="primary", key="email_export") and has_findings:
                email_template = generate_email_alert(
                    clusters=findings["clusters"],
                    circular_flows=findings["circular_flows"],
                    anomalies=findings["anomalies"],
                    mixers=findings["mixers"],
                    recipient=email_recipient,
                    case_id=email_case
                )

                st.session_state.email_template = email_template

            if "email_template" in st.session_state:
                template = st.session_state.email_template

                st.markdown("#### Email Details")
                col_email_detail1, col_email_detail2 = st.columns(2)
                with col_email_detail1:
                    st.write(f"**To:** {template['to']}")
                    if email_cc:
                        st.write(f"**CC:** {email_cc}")
                with col_email_detail2:
                    st.write(f"**Subject:** {template['subject']}")

                st.divider()

                # Show HTML preview
                with st.expander("👁️ Preview Email HTML", expanded=False):
                    st.markdown(template["body_html"], unsafe_allow_html=True)

                # Show text version
                with st.expander("📝 Text Version", expanded=False):
                    st.code(template["body_text"])

                # Copy buttons
                col_copy1, col_copy2, col_copy3 = st.columns(3)
                with col_copy1:
                    st.code(f"To: {template['to']}\nSubject: {template['subject']}\n\n{template['body_text']}")

                st.info(
                    "💡 **To Send Email:**\n"
                    "1. Copy the text above\n"
                    "2. Paste into your email client\n"
                    "3. Or integrate with email API (Gmail, O365, etc.)"
                )
            elif not has_findings:
                st.warning("⚠️ No findings detected. Run pattern analysis first.")

        # ── SIEM EXPORT ─────────────────────────────────────────
        with export_tabs[4]:
            st.markdown("### SIEM/SOAR Integration (CEF Format)")
            st.caption("Common Event Format for Splunk, ArcSight, QRadar, Sentinel")

            col_siem1, col_siem2 = st.columns(2)
            with col_siem1:
                severity_threshold_siem = st.slider("Min Severity for Events", 0, 100, 60)
            with col_siem2:
                siem_platform = st.selectbox(
                    "SIEM Platform",
                    ["Generic CEF", "Splunk", "ArcSight", "QRadar", "Azure Sentinel", "Elastic"]
                )

            if st.button("🔗 Generate SIEM Events", type="primary", key="siem_export") and has_findings:
                with st.spinner("Generating CEF events..."):
                    cef_events = export_to_siem(
                        clusters=findings["clusters"],
                        circular_flows=findings["circular_flows"],
                        anomalies=findings["anomalies"],
                        mixers=findings["mixers"],
                        severity_threshold=severity_threshold_siem
                    )

                st.session_state.cef_events = cef_events
                event_count = len(cef_events.split('\n'))
                st.success(f"✅ Generated {event_count} CEF events")

            if "cef_events" in st.session_state:
                cef_events = st.session_state.cef_events

                st.markdown("#### CEF Events (Ready to Forward)")
                st.code(cef_events, language="text")

                # Download
                st.download_button(
                    label="⬇️ Download CEF Events",
                    data=cef_events.encode('utf-8'),
                    file_name=f"forensics_cef_{datetime.now().strftime('%Y%m%d_%H%M')}.log",
                    mime="text/plain"
                )

                # Platform-specific instructions
                st.divider()
                st.markdown("#### Integration Instructions")

                if siem_platform == "Splunk":
                    st.code("""
        # Forward to Splunk HTTP Event Collector:
        curl -k https://your-splunk-hec:8088/services/collector \\
          -H "Authorization: Splunk your-hec-token" \\
          -d 'event=' + CEF_EVENT
                        """)
                elif siem_platform == "ArcSight":
                    st.code("""
        # Forward to ArcSight CEF Syslog:
        syslog-forward.py --host=arcsight.company.com --port=514 --events=forensics_cef.log
                        """)
                elif siem_platform == "QRadar":
                    st.code("""
        # Add to QRadar Log Source:
        1. Admin → Data Sources → Log Sources
        2. Add new Syslog source
        3. Point to CEF events file
        4. Set parser to "CEF"
                        """)
                else:
                    st.info("Refer to your SIEM documentation for CEF ingestion")
            elif not has_findings:
                st.warning("⚠️ No findings detected. Run pattern analysis first.")

        st.divider()
        st.markdown("### 📊 Export Summary")

        col_summary1, col_summary2, col_summary3, col_summary4 = st.columns(4)
        col_summary1.metric("Total Clusters", len(findings["clusters"]))
        col_summary2.metric("Total Flows", len(findings["circular_flows"]))
        col_summary3.metric("Total Anomalies", len(findings["anomalies"]))
        col_summary4.metric("Total Mixers", len(findings["mixers"]))

    # ── TAB 10: PATTERN INTEL ─────────────────────────────────
    # Brings forensics_patterns.py to life — was never wired up before
    elif page == '🧩 Pattern Intel':
        st.subheader("🧩 Pattern Intelligence")
        st.caption("Address clustering · Circular flows · Mixer detection · Behavioral anomalies · Structuring · Peeling chains · Cross-chain · Stablecoin analysis")

        run_col, opt_col = st.columns([2,3])
        with run_col:
            run_patterns = st.button("▶ Run Full Pattern Analysis", type="primary",
                                     help="Runs all detection engines on the loaded dataset")
        with opt_col:
            struct_window = st.number_input("Structuring window (hrs)", 1, 168, 24, key="struct_win")
            min_chain_hop = st.number_input("Min amount for cross-chain ($)", 100, 1_000_000, 1000, key="cc_min")

        if run_patterns:
            with st.spinner("Running pattern engines…"):
                p_prog = st.progress(0)

                p_prog.progress(10, "Clustering addresses…")
                clusters_raw = cluster_addresses_by_behavior(df)
                clusters     = analyze_cluster_characteristics(df, clusters_raw)

                p_prog.progress(25, "Detecting circular flows…")
                circular = detect_circular_flows(df)

                p_prog.progress(40, "Scanning behavioral anomalies…")
                anomalies = detect_behavioral_anomalies(df)

                p_prog.progress(55, "Fingerprinting mixers…")
                mixers = detect_mixer_patterns(df)

                p_prog.progress(65, "Detecting structuring…")
                structuring = detect_structuring(df, time_window_hours=int(struct_window))

                p_prog.progress(75, "Detecting peeling chains…")
                peeling = detect_peeling_chains(df)

                p_prog.progress(85, "Cross-chain correlation…")
                cross_chain = detect_cross_chain_hops(df, min_amount=float(min_chain_hop))

                p_prog.progress(95, "Stablecoin analysis…")
                stable = analyze_stablecoin_flows(df)

                p_prog.progress(100)
                p_prog.empty()

                st.session_state.pattern_results = {
                    "clusters": clusters, "circular": circular,
                    "anomalies": anomalies, "mixers": mixers,
                    "structuring": structuring, "peeling": peeling,
                    "cross_chain": cross_chain, "stable": stable,
                }
                st.success(
                    f"✅ Found: {len(clusters)} clusters · {len(circular)} circular flows · "
                    f"{len(anomalies)} anomalies · {len(mixers)} mixer candidates · "
                    f"{len(structuring)} structuring events · {len(peeling)} peeling chains · "
                    f"{len(cross_chain)} cross-chain hops"
                )

        if "pattern_results" in st.session_state:
            res = st.session_state.pattern_results
            pt1, pt2, pt3, pt4, pt5, pt6, pt7, pt8 = st.tabs([
                "🔵 Clusters", "🔄 Circular", "⚠️ Anomalies", "🔀 Mixers",
                "📉 Structuring", "🍂 Peeling", "🌉 Cross-chain", "💵 Stablecoins"
            ])

            with pt1:
                st.caption("Wallets grouped by similar transaction behavior — may indicate coordinated activity, bot networks, or exchange sweepers.")
                for c in res["clusters"][:10]:
                    with st.expander(f"{c['classification']} · {c['member_count']} wallets · ${c['total_volume']:,.0f} volume"):
                        c2a, c2b = st.columns(2)
                        c2a.metric("Avg Risk Score",     f"{c.get('avg_risk_score',0):.0f}/100")
                        c2b.metric("Intra-cluster txs",  f"{c.get('intra_cluster_ratio',0):.0%}")
                        st.markdown("**Sample addresses:**")
                        for addr in c.get("members",[])[:5]:
                            st.code(addr)

            with pt2:
                st.caption("A→B→C→A circular flows indicate wash trading, round-tripping, or mixer testing.")
                if res["circular"]:
                    for f in res["circular"][:15]:
                        label = classify_circular_flow(f)
                        with st.expander(f"{label} · {f['cycle_length']}-hop · ${f['total_volume']:,.0f} · severity {f['severity_score']:.0f}"):
                            st.markdown(" → ".join(str(a)[:16]+"…" for a in f.get("cycle",[])))
                            ci1,ci2,ci3 = st.columns(3)
                            ci1.metric("Volume",     f"${f['total_volume']:,.2f}")
                            ci2.metric("Time span",  f"{f['time_span_hours']:.1f} hrs")
                            ci3.metric("Tokens",     ", ".join(f.get("tokens",[])))
                else:
                    st.info("No circular flows detected.")

            with pt3:
                st.caption("Addresses showing sudden behavioral shifts — volume spikes, recipient explosions, activity surges.")
                if res["anomalies"]:
                    anom_df = pd.DataFrame(res["anomalies"][:50])
                    st.dataframe(anom_df[["address","type","severity","detail","tx_hash"]],
                                 use_container_width=True,
                                 height=480,
                                 hide_index=True,
                                 column_config={
                                     "address": st.column_config.TextColumn(
                                         "Address",
                                         width="large"
                                     ),
                                     "type": st.column_config.TextColumn(
                                         "Type",
                                         width="medium"
                                     ),
                                     "label": st.column_config.TextColumn(
                                         "Label",
                                         width="large"
                                     ),
                                     "source": st.column_config.TextColumn(
                                         "Source",
                                         width="medium"
                                     ),
                                 }
                                 )
                else:
                    st.info("No behavioral anomalies detected.")

            with pt4:
                st.caption("Addresses with fan-in/fan-out patterns typical of mixing services.")
                if res["mixers"]:
                    mix_df = pd.DataFrame(res["mixers"])
                    st.dataframe(mix_df[["address","mixer_score","fan_in","fan_out","total_volume","classification"]].style.background_gradient(
                        subset=["mixer_score"], cmap="Reds"), use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)
                else:
                    st.info("No mixer candidates detected.")

            with pt5:
                st.caption("Transactions broken into amounts just below reporting thresholds — FATF Typology #3.")
                if res["structuring"]:
                    for s in res["structuring"][:10]:
                        with st.expander(f"🚨 {s['address'][:20]}… · {s['tx_count']} txs · ${s['total_amount']:,.0f} {s['token']} · severity {s['severity']}"):
                            si1,si2,si3 = st.columns(3)
                            si1.metric("Threshold",    f"${s['threshold']:,.0f}")
                            si2.metric("Window",       f"{s['time_window_hrs']:.1f} hrs")
                            si3.metric("Avg Tx",       f"${s['avg_amount']:,.0f}")
                            st.caption(s["fatf_ref"])
                else:
                    st.info("No structuring detected with current settings.")

            with pt6:
                st.caption("Sequential hops with gradually decreasing amounts — common in ransomware cashouts.")
                if res["peeling"]:
                    peel_df = pd.DataFrame(res["peeling"])
                    st.dataframe(peel_df[["chain_length","start_address","end_address","start_amount","end_amount","peel_pct","severity"]],
                                 use_container_width=True,
                                 height=480,
                                 hide_index=True,
                                 column_config={
                                     "address": st.column_config.TextColumn(
                                         "Address",
                                         width="large"
                                     ),
                                     "type": st.column_config.TextColumn(
                                         "Type",
                                         width="medium"
                                     ),
                                     "label": st.column_config.TextColumn(
                                         "Label",
                                         width="large"
                                     ),
                                     "source": st.column_config.TextColumn(
                                         "Source",
                                         width="medium"
                                     ),
                                 }
                                 )
                else:
                    st.info("No peeling chains detected.")

            with pt7:
                st.caption("Same/similar amounts appearing on different blockchains within a short window — bridge-and-continue laundering.")
                if res["cross_chain"]:
                    cc_df = pd.DataFrame(res["cross_chain"])
                    st.dataframe(cc_df[["chain_from","chain_to","amount","delta_hours","token_a","token_b","address_from"]],
                                 use_container_width=True,
                                 height=480,
                                 hide_index=True,
                                 column_config={
                                     "address": st.column_config.TextColumn(
                                         "Address",
                                         width="large"
                                     ),
                                     "type": st.column_config.TextColumn(
                                         "Type",
                                         width="medium"
                                     ),
                                     "label": st.column_config.TextColumn(
                                         "Label",
                                         width="large"
                                     ),
                                     "source": st.column_config.TextColumn(
                                         "Source",
                                         width="medium"
                                     ),
                                 }
                                 )
                else:
                    st.info("No cross-chain hops detected (requires multi-chain dataset).")

            with pt8:
                s = res["stable"]
                if not s.get("empty"):
                    st.metric("Total Stablecoin Volume", f"${s['total_volume']:,.2f}")
                    st.metric("Concentration (top 10 senders)", f"{s['concentration']:.1%}")
                    st.metric("Round-number txs", f"{s['round_tx_count']:,} (${s['round_tx_volume']:,.0f})")
                    col_s1, col_s2 = st.columns(2)
                    with col_s1:
                        st.markdown("**By Token**")
                        st.bar_chart(pd.Series(s["token_split"]))
                    with col_s2:
                        st.markdown("**Top Senders**")
                        st.dataframe(pd.Series(s["top_senders"]).reset_index().rename(columns={"index":"address",0:"volume"}),
                                     hide_index=True)
                else:
                    st.info("No stablecoin transactions in dataset.")

    # ── TAB 11: VELOCITY ─────────────────────────────────────
    elif page == '⚡ Velocity':
        st.subheader("⚡ Velocity Analysis — Time-to-Forward")
        st.caption("How quickly addresses re-send received funds. Very fast turnaround (< 1 hr) strongly indicates automated layering.")
        if st.button("▶ Run Velocity Analysis", type="primary", key="run_vel"):
            with st.spinner("Calculating velocity…"):
                vel_df = analyze_velocity(df)
                st.session_state.vel_df = vel_df

        if "vel_df" in st.session_state:
            vel = st.session_state.vel_df
            v1,v2,v3,v4 = st.columns(4)
            v1.metric("Addresses analyzed",  len(vel))
            v2.metric("🔴 Instant (<15min)", (vel["velocity_class"].str.contains("INSTANT")).sum())
            v3.metric("🟠 Rapid (<1hr)",     (vel["velocity_class"].str.contains("RAPID")).sum())
            v4.metric("Avg TTF",             f"{vel['ttf_hours'].median():.1f} hrs")

            st.plotly_chart(plot_velocity_distribution(vel), width=True)

            st.markdown("**Highest Velocity Addresses**")
            show_cols = [c for c in ["address","ttf_minutes","velocity_class","velocity_score","volume_sent","pass_through_ratio"] if c in vel.columns]
            st.dataframe(
                vel[show_cols].head(50).style.background_gradient(subset=["velocity_score"], cmap="Reds"),
                use_container_width=True,
                height=480,
                hide_index=True,
                column_config={
                    "address": st.column_config.TextColumn(
                        "Address",
                        width="large"
                    ),
                    "type": st.column_config.TextColumn(
                        "Type",
                        width="medium"
                    ),
                    "label": st.column_config.TextColumn(
                        "Label",
                        width="large"
                    ),
                    "source": st.column_config.TextColumn(
                        "Source",
                        width="medium"
                    ),
                }
            )

            st.download_button("⬇️ Export Velocity CSV",
                vel.to_csv(index=False).encode(),
                "velocity_analysis.csv", "text/csv")

    # ── TAB 12: NETWORK GRAPH ────────────────────────────────
    elif page == '🕸 Network Graph':
        st.subheader("🕸️ Transaction Network Graph")
        st.caption("Force-directed graph — node size = volume, color = risk, edges = fund flows. Better than Sankey for spotting hubs and clusters.")
        ng1, ng2 = st.columns([1,3])
        with ng1:
            max_nodes = st.slider("Max nodes", 10, 120, 60, key="ng_nodes")
            min_edge  = st.number_input("Min edge amount ($)", 0.0, step=100.0, key="ng_min")
        with ng2:
            if st.button("🔄 Build Network Graph", type="primary", key="build_ng"):
                with st.spinner("Building network…"):
                    try:
                        import networkx
                        fig_ng = build_network_graph(df, max_nodes=max_nodes, min_amount=float(min_edge))
                        if fig_ng:
                            st.session_state.ng_fig = fig_ng
                        else:
                            st.warning("Not enough connected data to build graph.")
                    except ImportError:
                        st.error("networkx not installed. Run: pip install networkx")

        if "ng_fig" in st.session_state:
            st.plotly_chart(st.session_state.ng_fig, width=True)

        st.markdown("**Wallet Profiler** — full forensic profile for any address")
        prof_addr = st.text_input("Address to profile", placeholder="Paste from table or graph above", key="prof_addr")
        if st.button("🔍 Profile Wallet", key="prof_btn") and prof_addr.strip():
            profile = profile_wallet(df, prof_addr.strip())
            render_wallet_profile(profile)

    # ── TAB 13: CASE NOTES ───────────────────────────────────
    elif page == '📁 Case Notes':
        render_case_notes(df)


    # ── SAR / CTR Filing ─────────────────────────────────
    elif page == "📋 SAR / CTR Filing":
        render_compliance_ui(df)

    # ── EIP-712 Signing ──────────────────────────────────
    elif page == "🔐 EIP-712 Signing":
        findings_for_signing = {
            "case_id": "CASE-001",
            "overall_risk_score": int(df["risk_score"].max()) if "risk_score" in df.columns else 0,
            "total_transactions": len(df),
            "total_volume": float(df["amount"].sum()),
        }
        render_signing_ui(findings_for_signing)

    # ── ZK Proofs ────────────────────────────────────────
    elif page == "🔏 ZK Proofs":
        st.markdown("### 🔏 Zero-Knowledge Proofs")
        try:
            zk = ZKProofGenerator()
            actual = st.number_input("Amount (private)", min_value=0.0, step=100.0, key="zk_a")
            thresh = st.number_input("Threshold", min_value=0.0, value=10000.0, key="zk_t")
            if st.button("Generate Proof", key="zk_go"):
                if actual >= thresh:
                    proof = zk.generate_amount_proof(actual, thresh)
                    st.success(f"Proves amount ≥ ${thresh:,.0f} without revealing ${actual:,.0f}")
                    st.json(proof)
                else:
                    st.error("Amount is below threshold.")
        except NameError:
            st.info("Install forensics_zkp.py to use this feature.")

    # ── ENS Resolution ───────────────────────────────────
    elif page == "🌐 ENS Resolution":
        render_ens_lookup()
        st.divider()
        if st.button("Enrich dataset with ENS labels", key="ens_enrich"):
            with st.spinner("Resolving…"):
                enriched = enrich_dataframe_with_ens(df, max_lookups=20)
                st.session_state.enriched_df = enriched
        if "enriched_df" in st.session_state:
            edf = st.session_state.enriched_df
            show = [c for c in ["date","from_address","from_label","to_address","to_label","amount","token"] if c in edf.columns]
            st.dataframe(edf[show].head(100), use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)

    elif page == "🔔 Alerts & Monitoring":
        render_alerts_ui(get_key_fn=get_key)

    # ── Time Series ML ───────────────────────────────────
    elif page == "📈 Time Series ML":
        st.markdown("### 📈 Time Series ML")
        if st.button("▶ Run", type="primary", key="ts_run"):
            with st.spinner("Analysing…"):
                p = st.progress(0)
                p.progress(25, "Ramping…")
                ramp = detect_adaptive_laundering(df)
                p.progress(55, "Cyclical…")
                cycl = detect_cyclical_patterns(df)
                p.progress(80, "Dormant…")
                dorm = detect_dormant_reactivation(df)
                p.progress(100); p.empty()
                st.session_state.ts_r = {"ramp": ramp, "cycl": cycl, "dorm": dorm}
                st.success(f"{len(ramp)} ramping · {len(cycl)} cyclical · {len(dorm)} dormant")
        if "ts_r" in st.session_state:
            ts = st.session_state.ts_r
            t1,t2,t3 = st.tabs(["📈 Ramping","🤖 Cyclical","💤 Dormant"])
            with t1:
                if ts["ramp"]:
                    for r in ts["ramp"][:5]:
                        with st.expander(f"{r["address"][:24]}… · {r["multiplier"]}× · sev {r["severity"]}"):
                            st.caption(r["description"])
                            fig = plot_address_timeline(df, r["address"])
                            if fig is not None:
                                st.plotly_chart(
                                    fig,
                                    width=True,
                                    key=f"plot_{time.time_ns()}"
                                )
                else: st.info("None detected.")
            with t2:
                if ts["cycl"]: st.dataframe(pd.DataFrame(ts["cycl"]), use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)
                else: st.info("None detected.")
            with t3:
                if ts["dorm"]: st.dataframe(pd.DataFrame(ts["dorm"]), use_container_width=True,
    height=480,
    hide_index=True,
    column_config={
        "address": st.column_config.TextColumn(
            "Address",
            width="large"
        ),
        "type": st.column_config.TextColumn(
            "Type",
            width="medium"
        ),
        "label": st.column_config.TextColumn(
            "Label",
            width="large"
        ),
        "source": st.column_config.TextColumn(
            "Source",
            width="medium"
        ),
    }
)
                else: st.info("None detected.")
        st.divider()
        ts_a = st.text_input("Address timeline", key="ts_addr", placeholder="Paste address")
        if ts_a:
            fig = plot_address_timeline(df, ts_a)
            if fig: st.plotly_chart(fig, width=True)






    # ── Lightning Network ─────────────────────────────────
    elif page == "⚡ Lightning Network":
        render_lightning_ui(df)

    # ── Stablecoin Depeg ─────────────────────────────────
    elif page == "💹 Stablecoin Depeg":
        render_stablecoin_ui(df)

    # ── Crypto Crime News ─────────────────────────────────
    elif page == "📰 Crypto Crime News":
        render_newsfeed_ui(df)

    # ── Solana ───────────────────────────────────────────
    elif page == "◎ Solana Analysis":
        render_solana_ui()

    # ── Deep Analytics ───────────────────────────────────
    elif page in ("🌪️ Tornado Linking","🧠 GNN Clustering","⏳ Mempool Monitor","🔀 Atomic Swaps"):
        render_advanced2_ui(df, get_key_fn=get_key)

    # ── REST API ─────────────────────────────────────────
    elif page == "🔌 REST API":
        render_api_ui()



    # ── Social Media Intelligence ─────────────────────────
    elif page == "📡 Social Media Intel":
        render_social_ui(df, get_key_fn=get_key)

    # ── Infrastructure Clustering ─────────────────────────
    elif page == "🏗️ Infrastructure":
        render_netinfra_ui(df)

    # ── Threat Intelligence ───────────────────────────────
    elif page == "🎯 Threat Intel":
        render_scams_ui(df)

    elif page == "🤝 P2P & ATMs":
        render_scams_ui(df)

    # ── Profile & Timeline ────────────────────────────────
    elif page == "👤 Suspect Profile":
        render_profile_ui(df, get_key_fn=get_key)

    elif page == "🌱 Seed Phrase":
        render_seedphrase_ui(df, get_key_fn=get_key)

    elif page == "📅 Investigation Timeline":
        render_timeline_ui(df)

    elif page == "📱 QR Scanner":
        render_qr_scanner_ui(df)

    elif page == "🤖 Investigation Agent":
        render_agent_ui(df, get_key_fn=get_key)

    # ── MiCA Compliance ───────────────────────────────────
    elif page == "🇪🇺 MiCA Compliance":
        render_mica_compliance_ui(df, get_key_fn=get_key)

    # ── Maltego Export ────────────────────────────────────
    elif page == "🕸 Maltego Export":
        render_export_ui(df, get_key_fn=get_key)

    # ── MEV & Market Manipulation ────────────────────────
    elif page == "⚔️ MEV & Market Manipulation":
        render_mev_ui(df)

    # ── Regulatory pages (compliance2) ───────────────────
    elif page in ("✈️ FATF Travel Rule","🔵 L2 Chains","🔐 Multi-sig",
                   "🔒 Privacy Coins","🔌 Pro API Integration","📊 Case Dashboard"):
        render_compliance2_ui(df, get_key_fn=get_key)

    # ── Address Intelligence ──────────────────────────────
    elif page == "🏷️ Address Intelligence":
        render_address_intel_ui(df)

    # ── Advanced Features ─────────────────────────────────
    elif page in ("🖼 NFT & Airdrop","🌍 Geolocation","💾 Save/Restore","💼 Portfolio","📈 Price Ticker"):
        # All advanced sub-pages rendered by render_advanced_ui which uses its own tabs
        if page == "🖼 NFT & Airdrop":
            # Jump to NFT tab
            st.session_state["_adv_tab"] = 0
        elif page == "🌍 Geolocation":
            st.session_state["_adv_tab"] = 2
        elif page == "💾 Save/Restore":
            st.session_state["_adv_tab"] = 3
        elif page == "💼 Portfolio":
            st.session_state["_adv_tab"] = 4
        elif page == "📈 Price Ticker":
            st.session_state["_adv_tab"] = 5
        render_advanced_ui(df, get_key_fn=get_key)

    # ── OSINT Intelligence ────────────────────────────────
    elif page == "🔎 OSINT Intelligence":
        render_osint_ui(df, get_key_fn=get_key)

else:
    st.info(
        "👆 Upload a CSV file, click **Load Sample Data** in the sidebar, "
        "or enter a wallet address in the **On-chain Lookup** section to begin."
    )
    st.markdown("### Expected CSV columns")
    st.code("date, from_address, to_address, amount, token, tx_hash, chain", language="text")
    st.markdown(
        "All columns optional — auto-detected from Etherscan, BscScan, "
        "Chainalysis, and manual exports."
    )

st.caption("Crypto Forensics Pro v5.0 · Claude AI · For authorized investigative use only")