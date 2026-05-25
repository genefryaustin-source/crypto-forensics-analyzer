"""
forensics_advanced.py  —  Crypto Forensics Analyzer Pro v5.0
Advanced investigation features:
  • NFT wash trading & volume manipulation detection
  • Airdrop farming detection
  • Geolocation approximation from transaction timing
  • Investigation state save / restore (collaboration)
  • Portfolio balance tracker for traced addresses
  • Live crypto price ticker
"""

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import requests
import json
import io
import zipfile
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from collections import Counter

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# 1. NFT WASH TRADING DETECTOR
#    Identifies the same wallet buying/selling the same NFT
#    to create artificial trading volume and price inflation.
# ─────────────────────────────────────────────────────────────

NFT_CONTRACTS = {
    "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d": "Bored Ape Yacht Club",
    "0x60e4d786628fea6478f785a6d7e704777c86a7c6": "Mutant Ape YC",
    "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb": "CryptoPunks",
    "0x49cf6f5d44e70224e2e23fdcdd2c053f30ada28b": "CloneX",
    "0x8a90cab2b38dba80c64b7734e58ee1db38b8992e": "Doodles",
    "0x23581767a106ae21c074b2276d25e5c3e136a68b": "Moonbirds",
}

WASH_TRADE_WINDOW_HOURS = 168  # 7 days


@st.cache_data(show_spinner=False)
def detect_nft_wash_trading(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect NFT wash trading: same address (or related addresses)
    buying and selling the same token/NFT within a time window.
    
    Patterns detected:
    1. Same wallet buys then sells (or vice versa)
    2. Two wallets trade back and forth (coordinated wash)
    3. Circular NFT trades (A→B→C→A)
    """
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
    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    df = df.dropna(subset=["date"]).sort_values("date")

    findings = []
    window   = timedelta(hours=WASH_TRADE_WINDOW_HOURS)

    # Group by token to find repeated transfers of the same asset
    if "token" not in df.columns:
        return pd.DataFrame()

    for token in df["token"].unique():
        token_txs = df[df["token"] == token].sort_values("date")
        if len(token_txs) < 2:
            continue

        # Pattern 1: Same address sends and receives same token
        senders   = set(token_txs["from_address"])
        receivers = set(token_txs["to_address"])
        both_ways = senders & receivers  # addresses that both send and receive

        for addr in both_ways:
            sent_txs = token_txs[token_txs["from_address"] == addr]
            recv_txs = token_txs[token_txs["to_address"]   == addr]

            for _, recv in recv_txs.iterrows():
                # Find sends within window after receiving
                after_recv = sent_txs[
                    (sent_txs["date"] > recv["date"]) &
                    (sent_txs["date"] <= recv["date"] + window)
                ]
                for _, send in after_recv.iterrows():
                    price_diff_pct = abs(send["amount"] - recv["amount"]) / max(recv["amount"], 0.001)
                    findings.append({
                        "pattern":         "SELF_WASH" if send["to_address"] == recv["from_address"] else "PUMP_AND_DUMP",
                        "token":           token,
                        "wash_address":    addr,
                        "buy_tx":          recv.get("tx_hash",""),
                        "sell_tx":         send.get("tx_hash",""),
                        "buy_price":       recv["amount"],
                        "sell_price":      send["amount"],
                        "price_change_pct":round(price_diff_pct * 100, 1),
                        "hold_hours":      round((send["date"]-recv["date"]).total_seconds()/3600, 1),
                        "buy_date":        str(recv["date"])[:16],
                        "sell_date":       str(send["date"])[:16],
                        "severity":        min(100, 60 + int(recv["amount"] > 1) * 20 + int(price_diff_pct > 0.1) * 20),
                    })

        # Pattern 2: Two wallets trading back and forth (coordinated wash)
        addr_pairs = {}
        for _, tx in token_txs.iterrows():
            pair = tuple(sorted([tx["from_address"], tx["to_address"]]))
            addr_pairs.setdefault(pair, []).append(tx)

        for (a, b), txs in addr_pairs.items():
            if len(txs) >= 3:  # 3+ transfers between same pair = suspicious
                total_vol = sum(t["amount"] for t in txs)
                findings.append({
                    "pattern":          "COORDINATED_WASH",
                    "token":            token,
                    "wash_address":     f"{a[:16]}… ↔ {b[:16]}…",
                    "trade_count":      len(txs),
                    "total_volume":     total_vol,
                    "first_trade":      str(txs[0]["date"])[:16],
                    "last_trade":       str(txs[-1]["date"])[:16],
                    "severity":         min(100, 50 + len(txs) * 5),
                })

    logger.info(f"✅ NFT wash trading: {len(findings)} findings")
    return pd.DataFrame(findings).drop_duplicates() if findings else pd.DataFrame()


@st.cache_data(show_spinner=False)
def detect_airdrop_farming(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect airdrop farming: wallets interacting with many protocols
    in a short time to qualify for airdrops.
    
    Pattern: same address makes small transactions to 5+ unique protocols
    within 30 days, often with near-zero amounts.
    """
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
    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    df = df.dropna(subset=["date"]).sort_values("date")

    findings = []
    window = timedelta(days=30)

    for addr in df["from_address"].unique():
        addr_txs = df[df["from_address"] == addr].sort_values("date")
        if len(addr_txs) < 5:
            continue

        dates = addr_txs["date"].tolist()
        for i in range(len(dates)):
            window_txs = addr_txs[
                (addr_txs["date"] >= dates[i]) &
                (addr_txs["date"] <= dates[i] + window)
            ]
            unique_protocols = window_txs["to_address"].nunique()
            unique_tokens    = window_txs["token"].nunique()
            avg_amount       = window_txs["amount"].mean()

            # Farming signature: many unique targets, small amounts, diverse tokens
            if unique_protocols >= 5 and avg_amount < 100 and unique_tokens >= 2:
                findings.append({
                    "address":          addr,
                    "period_start":     str(dates[i])[:10],
                    "period_end":       str(dates[i] + window)[:10],
                    "unique_protocols": unique_protocols,
                    "unique_tokens":    unique_tokens,
                    "tx_count":         len(window_txs),
                    "avg_tx_amount":    round(avg_amount, 4),
                    "total_gas_spend":  round(window_txs["amount"].sum(), 4),
                    "severity":         min(100, unique_protocols * 8 + unique_tokens * 5),
                    "pattern":          "AIRDROP_FARMING",
                })
                break  # One finding per address

    logger.info(f"✅ Airdrop farming: {len(findings)} suspects")
    return pd.DataFrame(findings) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 2. GEOLOCATION APPROXIMATION
#    Transaction timing patterns reveal timezone → jurisdiction.
#    Human wallets show activity peaks during waking hours.
#    Automated wallets show uniform 24/7 activity.
# ─────────────────────────────────────────────────────────────

TIMEZONE_JURISDICTIONS = {
    range(0,  3):  "Europe / Africa (UTC+0 to UTC+2)",
    range(3,  6):  "Middle East / East Africa (UTC+3 to UTC+5)",
    range(6,  9):  "South Asia / Central Asia (UTC+5:30 to UTC+8)",
    range(9, 12):  "East Asia / Southeast Asia (UTC+9 to UTC+11)",
    range(12,15):  "Pacific / Oceania (UTC+12 to UTC+14)",
    range(15,18):  "Americas (UTC-9 to UTC-6)",
    range(18,21):  "North America Central/East (UTC-6 to UTC-3)",
    range(21,24):  "Atlantic / West Africa (UTC-1 to UTC+0)",
}

HIGH_RISK_JURISDICTIONS = {
    "East Asia / Southeast Asia":  "Elevated — common origin for crypto fraud operations",
    "Eastern Europe":              "Elevated — ransomware and DarkNet market activity",
}


@st.cache_data(show_spinner=False)
def infer_timezone(df: pd.DataFrame, address: str) -> Dict:
    """
    Infer timezone of an address controller from transaction timing patterns.
    Human activity typically peaks in local morning/afternoon.
    Returns timezone estimate and jurisdiction approximation.
    """
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
    df["date"] = pd.to_datetime(df["date"], errors="coerce")

    addr_txs = df[
        (df["from_address"].str.lower() == address.lower()) |
        (df["to_address"].str.lower()   == address.lower())
    ].dropna(subset=["date"])

    if len(addr_txs) < 5:
        return {"error": "Insufficient transaction history for timezone inference"}

    hours = addr_txs["date"].dt.hour.values
    hour_counts = Counter(hours)

    # Find peak activity window (most active 4-hour block)
    max_activity = 0
    peak_hour    = 0
    for h in range(24):
        window_count = sum(hour_counts.get((h + i) % 24, 0) for i in range(4))
        if window_count > max_activity:
            max_activity = window_count
            peak_hour    = h

    # Assume peak is midday (12:00-14:00 local) → infer UTC offset
    # Peak hour 9-13 UTC → local midday in UTC+0 to UTC+4
    estimated_utc_offset = (peak_hour - 12) % 24
    if estimated_utc_offset > 12:
        estimated_utc_offset -= 24

    # Map to jurisdiction
    jurisdiction = "Unknown"
    for hour_range, jur in TIMEZONE_JURISDICTIONS.items():
        if peak_hour in hour_range:
            jurisdiction = jur
            break

    # Detect automation (uniform activity = bot/exchange)
    total_txs   = len(addr_txs)
    active_hours = len(hour_counts)
    uniformity  = active_hours / 24  # 1.0 = perfectly uniform = bot

    return {
        "address":              address,
        "peak_activity_hour":   peak_hour,
        "estimated_utc_offset": estimated_utc_offset,
        "estimated_jurisdiction": jurisdiction,
        "activity_uniformity":  round(uniformity, 2),
        "is_automated":         uniformity > 0.75,
        "automation_note":      "Likely automated/exchange" if uniformity > 0.75 else "Likely human operator",
        "total_transactions":   total_txs,
        "active_hours":         active_hours,
        "hour_distribution":    dict(sorted(hour_counts.items())),
    }


def plot_activity_heatmap(df: pd.DataFrame, address: Optional[str] = None) -> go.Figure:
    """
    Plot hour-of-day × day-of-week transaction heatmap.
    Reveals timezone and behavioral patterns visually.
    """
    df2 = df.copy()
    df2["date"] = pd.to_datetime(df2["date"], errors="coerce")
    df2 = df2.dropna(subset=["date"])

    if address:
        df2 = df2[
            (df2["from_address"].str.lower() == address.lower()) |
            (df2["to_address"].str.lower()   == address.lower())
        ]

    if df2.empty:
        return None

    df2["hour"]    = df2["date"].dt.hour
    df2["weekday"] = df2["date"].dt.day_name()

    DAYS = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    heat = df2.groupby(["weekday","hour"]).size().reset_index(name="count")
    heat["weekday"] = pd.Categorical(heat["weekday"], categories=DAYS, ordered=True)
    pivot = heat.pivot(index="weekday", columns="hour", values="count").fillna(0)

    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=[f"{h:02d}:00 UTC" for h in pivot.columns],
        y=pivot.index.tolist(),
        colorscale="YlOrRd",
        hovertemplate="Day: %{y}<br>Hour: %{x}<br>Transactions: %{z}<extra></extra>",
    ))
    title = f"Transaction Activity Heatmap{' — ' + address[:20] + '…' if address else ''}"
    fig.update_layout(title=title, height=380, paper_bgcolor="rgba(0,0,0,0)",
                      xaxis_title="Hour (UTC)", yaxis_title="Day of Week")
    return fig


# ─────────────────────────────────────────────────────────────
# 3. INVESTIGATION STATE SAVE / RESTORE  (Collaboration)
#    Save the complete investigation state to a ZIP file.
#    Load it on any machine to continue where you left off.
# ─────────────────────────────────────────────────────────────

STATE_KEYS = [
    "processed_df", "raw_df", "ai_result", "pattern_results",
    "vel_df", "ofac_df", "rw_df", "usd_df", "proto_df",
    "class_df", "exc_df", "dark_df", "trace_summary",
    "ts_r", "sar_narrative", "sar_meta",
]


def save_investigation_state(case_id: str, analyst: str) -> bytes:
    """
    Save complete investigation state as a ZIP containing:
    - transactions.csv (processed dataframe)
    - state.json (session state, analysis results, AI output)
    - metadata.json (case info, timestamps)
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Save dataframe
        if "processed_df" in st.session_state and st.session_state.processed_df is not None:
            df = st.session_state.processed_df
            zf.writestr("transactions.csv", df.to_csv(index=False))

        # Save serializable session state
        state = {}
        for key in STATE_KEYS:
            if key in st.session_state and key != "processed_df" and key != "raw_df":
                val = st.session_state[key]
                try:
                    if isinstance(val, pd.DataFrame):
                        state[key] = val.to_dict("records")
                    elif isinstance(val, (str, int, float, list, dict, bool)):
                        state[key] = val
                    else:
                        state[key] = str(val)
                except Exception:
                    pass

        zf.writestr("state.json", json.dumps(state, indent=2, default=str))

        # Metadata
        meta = {
            "case_id":        case_id,
            "analyst":        analyst,
            "saved_at":       datetime.now().isoformat(),
            "tool_version":   "Crypto Forensics Analyzer Pro v5.0",
            "tx_count":       len(st.session_state.get("processed_df", [])),
        }
        zf.writestr("metadata.json", json.dumps(meta, indent=2))

    buf.seek(0)
    return buf.getvalue()


def load_investigation_state(zip_bytes: bytes) -> Dict:
    """Restore investigation state from a saved ZIP file."""
    result = {"metadata": {}, "state": {}, "df": None}
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()

            if "metadata.json" in names:
                result["metadata"] = json.loads(zf.read("metadata.json"))

            if "transactions.csv" in names:
                result["df"] = pd.read_csv(io.BytesIO(zf.read("transactions.csv")))

            if "state.json" in names:
                state = json.loads(zf.read("state.json"))
                # Restore DataFrames from records
                DF_KEYS = {"ofac_df","rw_df","usd_df","proto_df","class_df","exc_df","dark_df","vel_df"}
                for k, v in state.items():
                    if k in DF_KEYS and isinstance(v, list):
                        state[k] = pd.DataFrame(v)
                result["state"] = state

    except Exception as e:
        logger.error(f"State restore failed: {e}")
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────
# 4. PORTFOLIO BALANCE TRACKER
#    Show current holdings of all traced addresses.
#    Useful for asset freeze/seizure proceedings.
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=300, show_spinner=False)
def get_address_balance(address: str, chain: str, api_key: str) -> Dict:
    """Fetch current native token balance for an address."""
    chain_ids = {"ethereum":1, "bsc":56, "polygon":137, "avalanche":43114}
    native    = {"ethereum":"ETH","bsc":"BNB","polygon":"MATIC","avalanche":"AVAX"}
    cid = chain_ids.get(chain, 1)

    try:
        resp = requests.get(
            "https://api.etherscan.io/v2/api",
            params={"chainid":cid,"module":"account","action":"balance",
                    "address":address,"tag":"latest","apikey":api_key},
            timeout=10
        ).json()
        if resp.get("status") == "1":
            balance = int(resp["result"]) / 1e18
            return {"address":address,"chain":chain,"balance":balance,
                    "token":native.get(chain,"ETH"),"status":"ok"}
    except Exception as e:
        return {"address":address,"chain":chain,"balance":0,"token":"?","status":f"error: {e}"}

    return {"address":address,"chain":chain,"balance":0,"token":"?","status":"no_data"}


def fetch_portfolio(
    addresses: List[str],
    chain: str,
    api_key: str,
    progress_cb=None,
) -> pd.DataFrame:
    """Fetch balances for a list of addresses."""
    rows = []
    for i, addr in enumerate(addresses[:50]):  # cap at 50
        if progress_cb:
            progress_cb(i, len(addresses[:50]))
        bal = get_address_balance(str(addr), chain, api_key)
        rows.append(bal)
        time.sleep(0.2)
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────
# 5. LIVE PRICE TICKER
# ─────────────────────────────────────────────────────────────

COINGECKO_IDS = {
    "ETH":"ethereum","BTC":"bitcoin","BNB":"binancecoin","MATIC":"matic-network",
    "AVAX":"avalanche-2","TRX":"tron","LINK":"chainlink","UNI":"uniswap",
    "USDT":"tether","USDC":"usd-coin","DAI":"dai","AAVE":"aave",
    "CRV":"curve-dao-token","MKR":"maker","SOL":"solana","ADA":"cardano",
    "DOT":"polkadot","DOGE":"dogecoin","SHIB":"shiba-inu","ARB":"arbitrum",
    "OP":"optimism","APE":"apecoin","LDO":"lido-dao","RPL":"rocket-pool",
}


@st.cache_data(ttl=60, show_spinner=False)
def fetch_live_prices(tokens: List[str]) -> Dict[str, Dict]:
    """Fetch live prices + 24h change for a list of tokens."""
    ids = [COINGECKO_IDS.get(t.upper()) for t in tokens if COINGECKO_IDS.get(t.upper())]
    if not ids:
        return {}
    try:
        resp = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids":",".join(ids),"vs_currencies":"usd",
                    "include_24hr_change":"true","include_market_cap":"true"},
            timeout=15,
        ).json()
        result = {}
        for token in tokens:
            cg_id = COINGECKO_IDS.get(token.upper())
            if cg_id and cg_id in resp:
                d = resp[cg_id]
                result[token.upper()] = {
                    "price":      d.get("usd", 0),
                    "change_24h": d.get("usd_24h_change", 0),
                    "market_cap": d.get("usd_market_cap", 0),
                }
        return result
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_advanced_ui(df: pd.DataFrame, get_key_fn=None):
    """Full advanced features UI."""
    api_key = get_key_fn("etherscan_key") if get_key_fn else ""

    adv_tabs = st.tabs([
        "🖼 NFT Wash Trading", "🎁 Airdrop Farming",
        "🌍 Geolocation",      "💾 Save / Restore",
        "💼 Portfolio",        "📈 Price Ticker"
    ])

    with adv_tabs[0]:
        st.markdown("### 🖼 NFT Wash Trading Detection")
        st.caption(
            "Detects artificial trading: same wallets trading the same token back and forth "
            "to inflate volume and price. Used to manipulate NFT markets and create "
            "false trading history for tax or money laundering purposes."
        )
        if st.button("🖼 Detect Wash Trading", type="primary", key="run_wash"):
            with st.spinner("Scanning for wash trading patterns…"):
                wash_df = detect_nft_wash_trading(df)
                st.session_state.wash_df = wash_df

        if "wash_df" in st.session_state:
            wdf = st.session_state.wash_df
            if not wdf.empty:
                st.warning(f"⚠️ {len(wdf)} wash trading patterns detected")
                patterns = wdf["pattern"].value_counts()
                for pat, cnt in patterns.items():
                    st.markdown(f"- **{pat}**: {cnt} instances")
                show = [c for c in ["pattern","token","wash_address","buy_price",
                                     "sell_price","price_change_pct","hold_hours","severity"]
                        if c in wdf.columns]
                st.dataframe(wdf[show], use_container_width=True,
    hide_index=True,
    column_config={
        col: st.column_config.TextColumn(
            col,
            width="medium"
        )
        for col in df.columns
    }
)
                st.download_button("⬇️ Export Wash Trading Report",
                    wdf.to_csv(index=False).encode(), "wash_trading.csv", "text/csv")
            else:
                st.success("✅ No wash trading patterns detected.")

    with adv_tabs[1]:
        st.markdown("### 🎁 Airdrop Farming Detection")
        st.caption(
            "Identifies wallets systematically interacting with many protocols "
            "in short windows to farm airdrops. Indicates Sybil behavior — "
            "one entity controlling many wallets to multiply airdrop rewards."
        )
        if st.button("🎁 Detect Airdrop Farming", type="primary", key="run_airdrop"):
            with st.spinner("Scanning for airdrop farming…"):
                farm_df = detect_airdrop_farming(df)
                st.session_state.farm_df = farm_df

        if "farm_df" in st.session_state:
            fdf = st.session_state.farm_df
            if not fdf.empty:
                st.warning(f"⚠️ {len(fdf)} airdrop farming suspects")
                st.dataframe(fdf, use_container_width=True,
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
                st.download_button("⬇️ Export Airdrop Farming",
                    fdf.to_csv(index=False).encode(), "airdrop_farming.csv", "text/csv")
            else:
                st.success("✅ No airdrop farming detected.")

    with adv_tabs[2]:
        st.markdown("### 🌍 Geolocation Approximation")
        st.caption(
            "Infers approximate timezone and jurisdiction from transaction timing patterns. "
            "Human operators show distinct activity peaks during local waking hours. "
            "**Note:** This is probabilistic — not admissible as definitive location evidence."
        )

        geo_col1, geo_col2 = st.columns([2,1])
        with geo_col1:
            geo_addr = st.text_input("Address to geolocate", key="geo_addr",
                                      placeholder="Paste address from dataset")
        with geo_col2:
            st.markdown("<br>", unsafe_allow_html=True)
            run_geo = st.button("🌍 Infer Timezone", type="primary", key="run_geo")

        if run_geo and geo_addr.strip():
            tz_result = infer_timezone(df, geo_addr.strip())
            if "error" in tz_result:
                st.warning(tz_result["error"])
            else:
                g1,g2,g3,g4 = st.columns(4)
                g1.metric("Peak Activity Hour",    f"{tz_result['peak_activity_hour']:02d}:00 UTC")
                g2.metric("Est. UTC Offset",       f"UTC{tz_result['estimated_utc_offset']:+d}")
                g3.metric("Est. Jurisdiction",     tz_result["estimated_jurisdiction"])
                g4.metric("Automation",            "🤖 Bot" if tz_result["is_automated"] else "👤 Human")
                st.caption(tz_result["automation_note"])

        # Activity heatmap
        st.markdown("**Transaction Activity Heatmap**")
        hm_addr = st.text_input("Address (leave blank for full dataset)", key="hm_addr")
        if st.button("🔥 Generate Heatmap", key="run_hm"):
            fig_hm = plot_activity_heatmap(df, hm_addr.strip() or None)
            if fig_hm:
                st.plotly_chart(fig_hm, width=True)
            else:
                st.warning("No dated transactions found for this address.")

    with adv_tabs[3]:
        st.markdown("### 💾 Investigation State Save / Restore")
        st.caption(
            "Save your complete investigation — dataset, analysis results, AI output, "
            "case notes — as a ZIP file. Load it on any machine to continue working."
        )
        sv1, sv2 = st.columns(2)

        with sv1:
            st.markdown("**Save Investigation**")
            save_case    = st.text_input("Case ID", value=f"CASE-{datetime.now().strftime('%Y%m%d')}", key="save_case")
            save_analyst = st.text_input("Analyst",  key="save_analyst")
            if st.button("💾 Save State", type="primary", key="do_save"):
                zip_bytes = save_investigation_state(save_case, save_analyst)
                fname = f"investigation_{save_case}_{datetime.now().strftime('%H%M')}.zip"
                st.download_button("⬇️ Download Investigation ZIP",
                    zip_bytes, fname, "application/zip", type="primary")
                st.success(f"✅ Saved: {fname}")

        with sv2:
            st.markdown("**Restore Investigation**")
            restore_file = st.file_uploader("Load .zip", type=["zip"], key="restore_file")
            if restore_file and st.button("🔄 Restore", type="primary", key="do_restore"):
                result = load_investigation_state(restore_file.read())
                if "error" in result:
                    st.error(f"Restore failed: {result['error']}")
                else:
                    meta = result.get("metadata", {})
                    st.success(
                        f"✅ Restored: {meta.get('case_id','?')} · "
                        f"Analyst: {meta.get('analyst','?')} · "
                        f"Saved: {meta.get('saved_at','?')[:16]}"
                    )
                    # Restore dataframe
                    if result["df"] is not None:
                        st.session_state.raw_df = result["df"]
                        st.session_state.pop("processed_df", None)
                    # Restore session state
                    for k, v in result.get("state", {}).items():
                        st.session_state[k] = v
                    st.info("Data restored. Navigate to any tab to continue your investigation.")
                    st.rerun()

    with adv_tabs[4]:
        st.markdown("### 💼 Portfolio Balance Tracker")
        st.caption(
            "Fetch current cryptocurrency balances for traced addresses. "
            "Critical for asset freeze and seizure proceedings — shows current holdings."
        )
        if not api_key:
            st.warning("⚠️ Add Etherscan API key in sidebar to fetch live balances.")
        else:
            port_chain = st.selectbox("Chain", ["ethereum","bsc","polygon","avalanche"], key="port_chain")

            # Suggest top addresses from dataset
            top_addrs = df.groupby("from_address")["amount"].sum().nlargest(10).index.tolist()
            selected_addrs = st.multiselect(
                "Addresses to track (select or paste below)",
                options=top_addrs,
                default=top_addrs[:5],
                key="port_addrs",
            )
            extra_addrs = st.text_area(
                "Additional addresses (one per line)",
                key="port_extra", height=80
            )
            if extra_addrs.strip():
                selected_addrs += [a.strip() for a in extra_addrs.split("\n") if a.strip()]

            if st.button("💼 Fetch Balances", type="primary", key="run_port") and selected_addrs:
                prog_p = st.progress(0)
                def _pcb(i, total):
                    prog_p.progress(i/max(total,1), f"Fetching {i}/{total}…")
                with st.spinner("Fetching balances…"):
                    port_df = fetch_portfolio(selected_addrs, port_chain, api_key, _pcb)
                    st.session_state.port_df = port_df
                prog_p.empty()

            if "port_df" in st.session_state:
                pdf = st.session_state.port_df
                total_bal = pdf["balance"].sum()
                p1,p2,p3 = st.columns(3)
                p1.metric("Addresses Checked", len(pdf))
                p2.metric("Total Balance",     f"{total_bal:.4f}")
                p3.metric("Non-zero Wallets",  len(pdf[pdf["balance"] > 0]))

                pdf_display = pdf[pdf["balance"] > 0].sort_values("balance", ascending=False)
                st.dataframe(pdf_display, use_container_width=True,
    hide_index=True,
    column_config={
        col: st.column_config.TextColumn(
            col,
            width="medium"
        )
        for col in df.columns
    }
)
                st.download_button("⬇️ Export Portfolio",
                    pdf.to_csv(index=False).encode(), "portfolio.csv", "text/csv")
                if not pdf_display.empty:
                    st.plotly_chart(
                        px.bar(pdf_display.head(15), x="address", y="balance",
                               title="Top Wallet Balances", color="balance",
                               color_continuous_scale="Reds"),
                        width=True
                    )

    with adv_tabs[5]:
        st.markdown("### 📈 Live Price Ticker")
        st.caption("Live cryptocurrency prices for all tokens in your dataset. Auto-refreshes every 60 seconds.")

        # Get tokens from current dataset
        dataset_tokens = df["token"].str.upper().unique().tolist() if df is not None else []
        all_tokens     = list(set(dataset_tokens + list(COINGECKO_IDS.keys())))

        selected_tokens = st.multiselect(
            "Tokens to track",
            options=all_tokens,
            default=[t for t in dataset_tokens if t in COINGECKO_IDS][:8] or ["ETH","BTC","BNB","USDT"],
            key="price_tokens"
        )

        if st.button("🔄 Refresh Prices", key="refresh_prices") or selected_tokens:
            with st.spinner("Fetching live prices…"):
                prices = fetch_live_prices(selected_tokens)

            if prices:
                price_rows = []
                for token, data in prices.items():
                    change = data.get("change_24h", 0) or 0
                    price_rows.append({
                        "Token":      token,
                        "Price USD":  f"${data['price']:,.4f}" if data['price'] < 1 else f"${data['price']:,.2f}",
                        "24h Change": f"{'▲' if change > 0 else '▼'} {abs(change):.2f}%",
                        "Direction":  "up" if change > 0 else "down",
                        "_price":     data["price"],
                        "_change":    change,
                    })

                price_df = pd.DataFrame(price_rows)

                # Display as metric cards
                cols = st.columns(min(4, len(price_df)))
                for i, (_, row) in enumerate(price_df.iterrows()):
                    col = cols[i % len(cols)]
                    col.metric(
                        label=row["Token"],
                        value=row["Price USD"],
                        delta=f"{row['_change']:.2f}%",
                        delta_color="normal",
                    )

                # Volume-weighted value of dataset at current prices
                st.markdown("---")
                st.markdown("**Dataset Volume at Current Prices**")
                for token in dataset_tokens:
                    if token.upper() in prices:
                        token_vol = df[df["token"].str.upper() == token]["amount"].sum()
                        usd_val   = token_vol * prices[token.upper()]["price"]
                        st.metric(
                            f"{token} volume",
                            f"{token_vol:,.4f} {token}",
                            f"≈ ${usd_val:,.2f} USD"
                        )
            else:
                st.warning("No price data returned — check token names or CoinGecko rate limit.")

        st.caption("Prices from CoinGecko public API · Free tier: 10-30 req/min · Updates every 60s")
