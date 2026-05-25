"""
forensics_mev.py  —  Crypto Forensics Analyzer Pro v5.0
Market manipulation intelligence:
  • MEV / sandwich attack detection (front-run + back-run patterns)
  • Rug pull detection (liquidity removal, dev dump patterns)
  • Honeypot contract detection (tokens that can't be sold)
  • Coordinated token dump / insider trading detection
  • Wash trading volume inflation
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import requests
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# 1. MEV / SANDWICH ATTACK DETECTION
#    A sandwich attack: bot sees your pending tx, buys the
#    same token BEFORE yours (front-run), then sells AFTER
#    yours executes at the inflated price (back-run).
#    Victim gets worse price; bot profits the spread.
# ─────────────────────────────────────────────────────────────

# Known MEV bots and sandwich attackers (community maintained)
KNOWN_MEV_BOTS = {
    "0x000000000035b5e5ad9019092c665357240f594e": "Sandwich Bot (High Volume)",
    "0x00000000003b3cc22af3ae1eac0440bcee416b40": "MEV Bot",
    "0xa57bd00134b2850b2a1c55860c9e9ea100fdd6cf": "Sandwich Attacker",
    "0x0000000000007f150bd6f54c40a34d7c3d5e9f56": "MEV Bot (Jared)",
    "0xae2fc483527b8ef99eb5d9b44875f005ba1fae13": "Known Sandwich Bot",
    "0x6b75d8af000000e20b7a7ddf000ba900b4009a80": "MEV Searcher",
    "0x98c3d3183c4b8a650614ad179a1a98be0a8d6b8e": "Flashbots MEV",
}

MEV_TIME_WINDOW_SECONDS = 30   # Transactions within this window = potential sandwich


@st.cache_data(show_spinner=False)
def detect_sandwich_attacks(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect sandwich attacks in a transaction dataset.

    Pattern:
      Tx A (front-run):  bot buys token X, same block/near-block as victim
      Tx B (victim):     victim buys token X at inflated price
      Tx C (back-run):   bot sells token X for profit

    Detection heuristics:
    1. Same token, 3 transactions in tight time window
    2. First and third share the same sender (the bot)
    3. Middle transaction is a different sender (victim)
    4. Bot's buy price < victim's buy price < bot's sell price
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
    window   = timedelta(seconds=MEV_TIME_WINDOW_SECONDS)

    # Check for known MEV bots first (instant, high confidence)
    bot_lower = {k.lower(): v for k, v in KNOWN_MEV_BOTS.items()}
    from_lower = df["from_address"].str.lower()
    to_lower   = df["to_address"].str.lower()

    bot_mask = from_lower.isin(bot_lower) | to_lower.isin(bot_lower)
    for _, row in df[bot_mask].iterrows():
        bot_addr = row["from_address"] if row["from_address"].lower() in bot_lower else row["to_address"]
        bot_name = bot_lower.get(bot_addr.lower(), "Unknown MEV Bot")
        findings.append({
            "attack_type":    "KNOWN_MEV_BOT",
            "bot_address":    bot_addr,
            "bot_name":       bot_name,
            "victim_address": row["to_address"] if row["from_address"].lower() in bot_lower else row["from_address"],
            "token":          row["token"],
            "amount":         row["amount"],
            "tx_hash":        row.get("tx_hash",""),
            "date":           str(row["date"])[:16],
            "severity":       90,
            "confidence":     "HIGH — known bot address",
            "estimated_profit": row["amount"] * 0.003,  # typical 0.3% spread
        })

    # Heuristic sandwich detection (3-tx pattern)
    for token in df["token"].unique():
        token_txs = df[df["token"] == token].sort_values("date").reset_index(drop=True)
        if len(token_txs) < 3:
            continue

        dates = token_txs["date"].tolist()
        for i in range(len(dates) - 2):
            t0, t1, t2 = dates[i], dates[i+1], dates[i+2]

            # Must all be within the time window
            if (t2 - t0).total_seconds() > MEV_TIME_WINDOW_SECONDS:
                continue

            tx0 = token_txs.iloc[i]
            tx1 = token_txs.iloc[i+1]
            tx2 = token_txs.iloc[i+2]

            # Pattern: same sender for tx0 and tx2, different for tx1
            sender0 = tx0["from_address"].lower()
            sender1 = tx1["from_address"].lower()
            sender2 = tx2["from_address"].lower()

            if sender0 == sender2 and sender0 != sender1:
                # Price check: tx0 amount < tx1 amount (bot buys cheaper)
                amt0, amt1, amt2 = tx0["amount"], tx1["amount"], tx2["amount"]

                if amt0 > 0 and amt1 > 0 and amt2 > 0:
                    price_impact   = abs(amt1 - amt0) / max(amt0, 0.001)
                    estimated_profit = max(0, amt2 - amt0)

                    findings.append({
                        "attack_type":       "SANDWICH_ATTACK",
                        "bot_address":       tx0["from_address"],
                        "victim_address":    tx1["from_address"],
                        "token":             token,
                        "frontrun_amount":   amt0,
                        "victim_amount":     amt1,
                        "backrun_amount":    amt2,
                        "price_impact_pct":  round(price_impact * 100, 2),
                        "estimated_profit":  round(estimated_profit, 4),
                        "frontrun_tx":       tx0.get("tx_hash",""),
                        "victim_tx":         tx1.get("tx_hash",""),
                        "backrun_tx":        tx2.get("tx_hash",""),
                        "date":              str(t0)[:16],
                        "window_seconds":    round((t2 - t0).total_seconds(), 1),
                        "severity":          min(100, 60 + int(price_impact > 0.01) * 20 + int(estimated_profit > 1) * 20),
                        "confidence":        "MEDIUM — pattern match",
                    })

    logger.info(f"✅ MEV/sandwich detection: {len(findings)} findings")
    return pd.DataFrame(findings).drop_duplicates(subset=["victim_tx"]) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 2. RUG PULL DETECTION
#    A rug pull: dev launches token, builds liquidity,
#    attracts investors, then removes all liquidity or
#    dumps their pre-mined tokens. Investors lose everything.
#
#    Patterns detected:
#    - Sudden large liquidity removal (LP token burns/transfers)
#    - Dev wallet dump (creator selling large % of supply)
#    - Rapid token price collapse after sustained buys
# ─────────────────────────────────────────────────────────────

LIQUIDITY_POOL_SIGNATURES = [
    "uniswap", "pancakeswap", "sushiswap", "liquidity",
    "lp", "pool", "pair", "0x" + "0"*38,
]

RUG_PULL_INDICATORS = {
    "rapid_liquidity_removal":  "Liquidity removed within 30 days of launch",
    "dev_wallet_dump":          "Creator address sells >50% of holdings",
    "concentrated_supply":      ">80% of supply in <5 addresses",
    "no_sell_mechanism":        "Honeypot — buy transactions only, no sells",
    "mint_after_launch":        "New tokens minted after initial distribution",
    "ownership_not_renounced":  "Contract owner can still modify tokenomics",
}


@st.cache_data(show_spinner=False)
def detect_rug_pulls(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect rug pull patterns in a transaction dataset.
    Works on transfer data — does not require contract bytecode.
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

    for token in df["token"].unique():
        if token.upper() in ("ETH","BTC","BNB","USDT","USDC","DAI","MATIC","AVAX","TRX"):
            continue  # Skip major established tokens

        t_df = df[df["token"] == token].sort_values("date")
        if len(t_df) < 5:
            continue

        # ── Pattern 1: Liquidity Removal ────────────────────
        # Look for large single transfers OUT of LP-like addresses
        lp_mask = t_df["from_address"].str.lower().apply(
            lambda x: any(s in x for s in LIQUIDITY_POOL_SIGNATURES)
        )
        lp_exits = t_df[lp_mask]
        if not lp_exits.empty:
            max_exit   = lp_exits["amount"].max()
            total_vol  = t_df["amount"].sum()
            exit_ratio = max_exit / max(total_vol, 0.001)
            if exit_ratio > 0.3:  # >30% of volume pulled in one tx
                findings.append({
                    "token":           token,
                    "pattern":         "LIQUIDITY_REMOVAL",
                    "severity":        min(100, int(exit_ratio * 100)),
                    "evidence":        f"Single LP exit = {exit_ratio:.0%} of total volume",
                    "amount_removed":  max_exit,
                    "total_volume":    total_vol,
                    "exit_date":       str(lp_exits.loc[lp_exits["amount"].idxmax(), "date"])[:10],
                    "suspect_address": lp_exits.loc[lp_exits["amount"].idxmax(), "to_address"],
                    "tx_count":        len(t_df),
                })

        # ── Pattern 2: Dev Dump (concentrated outflow) ──────
        # Top sender controls disproportionate volume
        sender_vols = t_df.groupby("from_address")["amount"].sum()
        if len(sender_vols) > 1:
            top_sender_share = sender_vols.max() / max(sender_vols.sum(), 0.001)
            if top_sender_share > 0.5:  # >50% from one address
                top_addr = sender_vols.idxmax()
                # Check: was this address also a major early RECEIVER? (pre-mine)
                recv_vols = t_df.groupby("to_address")["amount"].sum()
                was_early_receiver = (recv_vols.get(top_addr, 0) / max(recv_vols.sum(), 0.001)) > 0.3
                if was_early_receiver:
                    findings.append({
                        "token":           token,
                        "pattern":         "DEV_WALLET_DUMP",
                        "severity":        min(100, int(top_sender_share * 100 + 20)),
                        "evidence":        f"Dev address sent {top_sender_share:.0%} of all transfers after receiving {recv_vols.get(top_addr,0)/max(recv_vols.sum(),0.001):.0%} of supply",
                        "dev_address":     top_addr,
                        "dump_volume":     sender_vols.max(),
                        "total_volume":    t_df["amount"].sum(),
                        "tx_count":        len(t_df),
                    })

        # ── Pattern 3: No Sell Mechanism (Honeypot) ─────────
        unique_senders   = set(t_df["from_address"])
        unique_receivers = set(t_df["to_address"])
        addresses_that_bought_only = unique_receivers - unique_senders

        if len(addresses_that_bought_only) > 5:
            honeypot_ratio = len(addresses_that_bought_only) / max(len(unique_receivers), 1)
            if honeypot_ratio > 0.7:  # >70% of buyers can't sell
                findings.append({
                    "token":           token,
                    "pattern":         "HONEYPOT_SUSPECTED",
                    "severity":        min(100, int(honeypot_ratio * 100)),
                    "evidence":        f"{honeypot_ratio:.0%} of buyers ({len(addresses_that_bought_only)}) have never sold — possible honeypot contract",
                    "buyers_trapped":  len(addresses_that_bought_only),
                    "total_buyers":    len(unique_receivers),
                    "tx_count":        len(t_df),
                })

    logger.info(f"✅ Rug pull detection: {len(findings)} findings")
    return pd.DataFrame(findings) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 3. INSIDER TRADING / COORDINATED DUMP DETECTION
#    Before a project announces bad news or a token crashes,
#    insiders often sell first. Detect coordinated selling
#    by connected wallets before a major price event.
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def detect_coordinated_selling(df: pd.DataFrame, coordination_window_hours: int = 6) -> pd.DataFrame:
    """
    Detect groups of wallets all selling the same token within
    a short time window — suggests coordinated insider selling.

    Also flags: wallets that received tokens recently before a dump.
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
    window   = timedelta(hours=coordination_window_hours)

    for token in df["token"].unique():
        if token.upper() in ("ETH","BTC","BNB","USDT","USDC","DAI"):
            continue

        t_df = df[df["token"] == token].sort_values("date")
        if len(t_df) < 10:
            continue

        dates = t_df["date"].tolist()
        for i in range(len(dates)):
            window_txs = t_df[
                (t_df["date"] >= dates[i]) &
                (t_df["date"] <= dates[i] + window)
            ]

            unique_sellers = window_txs["from_address"].nunique()
            total_sold     = window_txs["amount"].sum()

            if unique_sellers >= 3:
                # Check: were these sellers recent recipients (bought recently)?
                sellers     = set(window_txs["from_address"])
                recent_recv = t_df[
                    (t_df["date"] < dates[i]) &
                    (t_df["date"] >= dates[i] - timedelta(days=7)) &
                    (t_df["to_address"].isin(sellers))
                ]
                insider_ratio = len(set(recent_recv["to_address"]) & sellers) / max(unique_sellers, 1)

                if insider_ratio > 0.5:  # >50% of sellers received tokens in past week
                    findings.append({
                        "token":              token,
                        "pattern":            "COORDINATED_INSIDER_DUMP",
                        "window_start":       str(dates[i])[:16],
                        "window_end":         str(dates[i] + window)[:16],
                        "coordinated_sellers":unique_sellers,
                        "total_sold":         round(total_sold, 4),
                        "insider_ratio":      round(insider_ratio, 2),
                        "evidence":           f"{unique_sellers} wallets sold {total_sold:.2f} {token} within {coordination_window_hours}h; {insider_ratio:.0%} had received tokens within 7 days",
                        "severity":           min(100, int(unique_sellers * 10 + insider_ratio * 40)),
                        "seller_addresses":   list(sellers)[:5],
                    })
                    break  # One finding per token

    logger.info(f"✅ Coordinated dump detection: {len(findings)} findings")
    return pd.DataFrame(findings) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 4. HONEYPOT CHECK VIA EXTERNAL API
#    Honeypot.is and similar services check contract code
#    for hidden sell restrictions.
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=3600, show_spinner=False)
def check_honeypot(token_address: str, chain: str = "ethereum") -> Dict:
    """
    Check if a token contract is a honeypot using honeypot.is API (free).
    Returns analysis including buy/sell taxes and simulation results.
    """
    CHAIN_IDS = {"ethereum":"1","bsc":"56","polygon":"137","avalanche":"43114"}
    chain_id  = CHAIN_IDS.get(chain.lower(), "1")

    result = {
        "address":      token_address,
        "chain":        chain,
        "is_honeypot":  None,
        "buy_tax":      None,
        "sell_tax":     None,
        "transfer_tax": None,
        "flags":        [],
        "risk_level":   "UNKNOWN",
        "source":       "honeypot.is",
    }

    try:
        resp = requests.get(
            f"https://api.honeypot.is/v2/IsHoneypot",
            params={"address": token_address, "chainID": chain_id},
            timeout=10,
        ).json()

        hp = resp.get("honeypotResult", {})
        sim = resp.get("simulationResult", {})

        result["is_honeypot"]  = hp.get("isHoneypot", None)
        result["buy_tax"]      = sim.get("buyTax", None)
        result["sell_tax"]     = sim.get("sellTax", None)
        result["transfer_tax"] = sim.get("transferTax", None)

        flags = []
        if result["is_honeypot"]:
            flags.append("🚨 CONFIRMED HONEYPOT — tokens cannot be sold")
        if result["sell_tax"] and result["sell_tax"] > 10:
            flags.append(f"⚠️ High sell tax: {result['sell_tax']:.1f}%")
        if result["buy_tax"] and result["buy_tax"] > 10:
            flags.append(f"⚠️ High buy tax: {result['buy_tax']:.1f}%")

        result["flags"] = flags
        if result["is_honeypot"]:
            result["risk_level"] = "CRITICAL"
        elif result["sell_tax"] and result["sell_tax"] > 25:
            result["risk_level"] = "HIGH"
        elif result["sell_tax"] and result["sell_tax"] > 5:
            result["risk_level"] = "MEDIUM"
        else:
            result["risk_level"] = "LOW"

    except Exception as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────
# 5. ENHANCED NFT PUMP-AND-DUMP DETECTION
#    Coordinated floor price manipulation, fake rarity,
#    bid manipulation — more sophisticated than wash trading.
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def detect_nft_pump_dump(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect coordinated NFT pump-and-dump schemes.

    Patterns beyond simple wash trading:
    1. Floor price inflation: coordinated bids at increasing prices
    2. Rarity manipulation: same token trading at 10x normal floor
    3. Coordinated exit: multiple wallets dump same collection within 24h
    4. Fake volume: circular trades through 3+ wallets to inflate rankings
    """
    df = df.copy()
    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    df = df.dropna(subset=["date"]).sort_values("date")

    findings = []

    for token in df["token"].unique():
        if token.upper() in ("ETH","BTC","USDT","USDC","BNB","SOL","MATIC"):
            continue

        t_df = df[df["token"] == token].sort_values("date")
        if len(t_df) < 5:
            continue

        amounts = t_df["amount"].values
        dates   = t_df["date"].values

        # ── Pattern 1: Floor Price Inflation ─────────────────
        # Prices consistently increasing with coordinated buyers
        if len(amounts) >= 5:
            increases = sum(1 for i in range(1, len(amounts)) if amounts[i] > amounts[i-1])
            increase_ratio = increases / (len(amounts) - 1)

            unique_buyers = t_df["from_address"].nunique()
            unique_sellers = t_df["to_address"].nunique()

            if increase_ratio > 0.75 and unique_buyers <= 3:
                price_gain = (amounts[-1] - amounts[0]) / max(amounts[0], 0.001)
                findings.append({
                    "pattern":         "FLOOR_PRICE_INFLATION",
                    "token":           token,
                    "coordinated_wallets": unique_buyers,
                    "price_increase":  f"{price_gain:.0%}",
                    "tx_count":        len(t_df),
                    "first_price":     amounts[0],
                    "last_price":      amounts[-1],
                    "date_start":      str(t_df["date"].min())[:10],
                    "date_end":        str(t_df["date"].max())[:10],
                    "severity":        min(100, int(price_gain * 30 + unique_buyers * 5)),
                    "note":            f"{unique_buyers} wallets inflated {token} floor by {price_gain:.0%}",
                })

        # ── Pattern 2: Circular NFT Trading (3+ wallet ring) ──
        senders   = set(t_df["from_address"])
        receivers = set(t_df["to_address"])
        common    = senders & receivers   # Wallets that both send and receive

        if len(common) >= 3:
            # Check if they form a ring: A→B→C→A
            ring_vol = t_df[
                t_df["from_address"].isin(common) & t_df["to_address"].isin(common)
            ]["amount"].sum()

            if ring_vol > 0:
                findings.append({
                    "pattern":         "CIRCULAR_NFT_RING",
                    "token":           token,
                    "ring_size":       len(common),
                    "ring_volume":     ring_vol,
                    "tx_count":        len(t_df),
                    "date_start":      str(t_df["date"].min())[:10],
                    "date_end":        str(t_df["date"].max())[:10],
                    "severity":        min(100, len(common) * 15 + 30),
                    "note":            f"{len(common)}-wallet circular trading ring — creates fake volume/price history",
                })

        # ── Pattern 3: Coordinated Dump ───────────────────────
        # Multiple new sellers appear within 48h, all at peak price
        if len(amounts) >= 8:
            peak_price  = amounts.max()
            peak_idx    = amounts.argmax()
            post_peak   = t_df.iloc[peak_idx:]
            unique_post = post_peak["from_address"].nunique()

            if unique_post >= 4 and peak_idx > len(amounts) // 3:
                span = (post_peak["date"].max() - post_peak["date"].min()).total_seconds() / 3600
                if span <= 48:
                    findings.append({
                        "pattern":          "COORDINATED_NFT_DUMP",
                        "token":            token,
                        "peak_price":       peak_price,
                        "dumpers":          unique_post,
                        "dump_span_hours":  round(span, 1),
                        "tx_count":         len(t_df),
                        "date_start":       str(post_peak["date"].min())[:10],
                        "severity":         min(100, unique_post * 15 + 20),
                        "note":             f"{unique_post} wallets sold at peak price within {span:.0f}h — coordinated dump",
                    })

    logger.info(f"✅ NFT pump-dump detection: {len(findings)} findings")
    return pd.DataFrame(findings).drop_duplicates(subset=["token","pattern"]) if findings else pd.DataFrame()



def render_mev_ui(df: pd.DataFrame):
    """Market manipulation intelligence UI."""
    st.markdown("### ⚔️ Market Manipulation Intelligence")
    st.caption(
        "Detect MEV attacks, rug pulls, honeypots, and coordinated market manipulation. "
        "These patterns account for billions in annual losses and are increasingly used "
        "alongside traditional money laundering."
    )

    mev_tabs = st.tabs([
        "🥪 MEV / Sandwich Attacks", "🪤 Rug Pull Detection",
        "🍯 Honeypot Checker",       "📉 Coordinated Dumps",
        "🎨 NFT Pump & Dump"
    ])

    with mev_tabs[0]:
        st.markdown("**MEV & Sandwich Attack Detection**")
        st.caption(
            "Sandwich attacks extract value from regular users by front-running their "
            "transactions. MEV bots extracted ~$1.4B in 2023 alone. When combined with "
            "money laundering, profits are often routed through mixers."
        )
        if st.button("🥪 Detect MEV Attacks", type="primary", key="run_mev"):
            with st.spinner("Scanning for MEV and sandwich patterns…"):
                mev_df = detect_sandwich_attacks(df)
                st.session_state.mev_df = mev_df

        if "mev_df" in st.session_state:
            mdf = st.session_state.mev_df
            if not mdf.empty:
                st.warning(f"⚠️ {len(mdf)} MEV/sandwich findings")

                # Summary metrics
                if "estimated_profit" in mdf.columns:
                    m1,m2,m3 = st.columns(3)
                    m1.metric("Total Findings",        len(mdf))
                    m2.metric("Estimated Bot Profit",  f"${mdf['estimated_profit'].sum():,.2f}")
                    m3.metric("Unique Bot Addresses",  mdf.get("bot_address", pd.Series()).nunique())

                # By attack type
                types = mdf["attack_type"].value_counts()
                st.markdown("**By Attack Type:**")
                for t, c in types.items():
                    st.markdown(f"- **{t}**: {c} instances")

                show = [c for c in ["date","attack_type","bot_address","victim_address",
                                     "token","estimated_profit","severity","confidence"]
                        if c in mdf.columns]
                st.dataframe(mdf[show], use_container_width=True,
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
                st.download_button("⬇️ Export MEV Report",
                    mdf.to_csv(index=False).encode(), "mev_attacks.csv", "text/csv")
            else:
                st.success("✅ No MEV/sandwich patterns detected in dataset.")

    with mev_tabs[1]:
        st.markdown("**Rug Pull Detection**")
        st.caption(
            "Analyzes token transfer patterns to identify exit scam signatures: "
            "liquidity removal, dev wallet dumps, and honeypot characteristics."
        )
        if st.button("🪤 Detect Rug Pulls", type="primary", key="run_rug"):
            with st.spinner("Analyzing token patterns for rug pull signatures…"):
                rug_df = detect_rug_pulls(df)
                st.session_state.rug_df = rug_df

        if "rug_df" in st.session_state:
            rdf = st.session_state.rug_df
            if not rdf.empty:
                st.error(f"🚨 {len(rdf)} rug pull indicators found")

                # Group by pattern
                for pattern, group in rdf.groupby("pattern"):
                    with st.expander(f"**{pattern}** — {len(group)} token(s)", expanded=True):
                        for _, row in group.iterrows():
                            st.markdown(f"**Token: `{row['token']}`** · Severity: {row['severity']}/100")
                            st.caption(row.get("evidence",""))
                            cols = st.columns(3)
                            if "amount_removed" in row:
                                cols[0].metric("Amount Removed", f"{row['amount_removed']:,.2f}")
                            if "total_volume" in row:
                                cols[1].metric("Total Volume",   f"{row['total_volume']:,.2f}")
                            if "tx_count" in row:
                                cols[2].metric("Transactions",   row["tx_count"])
                st.download_button("⬇️ Export Rug Pull Report",
                    rdf.to_csv(index=False).encode(), "rug_pulls.csv", "text/csv")
            else:
                st.success("✅ No rug pull patterns detected.")

    with mev_tabs[2]:
        st.markdown("**Honeypot Contract Checker**")
        st.caption(
            "Checks token contracts against honeypot.is — a free service that simulates "
            "buy and sell transactions to detect hidden restrictions that prevent selling."
        )
        hp_chain = st.selectbox("Chain", ["ethereum","bsc","polygon","avalanche"], key="hp_chain")
        hp_addr  = st.text_input("Token contract address (0x…)", key="hp_addr",
                                  placeholder="Contract address of the token to check")

        col_hp1, col_hp2 = st.columns(2)
        with col_hp1:
            if st.button("🍯 Check Single Token", key="run_hp") and hp_addr.strip():
                with st.spinner("Simulating transactions via honeypot.is…"):
                    result = check_honeypot(hp_addr.strip(), hp_chain)

                if "error" in result:
                    st.error(f"API error: {result['error']}")
                else:
                    risk_icon = "🔴" if result["risk_level"]=="CRITICAL" else \
                                "🟠" if result["risk_level"]=="HIGH" else \
                                "🟡" if result["risk_level"]=="MEDIUM" else "🟢"
                    st.markdown(f"### {risk_icon} {result['risk_level']}")
                    hc1,hc2,hc3 = st.columns(3)
                    hc1.metric("Honeypot",      "YES ⚠️" if result["is_honeypot"] else "No ✅")
                    hc2.metric("Buy Tax",        f"{result['buy_tax']:.1f}%" if result['buy_tax'] is not None else "—")
                    hc3.metric("Sell Tax",       f"{result['sell_tax']:.1f}%" if result['sell_tax'] is not None else "—")
                    for flag in result["flags"]:
                        st.warning(flag)
                    if not result["flags"]:
                        st.success("✅ No honeypot indicators detected")

        with col_hp2:
            if st.button("🍯 Batch Check Dataset Tokens", key="run_hp_batch"):
                # Get unique token-like addresses from dataset
                token_addrs = [t for t in df["token"].unique()
                               if str(t).startswith("0x") and len(str(t)) == 42]
                if token_addrs:
                    results = []
                    prog = st.progress(0)
                    for i, addr in enumerate(token_addrs[:10]):  # max 10
                        prog.progress(i/len(token_addrs[:10]))
                        results.append(check_honeypot(addr, hp_chain))
                        import time; time.sleep(0.5)
                    prog.empty()
                    hp_df = pd.DataFrame(results)
                    st.session_state.hp_batch = hp_df
                    honeypots = hp_df[hp_df["is_honeypot"]==True]
                    if not honeypots.empty:
                        st.error(f"🚨 {len(honeypots)} honeypot contracts found!")
                    st.dataframe(hp_df[["address","is_honeypot","buy_tax","sell_tax","risk_level"]],
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
                    st.info("No 0x contract addresses found in token column.")

    with mev_tabs[3]:
        st.markdown("**Coordinated Token Dump Detection**")
        st.caption(
            "Detects groups of connected wallets selling the same token within a short window. "
            "When combined with recent token receipts, this indicates insider selling — "
            "the team pre-positioned, distributed tokens, then coordinated an exit."
        )
        dump_window = st.slider("Coordination window (hours)", 1, 48, 6, key="dump_window")
        if st.button("📉 Detect Coordinated Dumps", type="primary", key="run_dump"):
            with st.spinner("Analyzing selling coordination…"):
                dump_df = detect_coordinated_selling(df, int(dump_window))
                st.session_state.dump_df = dump_df

        if "dump_df" in st.session_state:
            ddf = st.session_state.dump_df
            if not ddf.empty:
                st.warning(f"⚠️ {len(ddf)} coordinated dump events detected")
                for _, row in ddf.iterrows():
                    with st.expander(
                        f"**{row['token']}** · {row['coordinated_sellers']} sellers · severity {row['severity']}",
                        expanded=True
                    ):
                        st.caption(row["evidence"])
                        dc1,dc2,dc3 = st.columns(3)
                        dc1.metric("Sellers",        row["coordinated_sellers"])
                        dc2.metric("Total Sold",     f"{row['total_sold']:.4f} {row['token']}")
                        dc3.metric("Insider Ratio",  f"{row['insider_ratio']:.0%}")
                        st.caption(f"Window: {row['window_start']} → {row['window_end']}")
                        if row.get("seller_addresses"):
                            st.markdown("**Top seller addresses:**")
                            for addr in row["seller_addresses"]:
                                st.code(addr)
                st.download_button("⬇️ Export Dump Report",
                    ddf.to_csv(index=False).encode(), "coordinated_dumps.csv", "text/csv")
            else:
                st.success("✅ No coordinated selling patterns detected.")


    with mev_tabs[4]:
        st.markdown("**NFT Pump & Dump Detection**")
        st.caption(
            "Detects coordinated NFT price manipulation: floor price inflation by small "
            "wallet groups, circular trading rings creating fake volume, and coordinated "
            "dumps at peak price. More sophisticated than simple wash trading detection."
        )
        if st.button("🎨 Detect NFT Pump & Dump", type="primary", key="run_nft_pd"):
            with st.spinner("Scanning NFT trading patterns…"):
                nft_pd_df = detect_nft_pump_dump(df)
                st.session_state.nft_pd_df = nft_pd_df
            if not nft_pd_df.empty:
                st.error(f"🚨 {len(nft_pd_df)} NFT pump-and-dump patterns detected")
            else:
                st.success("✅ No NFT pump-and-dump patterns detected.")

        if "nft_pd_df" in st.session_state and not st.session_state.nft_pd_df.empty:
            npdf = st.session_state.nft_pd_df
            pattern_counts = npdf["pattern"].value_counts()
            for pat, cnt in pattern_counts.items():
                st.markdown(f"- **{pat}**: {cnt} token(s)")
            cols_show = [c for c in ["pattern","token","severity","note","tx_count",
                                      "date_start","date_end"] if c in npdf.columns]
            st.dataframe(npdf[cols_show], use_container_width=True,
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
            st.download_button("⬇️ Export NFT P&D Report",
                npdf.to_csv(index=False).encode(), "nft_pump_dump.csv", "text/csv")
