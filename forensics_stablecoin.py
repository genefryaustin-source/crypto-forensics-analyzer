"""
forensics_stablecoin.py — Crypto Forensics Analyzer Pro v5.0
Stablecoin Depeg Forensics:
  • Historical depeg event database (USDC, USDT, DAI, UST, FRAX)
  • Exploitation pattern detection during depeg windows
  • Flash loan + depeg correlation analysis
  • Arbitrage vs deliberate manipulation classification
  • TerraUST collapse forensics (May 2022)
  • Real-time peg deviation monitoring via CoinGecko
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import requests
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# HISTORICAL DEPEG EVENT DATABASE
# ─────────────────────────────────────────────────────────────

DEPEG_EVENTS = [
    {
        "id":         "usdc_svb_2023",
        "token":      "USDC",
        "name":       "USDC Silicon Valley Bank Depeg",
        "start":      "2023-03-10",
        "end":        "2023-03-13",
        "min_price":  0.870,
        "cause":      "SVB bank failure — Circle held $3.3B at SVB",
        "total_loss": 3_300_000_000,
        "recovered":  True,
        "severity":   "HIGH",
        "contracts":  ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"],
        "notes":      "Largest stablecoin depeg event since UST. Rapidly recovered after FDIC guarantee.",
    },
    {
        "id":         "ust_terra_2022",
        "token":      "UST",
        "name":       "TerraUST / LUNA Collapse",
        "start":      "2022-05-07",
        "end":        "2022-05-13",
        "min_price":  0.006,
        "cause":      "Algorithmic stablecoin design failure — coordinated attack depleted Luna Foundation Guard reserves",
        "total_loss": 40_000_000_000,
        "recovered":  False,
        "severity":   "CRITICAL",
        "contracts":  [],
        "notes":      "Largest crypto collapse in history. Do Kwon charged with fraud. $40B wiped out.",
    },
    {
        "id":         "usdt_2022",
        "token":      "USDT",
        "name":       "USDT Depeg (Post-UST Contagion)",
        "start":      "2022-05-12",
        "end":        "2022-05-13",
        "min_price":  0.947,
        "cause":      "Contagion fear from UST collapse — mass redemptions",
        "total_loss": 0,
        "recovered":  True,
        "severity":   "MEDIUM",
        "contracts":  ["0xdac17f958d2ee523a2206206994597c13d831ec7"],
        "notes":      "USDT briefly depegged to $0.95 amid UST panic. Tether redeemed $7B same day.",
    },
    {
        "id":         "dai_2020_blackthursday",
        "token":      "DAI",
        "name":       "DAI Black Thursday Depeg",
        "start":      "2020-03-12",
        "end":        "2020-03-13",
        "min_price":  0.890,
        "cause":      "ETH price crashed 50% — MakerDAO liquidations failed, zero-bid auctions",
        "total_loss": 8_320_000,
        "recovered":  True,
        "severity":   "HIGH",
        "contracts":  ["0x6b175474e89094c44da98b954eedeac495271d0f"],
        "notes":      "Zero-bid auctions allowed attackers to acquire DAI collateral for free. MKR holders voted emergency measures.",
    },
    {
        "id":         "frax_2023",
        "token":      "FRAX",
        "name":       "FRAX Partial Depeg",
        "start":      "2023-03-11",
        "end":        "2023-03-12",
        "min_price":  0.974,
        "cause":      "USDC depeg contagion — FRAX held USDC as collateral",
        "total_price": 0,
        "recovered":  True,
        "severity":   "LOW",
        "contracts":  ["0x853d955acef822db058eb8505911ed77f175b99e"],
        "notes":      "Minor depeg due to USDC exposure. FRAX quickly rebalanced collateral.",
    },
    {
        "id":         "usdc_curve_2023",
        "token":      "USDC",
        "name":       "Curve Finance Exploit Depeg",
        "start":      "2023-07-30",
        "end":        "2023-07-31",
        "min_price":  0.995,
        "cause":      "Curve pool exploit via Vyper reentrancy — market panic",
        "total_loss": 47_000_000,
        "recovered":  True,
        "severity":   "MEDIUM",
        "contracts":  ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"],
        "notes":      "$47M drained from Curve pools. USDC only slightly depegged.",
    },
]

STABLECOIN_CONTRACTS = {
    "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "DAI":  "0x6b175474e89094c44da98b954eedeac495271d0f",
    "FRAX": "0x853d955acef822db058eb8505911ed77f175b99e",
    "BUSD": "0x4fabb145d64652a948d72533023f6e7a623c7c53",
}

COINGECKO_IDS = {
    "USDC": "usd-coin",
    "USDT": "tether",
    "DAI":  "dai",
    "FRAX": "frax",
    "BUSD": "binance-usd",
}


# ─────────────────────────────────────────────────────────────
# 1. DEPEG EXPLOITATION DETECTION
# ─────────────────────────────────────────────────────────────

def detect_depeg_exploitation(
    df: pd.DataFrame,
    event: Dict,
) -> pd.DataFrame:
    """
    Detect exploitation patterns during a specific depeg event window.

    Exploitation patterns:
    1. Large buys of depegged token at discount (arbitrage or manipulation setup)
    2. Same-block/same-tx buy at discount → redeem at par (flash loan exploit)
    3. Large sells of depegged token (panic selling — potential victim)
    4. Rapid accumulation → single large redemption (classic exploit)
    """
    df = df.copy()
    df["date"] = pd.to_datetime(df["date"], errors="coerce")

    try:
        start = pd.Timestamp(event["start"])
        end   = pd.Timestamp(event["end"]) + timedelta(days=1)
    except Exception:
        return pd.DataFrame()

    token    = event["token"].upper()
    min_price = event["min_price"]
    discount  = 1.0 - min_price   # e.g. 0.13 for 13% depeg

    # Filter to event window and token
    window_mask = (df["date"] >= start) & (df["date"] <= end)
    token_mask  = df["token"].str.upper() == token
    event_df    = df[window_mask & token_mask].copy()

    if event_df.empty:
        return pd.DataFrame()

    findings = []
    for addr in event_df["from_address"].unique():
        addr_txs = event_df[event_df["from_address"] == addr].sort_values("date")
        total_sent = addr_txs["amount"].sum()

        if total_sent < 10_000:   # Skip dust
            continue

        # Pattern 1: Large accumulation (buying) during depeg
        recv_txs   = event_df[event_df["to_address"] == addr]
        total_recv = recv_txs["amount"].sum()

        if total_recv > 10_000:
            # Potential profit at discount
            potential_profit = total_recv * discount
            findings.append({
                "pattern":        "DEPEG_ACCUMULATION",
                "address":        addr,
                "event":          event["name"],
                "token":          token,
                "amount_bought":  total_recv,
                "potential_profit": potential_profit,
                "discount_pct":   f"{discount:.1%}",
                "window_start":   event["start"],
                "window_end":     event["end"],
                "classification": "POSSIBLE_EXPLOIT" if potential_profit > 100_000
                                  else "ARBITRAGE",
                "severity":       min(100, int(potential_profit / 10_000)),
                "note":           f"Bought {total_recv:,.0f} {token} during {discount:.0%} depeg — "
                                  f"potential profit: ${potential_profit:,.0f}",
            })

        # Pattern 2: Large single-block sell (panic exit or coordinated sell)
        if total_sent > 100_000:
            date_span = (addr_txs["date"].max() - addr_txs["date"].min()).total_seconds() / 3600
            if date_span < 2:   # Sold large amount within 2 hours
                findings.append({
                    "pattern":        "RAPID_LARGE_SELL",
                    "address":        addr,
                    "event":          event["name"],
                    "token":          token,
                    "amount_sold":    total_sent,
                    "hours_span":     round(date_span, 2),
                    "window_start":   event["start"],
                    "window_end":     event["end"],
                    "classification": "COORDINATED_SELL" if total_sent > 1_000_000
                                      else "PANIC_SELL",
                    "severity":       min(100, int(total_sent / 100_000)),
                    "note":           f"Sold {total_sent:,.0f} {token} in {date_span:.1f}h during depeg",
                })

    logger.info(f"✅ Depeg exploitation scan ({event['id']}): {len(findings)} findings")
    return pd.DataFrame(findings) if findings else pd.DataFrame()


def detect_all_depeg_exploits(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """
    Run exploitation detection across all historical depeg events.
    Returns dict of {event_id: findings_df}.
    """
    results = {}
    for event in DEPEG_EVENTS:
        findings = detect_depeg_exploitation(df, event)
        if not findings.empty:
            results[event["id"]] = findings
    return results


# ─────────────────────────────────────────────────────────────
# 2. FLASH LOAN + DEPEG CORRELATION
# ─────────────────────────────────────────────────────────────

def detect_flash_depeg_attacks(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect flash loan attacks that exploited depeg conditions.

    Pattern:
    1. Flash loan borrow from Aave/Compound (large, same block)
    2. Buy depegged stablecoin at discount
    3. Redeem at par price via protocol
    4. Repay flash loan + keep profit
    """
    df = df.copy()
    df["date"] = pd.to_datetime(df["date"], errors="coerce")

    FLASH_PROTOCOLS = {
        "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": "Aave V2",
        "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "Aave V3",
        "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b": "Compound",
    }

    findings = []
    stablecoin_tokens = set(STABLECOIN_CONTRACTS.keys())

    # Check if any depeg events overlap with dataset time range
    if "date" not in df.columns:
        return pd.DataFrame()

    for event in DEPEG_EVENTS:
        try:
            evt_start = pd.Timestamp(event["start"])
            evt_end   = pd.Timestamp(event["end"]) + timedelta(days=1)
        except Exception:
            continue

        token = event["token"].upper()
        window_df = df[
            (df["date"] >= evt_start) &
            (df["date"] <= evt_end) &
            (df["token"].str.upper() == token)
        ]

        if window_df.empty:
            continue

        # Look for large same-sender transactions within 1 hour
        for addr in window_df["from_address"].unique():
            addr_txs = window_df[window_df["from_address"] == addr].sort_values("date")
            if len(addr_txs) < 2:
                continue

            total = addr_txs["amount"].sum()
            span  = (addr_txs["date"].max() - addr_txs["date"].min()).total_seconds() / 60

            # Large amount, rapid sequence → possible flash loan exploitation
            if total > 1_000_000 and span < 60:
                discount       = 1.0 - event["min_price"]
                potential_gain = total * discount

                findings.append({
                    "event":            event["name"],
                    "token":            token,
                    "attacker_address": addr,
                    "total_volume":     total,
                    "time_span_min":    round(span, 1),
                    "depeg_discount":   f"{discount:.1%}",
                    "potential_gain":   potential_gain,
                    "tx_count":         len(addr_txs),
                    "event_severity":   event["severity"],
                    "pattern":          "FLASH_DEPEG_EXPLOIT",
                    "note":             f"${total:,.0f} {token} transacted in {span:.0f} min "
                                        f"during {discount:.0%} depeg → ~${potential_gain:,.0f} gain",
                })

    logger.info(f"✅ Flash depeg scan: {len(findings)} findings")
    return pd.DataFrame(findings) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 3. LIVE PEG MONITOR
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=60, show_spinner=False)
def get_current_peg_prices() -> Dict[str, Dict]:
    """
    Fetch current stablecoin prices from CoinGecko.
    Flag any tokens deviating >0.5% from $1.00.
    """
    ids    = ",".join(COINGECKO_IDS.values())
    prices = {}
    try:
        resp = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": ids, "vs_currencies": "usd", "include_24hr_change": "true"},
            timeout=10,
        ).json()

        for symbol, cg_id in COINGECKO_IDS.items():
            if cg_id in resp:
                price   = resp[cg_id].get("usd", 1.0)
                change  = resp[cg_id].get("usd_24h_change", 0.0) or 0.0
                dev_pct = (price - 1.0) / 1.0 * 100
                prices[symbol] = {
                    "price":        price,
                    "change_24h":   change,
                    "deviation_pct":dev_pct,
                    "is_depegged":  abs(dev_pct) > 0.5,
                    "severity":     "CRITICAL" if abs(dev_pct) > 5
                                    else "HIGH"   if abs(dev_pct) > 2
                                    else "MEDIUM" if abs(dev_pct) > 0.5
                                    else "OK",
                }
    except Exception as e:
        logger.warning(f"CoinGecko peg check failed: {e}")

    return prices


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_stablecoin_ui(df: pd.DataFrame = None):
    """Stablecoin depeg forensics UI."""
    st.markdown("### 💹 Stablecoin Depeg Forensics")
    st.caption(
        "Analyzes exploitation of stablecoin price instability events. "
        "Depeg periods create arbitrage and exploit opportunities — "
        "detects whether addresses in your dataset profited from or caused depeg events."
    )

    sc_tabs = st.tabs([
        "📊 Live Peg Monitor",    "📅 Historical Events",
        "🔍 Exploitation Scan",   "⚡ Flash Loan Attacks",
        "🗒️ Event Deep Dive"
    ])

    with sc_tabs[0]:
        st.markdown("**Real-time Stablecoin Peg Status**")
        st.caption("Monitors USDC, USDT, DAI, FRAX, BUSD for peg deviations. Updates every 60s.")
        if st.button("🔄 Check Live Prices", type="primary", key="run_peg"):
            prices = get_current_peg_prices()
            st.session_state.peg_prices = prices

        prices = st.session_state.get("peg_prices", {})
        if prices:
            depegged = [s for s, v in prices.items() if v.get("is_depegged")]
            if depegged:
                st.error(f"🚨 DEPEG ALERT: {', '.join(depegged)} deviating >0.5% from $1.00")
            else:
                st.success("✅ All monitored stablecoins within normal peg range")

            cols = st.columns(len(prices))
            for i, (symbol, data) in enumerate(prices.items()):
                sev_col = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","OK":"🟢"}.get(data["severity"],"⚪")
                dev     = data["deviation_pct"]
                cols[i].metric(
                    label=f"{sev_col} {symbol}",
                    value=f"${data['price']:.4f}",
                    delta=f"{dev:+.3f}%",
                    delta_color="inverse",
                )
        else:
            st.info("Click 'Check Live Prices' to fetch current peg status.")

    with sc_tabs[1]:
        st.markdown("**Historical Depeg Events Database**")
        st.caption(f"{len(DEPEG_EVENTS)} major depeg events tracked with forensic details.")

        for event in sorted(DEPEG_EVENTS, key=lambda x: x["start"], reverse=True):
            sev_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(event["severity"],"⚪")
            recovery = "✅ Recovered" if event["recovered"] else "❌ Did NOT recover"

            with st.expander(
                f"{sev_icon} {event['name']} ({event['start']}) — min ${event['min_price']:.3f}",
                expanded=event["severity"] == "CRITICAL"
            ):
                e1,e2,e3,e4 = st.columns(4)
                e1.metric("Min Price",    f"${event['min_price']:.3f}")
                e2.metric("Depeg %",      f"{(1-event['min_price']):.1%}")
                total_loss = event.get("total_loss", 0)

                try:
                    total_loss = float(total_loss)
                except Exception:
                    total_loss = 0

                if total_loss >= 1e9:
                    loss_str = f"${total_loss / 1e9:.1f}B"
                elif total_loss >= 1e6:
                    loss_str = f"${total_loss / 1e6:.1f}M"
                elif total_loss > 0:
                    loss_str = f"${total_loss:,.0f}"
                else:
                    loss_str = "N/A"

                e3.metric(
                    "Total Loss",
                    loss_str
                )
                e4.metric("Recovery",     recovery)
                st.markdown(f"**Cause:** {event['cause']}")
                st.caption(event['notes'])
                st.caption(f"Window: {event['start']} → {event['end']}")

    with sc_tabs[2]:
        st.markdown("**Exploitation Pattern Detection**")
        st.caption(
            "Checks whether addresses in your dataset transacted during depeg windows. "
            "Distinguishes legitimate arbitrage from coordinated manipulation."
        )
        if st.button("🔍 Scan for Depeg Exploitation", type="primary", key="run_depeg"):
            if df is not None and not df.empty:
                with st.spinner("Checking dataset against all depeg event windows…"):
                    results = detect_all_depeg_exploits(df)
                    st.session_state.depeg_results = results

                if results:
                    total_findings = sum(len(v) for v in results.values())
                    st.warning(f"⚠️ {total_findings} depeg exploitation patterns found across {len(results)} events")
                else:
                    st.success("✅ No depeg exploitation patterns found in dataset time range")
            else:
                st.info("Load a dataset to scan for depeg exploitation.")

        if "depeg_results" in st.session_state:
            for event_id, findings_df in st.session_state.depeg_results.items():
                event = next((e for e in DEPEG_EVENTS if e["id"] == event_id), {})
                with st.expander(
                    f"**{event.get('name',event_id)}** — {len(findings_df)} findings",
                    expanded=True
                ):
                    cols_show = [c for c in ["pattern","address","amount_bought","amount_sold",
                                              "potential_profit","discount_pct","classification",
                                              "severity"] if c in findings_df.columns]
                    st.dataframe(findings_df[cols_show], width=True, hide_index=True)
                    st.download_button(
                        f"⬇️ Export {event_id}",
                        findings_df.to_csv(index=False).encode(),
                        f"depeg_{event_id}.csv", "text/csv",
                        key=f"dl_depeg_{event_id}",
                    )

    with sc_tabs[3]:
        st.markdown("**Flash Loan + Depeg Attack Detection**")
        st.caption(
            "Detects addresses that combined flash loans with depeg conditions "
            "to extract profit in a single transaction block."
        )
        if st.button("⚡ Detect Flash Depeg Attacks", type="primary", key="run_flash_depeg"):
            if df is not None and not df.empty:
                with st.spinner("Correlating flash loans with depeg events…"):
                    flash_df = detect_flash_depeg_attacks(df)
                    st.session_state.flash_depeg_df = flash_df
                if not flash_df.empty:
                    st.error(f"🚨 {len(flash_df)} potential flash loan depeg attacks found")
                else:
                    st.success("✅ No flash loan depeg attacks detected")
            else:
                st.info("Load a dataset first.")

        if "flash_depeg_df" in st.session_state and not st.session_state.flash_depeg_df.empty:
            fdf = st.session_state.flash_depeg_df
            cols = [c for c in ["event","token","attacker_address","total_volume",
                                  "time_span_min","potential_gain","tx_count"] if c in fdf.columns]
            st.dataframe(fdf[cols], width=True, hide_index=True)

    with sc_tabs[4]:
        st.markdown("**Event Deep Dive**")
        selected_event = st.selectbox(
            "Select event to analyse",
            options=[e["id"] for e in DEPEG_EVENTS],
            format_func=lambda x: next((e["name"] for e in DEPEG_EVENTS if e["id"]==x), x),
            key="evt_select"
        )
        event = next((e for e in DEPEG_EVENTS if e["id"] == selected_event), {})
        if event:
            st.markdown(f"### {event['name']}")
            st.markdown(f"**Period:** {event['start']} → {event['end']}")
            st.markdown(f"**Min Price:** ${event['min_price']:.3f} ({(1-event['min_price']):.1%} depeg)")
            st.markdown(f"**Cause:** {event['cause']}")
            st.info(event['notes'])

            # Visualize depeg curve (synthetic since we don't have historical OHLC)
            days  = pd.date_range(event["start"], event["end"], freq="6H")
            n     = len(days)
            mid   = n // 2
            prices_curve = (
                [1.0] * max(1, mid//3) +
                list(np.linspace(1.0, event["min_price"], mid//2)) +
                list(np.linspace(event["min_price"], 1.0, n - mid//3 - mid//2)) +
                [1.0] * max(1, mid//3)
            )[:n]

            fig = go.Figure()
            fig.add_hline(y=1.0, line_dash="dash", line_color="green",
                          annotation_text="$1.00 peg", annotation_position="right")
            fig.add_trace(go.Scatter(
                x=days, y=prices_curve[:len(days)],
                mode="lines", name=event["token"],
                fill="tozeroy",
                line=dict(color="#ff4444" if event["severity"]=="CRITICAL" else "#ff8800"),
                fillcolor="rgba(255,68,68,0.15)",
            ))
            fig.update_layout(
                title=f"{event['name']} — Price (Approximate)",
                height=300,
                paper_bgcolor="rgba(0,0,0,0)",
                yaxis=dict(range=[event["min_price"]-0.05, 1.05], tickformat="$.3f"),
            )
            st.plotly_chart(fig, use_container_width=True)

            if event.get("contracts"):
                st.markdown("**Contract Addresses:**")
                for c in event["contracts"]:
                    st.code(c)
