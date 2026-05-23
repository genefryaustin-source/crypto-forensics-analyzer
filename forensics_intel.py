"""
forensics_intel.py  —  Crypto Forensics Analyzer Pro v5.0
Advanced intelligence layer: structuring, velocity, network graph,
wallet profiler, peeling chain, and case notes.
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# 1. STRUCTURING / SMURFING DETECTOR
#    Detects transactions broken into chunks just below reporting
#    thresholds — classic AML typology (FATF #3, FinCEN §1010.314)
# ─────────────────────────────────────────────────────────────

REPORTING_THRESHOLDS = {
    "USD": [10_000, 3_000, 1_000],   # CTR / MSB / SAR triggers
    "USDT": [10_000, 3_000, 1_000],
    "USDC": [10_000, 3_000, 1_000],
    "DAI":  [10_000, 3_000, 1_000],
    "ETH":  [5.0, 1.0],              # Approximate USD equivalents vary; use conservative thresholds
    "BTC":  [0.15, 0.04],
    "BNB":  [15.0, 3.0],
    "TRX":  [80_000, 25_000],
}
JUST_BELOW_PCT = 0.15   # Flag if within 15% below threshold


@st.cache_data(show_spinner=False)
def detect_structuring(
    df: pd.DataFrame,
    time_window_hours: int = 24,
    min_transactions: int = 3,
) -> List[Dict]:
    """
    Detect structuring (smurfing): multiple transactions just below
    reporting thresholds from the same address within a time window.

    Returns list of structuring events sorted by severity.
    """
    logger.info("Scanning for structuring patterns…")
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
    window   = timedelta(hours=time_window_hours)

    for addr in df["from_address"].unique():
        addr_txs = df[df["from_address"] == addr].copy()
        if len(addr_txs) < min_transactions:
            continue

        for token, thresholds in REPORTING_THRESHOLDS.items():
            token_txs = addr_txs[addr_txs["token"].str.upper() == token.upper()]
            if len(token_txs) < min_transactions:
                continue

            for threshold in thresholds:
                low  = threshold * (1 - JUST_BELOW_PCT)
                # Transactions just below threshold
                near = token_txs[(token_txs["amount"] >= low) & (token_txs["amount"] < threshold)]
                if len(near) < min_transactions:
                    continue

                # Sliding window: look for N+ in the window
                near = near.sort_values("date")
                dates = near["date"].tolist()
                for i in range(len(dates)):
                    window_txs = near[(near["date"] >= dates[i]) & (near["date"] <= dates[i] + window)]
                    if len(window_txs) >= min_transactions:
                        total = window_txs["amount"].sum()
                        severity = min(100, int(
                            (len(window_txs) / min_transactions) * 30 +
                            (total / threshold) * 20 +
                            30
                        ))
                        findings.append({
                            "address":          addr,
                            "token":            token,
                            "threshold":        threshold,
                            "tx_count":         len(window_txs),
                            "total_amount":     total,
                            "avg_amount":       window_txs["amount"].mean(),
                            "time_window_hrs":  (window_txs["date"].max() - window_txs["date"].min()).total_seconds() / 3600,
                            "first_tx":         str(window_txs["date"].min()),
                            "last_tx":          str(window_txs["date"].max()),
                            "tx_hashes":        window_txs["tx_hash"].tolist()[:5],
                            "severity":         severity,
                            "typology":         "STRUCTURING / SMURFING",
                            "fatf_ref":         "FATF Typology #3 — Structuring",
                            "sar_indicator":    True,
                        })
                        break   # One finding per address/token/threshold combo

    logger.info(f"✅ Found {len(findings)} structuring patterns")
    return sorted(findings, key=lambda x: x["severity"], reverse=True)


# ─────────────────────────────────────────────────────────────
# 2. VELOCITY ANALYSIS
#    Time between receiving and re-sending funds. Very fast
#    turnaround (< 1 hour) strongly indicates automated layering.
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def analyze_velocity(df: pd.DataFrame) -> pd.DataFrame:
    """
    For each address: calculate time-to-forward (TTF) — how quickly
    received funds are sent on. Short TTF = high automation risk.

    Returns DataFrame of addresses with velocity metrics.
    """
    logger.info("Calculating velocity metrics…")
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
    df = df.dropna(subset=["date"])

    inbound  = df.groupby("to_address")["date"].min().rename("first_received")
    outbound = df.groupby("from_address")["date"].min().rename("first_sent")

    velocity = pd.concat([inbound, outbound], axis=1).dropna()
    velocity["ttf_hours"]   = (velocity["first_sent"] - velocity["first_received"]).dt.total_seconds() / 3600
    velocity = velocity[velocity["ttf_hours"] >= 0]   # Ignore impossible negative values
    velocity["ttf_minutes"] = (velocity["ttf_hours"] * 60).round(1)

    # Enrich with volume
    in_vol  = df.groupby("to_address")["amount"].sum().rename("volume_received")
    out_vol = df.groupby("from_address")["amount"].sum().rename("volume_sent")
    velocity = velocity.join(in_vol, how="left").join(out_vol, how="left")
    velocity["pass_through_ratio"] = (
        velocity["volume_sent"] / velocity["volume_received"].replace(0, np.nan)
    ).clip(0, 5)

    # Risk classification
    conditions = [
        velocity["ttf_hours"] < 0.25,    # < 15 min
        velocity["ttf_hours"] < 1,
        velocity["ttf_hours"] < 6,
        velocity["ttf_hours"] < 24,
    ]
    labels = ["🔴 INSTANT (<15min)", "🟠 RAPID (<1hr)", "🟡 FAST (<6hr)", "🟢 SAME_DAY"]
    velocity["velocity_class"] = np.select(conditions, labels, default="⚪ NORMAL")
    velocity["velocity_score"] = np.where(
        velocity["ttf_hours"] < 0.25, 95,
        np.where(velocity["ttf_hours"] < 1, 75,
        np.where(velocity["ttf_hours"] < 6, 45,
        np.where(velocity["ttf_hours"] < 24, 20, 5)))
    )

    return velocity.reset_index().rename(columns={"index": "address"}).sort_values("velocity_score", ascending=False)


def plot_velocity_distribution(velocity_df: pd.DataFrame) -> go.Figure:
    """Histogram of time-to-forward distribution."""
    df2 = velocity_df[velocity_df["ttf_hours"] <= 72].copy()
    fig = px.histogram(
        df2, x="ttf_hours", nbins=60,
        color="velocity_class",
        color_discrete_map={
            "🔴 INSTANT (<15min)": "#ff4444",
            "🟠 RAPID (<1hr)":     "#ff8800",
            "🟡 FAST (<6hr)":      "#ffcc00",
            "🟢 SAME_DAY":         "#22c55e",
            "⚪ NORMAL":           "#888888",
        },
        title="⚡ Time-to-Forward Distribution (hours) — shorter = higher risk",
        labels={"ttf_hours": "Hours between receive → re-send", "count": "Addresses"},
    )
    fig.add_vline(x=1,  line_dash="dash", line_color="#ff8800", annotation_text="1 hr")
    fig.add_vline(x=24, line_dash="dash", line_color="#22c55e", annotation_text="24 hr")
    fig.update_layout(height=380, paper_bgcolor="rgba(0,0,0,0)")
    return fig


# ─────────────────────────────────────────────────────────────
# 3. NETWORK GRAPH  (force-directed, better than Sankey alone)
#    Nodes = addresses, edges = fund flows, size = volume,
#    color = risk level. Shows clusters and hub addresses clearly.
# ─────────────────────────────────────────────────────────────

def build_network_graph(
    df: pd.DataFrame,
    max_nodes: int = 60,
    min_amount: float = 0,
) -> go.Figure:
    """
    Build an interactive force-directed network graph using Plotly.
    Nodes = addresses, edges = transactions, size = volume.
    """
    import networkx as nx

    df2 = df[df["amount"] >= min_amount].copy()
    df2 = df2.dropna(
        subset=["from_address", "to_address", "amount"]
    )
    flows = (
        df2.groupby(["from_address", "to_address"])
        .agg(total=("amount", "sum"), count=("amount", "size"),
             risk=("risk_level", lambda x: x.mode()[0] if len(x) else "LOW"))
        .reset_index()
        .nlargest(max_nodes * 2, "total")
    )

    G = nx.DiGraph()
    for _, row in flows.iterrows():
        G.add_edge(row["from_address"], row["to_address"],
                   weight=row["total"], count=row["count"], risk=row["risk"])

    if len(G.nodes) == 0:
        return None

    # Limit to top nodes by degree * volume
    if len(G.nodes) > max_nodes:
        node_scores = {n: G.degree(n) * (df2[
            (df2["from_address"]==n)|(df2["to_address"]==n)
        ]["amount"].sum()) for n in G.nodes}
        top_nodes = sorted(node_scores, key=node_scores.get, reverse=True)[:max_nodes]
        G = G.subgraph(top_nodes).copy()

    # Layout
    try:
        pos = nx.spring_layout(G, k=2.5/max(1, len(G.nodes)**0.5), seed=42, iterations=50)
    except Exception:
        pos = nx.random_layout(G, seed=42)

    RCOL = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#22c55e"}

    # Risk map per node
    risk_map = {}
    if "risk_level" in df2.columns:
        for addr in G.nodes:
            lvls = df2[(df2["from_address"]==addr)|(df2["to_address"]==addr)]["risk_level"]
            if len(lvls):
                order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
                risk_map[addr] = max(lvls.unique(), key=lambda x: order.get(x,0))

    # Edge traces
    edge_traces = []
    for u, v, data in G.edges(data=True):
        x0,y0 = pos[u]; x1,y1 = pos[v]
        risk = data.get("risk","LOW")
        color = RCOL.get(risk,"#555555")
        w = max(0.5, min(6, np.log1p(data["weight"]) * 0.4))
        edge_traces.append(go.Scatter(
            x=[x0,x1,None], y=[y0,y1,None],
            mode="lines",
            line=dict(width=w, color=color),
            opacity=0.45,
            hoverinfo="none",
            showlegend=False,
        ))

    # Node trace
    node_x, node_y, node_text, node_color, node_size, node_hover = [], [], [], [], [], []
    vol_map = df2.groupby("from_address")["amount"].sum().to_dict()

    for node in G.nodes:
        x, y = pos[node]
        node_x.append(x); node_y.append(y)
        risk  = risk_map.get(node, "LOW")
        vol   = vol_map.get(node, 0)
        label = str(node)[:10]+"…" if len(str(node))>10 else str(node)
        node_text.append(label)
        node_color.append(RCOL.get(risk, "#888888"))
        node_size.append(max(12, min(45, 8 + np.log1p(vol) * 2)))
        node_hover.append(
            f"<b>{node}</b><br>Risk: {risk}<br>"
            f"Volume out: ${vol:,.0f}<br>Connections: {G.degree(node)}"
        )

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode="markers+text",
        text=node_text, textposition="top center",
        textfont=dict(size=8),
        marker=dict(size=node_size, color=node_color,
                    line=dict(width=1.5, color="rgba(255,255,255,0.5)")),
        hovertext=node_hover, hoverinfo="text",
        showlegend=False,
    )

    fig = go.Figure(data=edge_traces + [node_trace])

    # Legend
    for risk, col in RCOL.items():
        fig.add_trace(go.Scatter(
            x=[None], y=[None], mode="markers",
            marker=dict(size=10, color=col),
            name=risk, showlegend=True,
        ))

    fig.update_layout(
        title="🕸️ Transaction Network Graph — node size = volume, color = risk",
        showlegend=True,
        hovermode="closest",
        height=600,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        legend=dict(orientation="h", yanchor="bottom", y=1.01, xanchor="right", x=1),
    )
    return fig


# ─────────────────────────────────────────────────────────────
# 4. WALLET PROFILER
#    Full forensic profile for any address in the dataset
# ─────────────────────────────────────────────────────────────

def profile_wallet(df: pd.DataFrame, address: str) -> Dict:
    """
    Generate a full forensic profile for a single address.
    Works on the loaded dataset — no API calls needed.
    """
    addr_lower = str(address).lower()
    outbound = df[
        df["from_address"].astype(str).str.lower() == addr_lower
        ]

    inbound = df[
        df["to_address"].astype(str).str.lower() == addr_lower
        ]

    if outbound.empty and inbound.empty:
        return {"error": f"Address {address} not found in dataset."}

    all_txs  = pd.concat([outbound, inbound]).drop_duplicates("tx_hash")
    dates    = pd.to_datetime(all_txs["date"], errors="coerce").dropna()

    # Counterparties
    sent_to   = outbound["to_address"].value_counts().head(10).to_dict()
    recv_from = inbound["from_address"].value_counts().head(10).to_dict()

    # Risk distribution
    risk_dist = {}
    if "risk_level" in all_txs.columns:
        risk_dist = all_txs["risk_level"].value_counts().to_dict()

    # Velocity
    ttf = None
    if not inbound.empty and not outbound.empty:
        first_in  = pd.to_datetime(inbound["date"],  errors="coerce").min()
        first_out = pd.to_datetime(outbound["date"], errors="coerce").min()
        if pd.notna(first_in) and pd.notna(first_out) and first_out > first_in:
            ttf = (first_out - first_in).total_seconds() / 3600

    # Token breakdown
    tokens_sent = outbound.groupby("token")["amount"].sum().to_dict()
    tokens_recv = inbound.groupby("token")["amount"].sum().to_dict()

    # Anomaly flag
    high_risk_txs = all_txs[all_txs.get("risk_level", "LOW") == "CRITICAL"] if "risk_level" in all_txs.columns else pd.DataFrame()

    profile = {
        "address":              address,
        "first_seen":           str(dates.min()) if len(dates) else "—",
        "last_seen":            str(dates.max()) if len(dates) else "—",
        "active_days":          (dates.max() - dates.min()).days if len(dates) > 1 else 0,
        "total_transactions":   len(all_txs),
        "outbound_count":       len(outbound),
        "inbound_count":        len(inbound),
        "total_sent":           outbound["amount"].sum(),
        "total_received":       inbound["amount"].sum(),
        "net_flow":             inbound["amount"].sum() - outbound["amount"].sum(),
        "unique_senders":       inbound["from_address"].nunique(),
        "unique_recipients":    outbound["to_address"].nunique(),
        "tokens_used":          sorted(all_txs["token"].unique().tolist()),
        "chains":               sorted(all_txs["chain"].unique().tolist()) if "chain" in all_txs.columns else [],
        "top_counterparties_sent":  sent_to,
        "top_counterparties_recv":  recv_from,
        "risk_distribution":    risk_dist,
        "critical_tx_count":    len(high_risk_txs),
        "time_to_forward_hrs":  round(ttf, 2) if ttf is not None else None,
        "tokens_sent_volume":   tokens_sent,
        "tokens_recv_volume":   tokens_recv,
        "avg_tx_size":          outbound["amount"].mean() if len(outbound) else 0,
        "max_single_tx":        outbound["amount"].max() if len(outbound) else 0,
        "pass_through_ratio":   round(outbound["amount"].sum() / max(inbound["amount"].sum(), 0.001), 3),
    }

    # Overall risk verdict
    score = 0
    if profile["time_to_forward_hrs"] is not None and profile["time_to_forward_hrs"] < 1:
        score += 30
    if profile["critical_tx_count"] > 0:
        score += 40
    if profile["unique_recipients"] > 20:
        score += 15
    if profile["pass_through_ratio"] > 0.9:
        score += 15
    profile["profile_risk_score"] = min(score, 100)
    profile["profile_risk_level"] = (
        "CRITICAL" if score >= 80 else
        "HIGH"     if score >= 60 else
        "MEDIUM"   if score >= 35 else "LOW"
    )

    return profile


def render_wallet_profile(profile: Dict):
    """Render a wallet profile in Streamlit."""
    if "error" in profile:
        st.error(profile["error"])
        return

    risk_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    lvl = profile["profile_risk_level"]
    st.markdown(f"### {risk_colors.get(lvl,'⚪')} `{profile['address']}` — Risk: **{lvl}** ({profile['profile_risk_score']}/100)")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Tx",          profile["total_transactions"])
    c2.metric("Total Sent",        f"${profile['total_sent']:,.2f}")
    c3.metric("Total Received",    f"${profile['total_received']:,.2f}")
    c4.metric("Unique Recipients", profile["unique_recipients"])
    c5.metric("Active Days",       profile["active_days"])

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Activity**")
        st.markdown(f"- First seen: `{profile['first_seen'][:10]}`")
        st.markdown(f"- Last seen:  `{profile['last_seen'][:10]}`")
        st.markdown(f"- Chains: {', '.join(profile['chains']) or '—'}")
        st.markdown(f"- Tokens: {', '.join(profile['tokens_used'][:8])}")
        ttf = profile["time_to_forward_hrs"]
        if ttf is not None:
            ttf_flag = "🔴 INSTANT" if ttf < 0.25 else "🟠 RAPID" if ttf < 1 else "🟡 FAST" if ttf < 6 else "🟢 Normal"
            st.markdown(f"- Time-to-forward: `{ttf:.1f} hrs` {ttf_flag}")
        st.markdown(f"- Pass-through ratio: `{profile['pass_through_ratio']:.2f}` {'⚠️ HIGH' if profile['pass_through_ratio'] > 0.85 else ''}")

    with col_b:
        st.markdown("**Top Recipients**")
        for addr, cnt in list(profile["top_counterparties_sent"].items())[:5]:
            st.markdown(f"- `{addr[:20]}…` — {cnt} tx(s)")

    if profile["risk_distribution"]:
        st.markdown("**Risk Distribution**")
        rd = profile["risk_distribution"]
        cols = st.columns(len(rd))
        for i, (lvl, cnt) in enumerate(rd.items()):
            cols[i].metric(lvl, cnt)


# ─────────────────────────────────────────────────────────────
# 5. PEELING CHAIN DETECTOR
#    Bitcoin/EVM pattern: funds stripped off in sequential hops
#    with decreasing amounts. Common in ransomware cashouts.
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def detect_peeling_chains(
    df: pd.DataFrame,
    min_hops: int = 3,
    tolerance_pct: float = 0.30,
) -> List[Dict]:
    """
    Detect peeling chain patterns: A sends 90% to B, keeps 10%.
    B sends 90% to C, keeps 10%. Common in ransomware and exit scams.

    Looks for sequences where each hop sends (1-fee) of received amount onward.
    """
    logger.info("Scanning for peeling chains…")
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
    df = df.sort_values("date")

    chains     = []
    visited    = set()

    for _, start_tx in df.iterrows():
        start_hash = start_tx["tx_hash"]
        if start_hash in visited:
            continue

        chain_path  = [start_tx.to_dict()]
        current_to  = start_tx["to_address"]
        current_amt = start_tx["amount"]

        for _ in range(20):   # Max chain depth
            # Find next outbound from current_to with similar (slightly smaller) amount
            current_to_safe = str(current_to).strip().lower()

            df2 = df.copy()

            df2["from_address"] = (
                df2["from_address"]
                .fillna("")
                .astype(str)
                .str.strip()
                .str.lower()
            )

            df2["amount"] = pd.to_numeric(
                df2["amount"],
                errors="coerce"
            ).fillna(0)

            candidates = df2[
                (
                        df2["from_address"] == current_to_safe
                )
                &
                (
                        df2["amount"] <= float(current_amt)
                )
                &
                (
                        df2["amount"] >= float(current_amt) * (1 - tolerance_pct)
                )
                ]

            if candidates.empty:
                break

            # Take the closest match
            next_tx = candidates.iloc[(candidates["amount"] - current_amt).abs().argsort()[:1]]
            next_row = next_tx.iloc[0]

            chain_path.append(next_row.to_dict())
            visited.add(next_row["tx_hash"])
            current_to  = next_row["to_address"]
            current_amt = next_row["amount"]

        if len(chain_path) >= min_hops:
            start_amt = chain_path[0]["amount"]
            end_amt   = chain_path[-1]["amount"]
            chains.append({
                "chain_length":    len(chain_path),
                "start_address":   chain_path[0]["from_address"],
                "end_address":     chain_path[-1]["to_address"],
                "start_amount":    start_amt,
                "end_amount":      end_amt,
                "total_peeled":    start_amt - end_amt,
                "peel_pct":        round((1 - end_amt / max(start_amt, 1)) * 100, 1),
                "addresses":       list({tx["from_address"] for tx in chain_path}),
                "tx_hashes":       [tx["tx_hash"] for tx in chain_path],
                "tokens":          list({tx["token"] for tx in chain_path}),
                "date_start":      str(chain_path[0].get("date", "")),
                "date_end":        str(chain_path[-1].get("date", "")),
                "severity":        min(100, len(chain_path) * 15 + int(start_amt > 10000) * 20),
                "typology":        "PEELING CHAIN",
            })

    logger.info(f"✅ Found {len(chains)} peeling chains")
    return sorted(chains, key=lambda x: x["severity"], reverse=True)


# ─────────────────────────────────────────────────────────────
# 6. CROSS-CHAIN CORRELATION
#    Detects same/similar amounts appearing on different chains
#    close together in time — bridge-and-continue patterns.
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def detect_cross_chain_hops(
    df: pd.DataFrame,
    time_window_hours: int = 6,
    amount_tolerance_pct: float = 0.05,
    min_amount: float = 1000,
) -> List[Dict]:
    """
    Find amounts that appear on one chain and reappear on a different
    chain within the time window — indicating bridge usage to obscure trail.
    """
    logger.info("Scanning for cross-chain hops…")

    if "chain" not in df.columns or df["chain"].nunique() < 2:
        return []

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
    df = df[df["amount"] >= min_amount].dropna(subset=["date"])

    hops = []
    chains = df["chain"].unique()

    for i, chain_a in enumerate(chains):
        for chain_b in chains[i+1:]:
            txs_a = df[df["chain"] == chain_a]
            txs_b = df[df["chain"] == chain_b]

            for _, tx_a in txs_a.iterrows():
                amt_a = tx_a["amount"]
                window_start = tx_a["date"]
                window_end   = tx_a["date"] + timedelta(hours=time_window_hours)

                # Find matching amount on chain_b within window
                tol = amt_a * amount_tolerance_pct
                matches = txs_b[
                    (txs_b["date"] >= window_start) &
                    (txs_b["date"] <= window_end)   &
                    (txs_b["amount"].between(amt_a - tol, amt_a + tol))
                ]

                for _, tx_b in matches.iterrows():
                    delta_hours = (tx_b["date"] - tx_a["date"]).total_seconds() / 3600
                    hops.append({
                        "chain_from":      chain_a,
                        "chain_to":        chain_b,
                        "amount":          amt_a,
                        "amount_chain_b":  tx_b["amount"],
                        "address_from":    tx_a["from_address"],
                        "address_to":      tx_b["to_address"],
                        "tx_hash_a":       tx_a["tx_hash"],
                        "tx_hash_b":       tx_b["tx_hash"],
                        "date_a":          str(tx_a["date"]),
                        "date_b":          str(tx_b["date"]),
                        "delta_hours":     round(delta_hours, 2),
                        "token_a":         tx_a["token"],
                        "token_b":         tx_b["token"],
                        "severity":        min(100, int(70 + (1 / max(delta_hours, 0.1)) * 5)),
                    })

    logger.info(f"✅ Found {len(hops)} cross-chain correlations")
    return sorted(hops, key=lambda x: x["severity"], reverse=True)[:100]   # Cap at 100


# ─────────────────────────────────────────────────────────────
# 7. CASE NOTES  (persisted as JSON in app directory)
#    Investigators can annotate addresses, tag transactions,
#    and record findings for each case.
# ─────────────────────────────────────────────────────────────

NOTES_FILE = Path(__file__).parent / "case_notes.json"


def _load_notes() -> Dict:
    if NOTES_FILE.exists():
        try:
            return json.loads(NOTES_FILE.read_text())
        except Exception:
            pass
    return {"cases": {}, "address_tags": {}, "tx_notes": {}}


def _save_notes(data: Dict):
    NOTES_FILE.write_text(json.dumps(data, indent=2, default=str))


def render_case_notes(df: Optional[pd.DataFrame] = None):
    """Render the full case notes UI in Streamlit."""
    notes = _load_notes()

    st.markdown("### 📁 Case Management")

    # Case selector
    case_col, new_col = st.columns([3, 1])
    with case_col:
        case_names = list(notes["cases"].keys()) or ["Default"]
        active_case = st.selectbox("Active Case", case_names, key="active_case_select")
    with new_col:
        new_case = st.text_input("New case name", key="new_case_input", placeholder="e.g. CASE-2024-001")
        if st.button("➕ Create", key="create_case_btn") and new_case:
            notes["cases"][new_case] = {
                "created": str(datetime.now()),
                "summary": "",
                "tags": [],
                "notes": [],
            }
            _save_notes(notes)
            st.success(f"Case '{new_case}' created")
            st.rerun()

    if active_case and active_case in notes["cases"]:
        case = notes["cases"][active_case]

        # Case summary
        summary = st.text_area("Case Summary", value=case.get("summary", ""),
                                height=80, key="case_summary_field")
        if st.button("💾 Save Summary", key="save_summary_btn"):
            notes["cases"][active_case]["summary"] = summary
            _save_notes(notes)
            st.success("Saved ✅")

        # Investigation notes
        st.markdown("**Investigation Notes**")
        new_note = st.text_area("Add note", height=60, key="new_note_field",
                                 placeholder="Add observation, finding, or action taken…")
        note_tag = st.selectbox("Tag", ["📋 General","🔴 Critical","🟠 High","💱 SAR","📞 Escalated","✅ Resolved"],
                                 key="note_tag_select")
        if st.button("➕ Add Note", key="add_note_btn") and new_note.strip():
            notes["cases"][active_case].setdefault("notes", []).append({
                "timestamp": str(datetime.now())[:19],
                "tag":       note_tag,
                "text":      new_note.strip(),
            })
            _save_notes(notes)
            st.success("Note added ✅")
            st.rerun()

        # Display notes
        for i, note in enumerate(reversed(case.get("notes", []))):
            with st.container():
                st.markdown(
                    f"**{note['tag']}** · `{note['timestamp']}`  \n{note['text']}"
                )
                if st.button("🗑️", key=f"del_note_{i}"):
                    case["notes"].pop(-(i+1))
                    _save_notes(notes)
                    st.rerun()
            st.divider()

    st.markdown("---")

    # Address tagging
    st.markdown("### 🏷️ Address Tags")
    col_addr, col_tag, col_note = st.columns([3, 2, 3])
    with col_addr:
        tag_addr = st.text_input("Address", key="tag_addr", placeholder="0x… or T…")
    with col_tag:
        tag_type = st.selectbox("Label", [
            "🔴 Suspect", "🟠 Under Review", "🏦 Exchange",
            "🔄 Mixer", "🐳 Whale", "✅ Cleared", "👤 Subject", "⚠️ Watchlist"
        ], key="tag_type")
    with col_note:
        tag_note = st.text_input("Note", key="tag_note_field", placeholder="e.g. linked to case #001")

    if st.button("🏷️ Tag Address", key="tag_addr_btn") and tag_addr.strip():
        notes["address_tags"][tag_addr.lower().strip()] = {
            "label":     tag_type,
            "note":      tag_note,
            "tagged_at": str(datetime.now())[:19],
            "case":      active_case,
        }
        _save_notes(notes)
        st.success(f"Tagged `{tag_addr}`")
        st.rerun()

    if notes["address_tags"]:
        tags_df = pd.DataFrame([
            {"address": k, **v} for k, v in notes["address_tags"].items()
        ])
        st.dataframe(tags_df, width='stretch', hide_index=True)

        # Export tags as CSV
        st.download_button(
            "⬇️ Export Tags CSV",
            tags_df.to_csv(index=False).encode(),
            "address_tags.csv", "text/csv",
        )


# ─────────────────────────────────────────────────────────────
# 8. STABLECOIN FLOW ANALYSIS
#    USDT/USDC are the most common laundering vehicles.
#    Flag high-value stablecoin flows with concentration analysis.
# ─────────────────────────────────────────────────────────────

STABLECOINS = {"USDT","USDC","DAI","BUSD","TUSD","FRAX","LUSD","GUSD","USDP","PYUSD"}

@st.cache_data(show_spinner=False)
def analyze_stablecoin_flows(df: pd.DataFrame) -> Dict:
    """
    Focused analysis on stablecoin transactions — common laundering vehicle.
    Returns concentration metrics, top flows, and risk flags.
    """
    stable_df = df[df["token"].str.upper().isin(STABLECOINS)].copy()

    if stable_df.empty:
        return {"empty": True}

    total_vol    = stable_df["amount"].sum()
    token_split  = stable_df.groupby("token")["amount"].sum().sort_values(ascending=False)
    top_senders  = stable_df.groupby("from_address")["amount"].sum().nlargest(10)
    top_receivers= stable_df.groupby("to_address")["amount"].sum().nlargest(10)

    # Concentration: what % of volume comes from top 10 addresses
    top10_vol    = top_senders.sum()
    concentration= top10_vol / max(total_vol, 1)

    # Round-number transactions (structuring indicator)
    round_txs = stable_df[stable_df["amount"].apply(lambda x: x == round(x, -3))]

    return {
        "empty":            False,
        "total_volume":     total_vol,
        "tx_count":         len(stable_df),
        "token_split":      token_split.to_dict(),
        "top_senders":      top_senders.to_dict(),
        "top_receivers":    top_receivers.to_dict(),
        "concentration":    concentration,
        "round_tx_count":   len(round_txs),
        "round_tx_volume":  round_txs["amount"].sum(),
        "avg_tx_size":      stable_df["amount"].mean(),
        "max_tx_size":      stable_df["amount"].max(),
        "stable_df":        stable_df,
    }
