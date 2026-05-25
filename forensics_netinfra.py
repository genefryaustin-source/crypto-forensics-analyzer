"""
forensics_netinfra.py — Crypto Forensics Analyzer Pro v5.0
Network Infrastructure Clustering:
  Groups addresses that share OPERATIONAL patterns rather than
  just transaction links. Goes beyond GNN graph clustering to
  identify the same human operator or bot infrastructure
  controlling multiple wallets.

  Features:
  • Operational hour clustering (timezone/schedule fingerprint)
  • Gas price strategy fingerprinting (same wallet software)
  • Transaction timing interval analysis (same automation)
  • Fee structure patterns (same operator preference)
  • Token sequence behavioral fingerprinting
  • Multi-dimensional infrastructure cluster visualization
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
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


from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# 1. OPERATIONAL HOUR FINGERPRINTING
#    Same human → same waking hours → similar activity windows.
#    Different from geolocation — this links wallets to each other
#    rather than to a geographic region.
# ─────────────────────────────────────────────────────────────

def compute_hourly_activity_vector(
    df: pd.DataFrame,
    address: str,
) -> np.ndarray:
    """
    Build a 24-element activity vector for an address.
    Each element = fraction of transactions in that UTC hour.
    Two addresses with similar vectors → same operator.
    """
    df2 = df.copy()
    df2["date"] = pd.to_datetime(df2["date"], errors="coerce")
    addr_txs = df2[
        (df2["from_address"].str.lower() == address.lower()) |
        (df2["to_address"].str.lower() == address.lower())
    ].dropna(subset=["date"])

    vec = np.zeros(24)
    if addr_txs.empty:
        return vec

    for hour in addr_txs["date"].dt.hour:
        vec[int(hour)] += 1

    total = vec.sum()
    if total > 0:
        vec = vec / total   # Normalize to probability distribution
    return vec


def compute_weekly_activity_vector(
    df: pd.DataFrame,
    address: str,
) -> np.ndarray:
    """Build a 7-element day-of-week activity vector."""
    df2 = df.copy()
    df2["date"] = pd.to_datetime(df2["date"], errors="coerce")
    addr_txs = df2[
        (df2["from_address"].str.lower() == address.lower()) |
        (df2["to_address"].str.lower() == address.lower())
    ].dropna(subset=["date"])

    vec = np.zeros(7)
    if addr_txs.empty:
        return vec
    for dow in addr_txs["date"].dt.dayofweek:
        vec[int(dow)] += 1
    total = vec.sum()
    if total > 0:
        vec = vec / total
    return vec


# ─────────────────────────────────────────────────────────────
# 2. GAS PRICE FINGERPRINTING
#    Different wallet software uses different default gas prices.
#    Addresses consistently using the same gas price ranges
#    are likely using the same wallet/tool/operator.
# ─────────────────────────────────────────────────────────────

def compute_gas_fingerprint(
    df: pd.DataFrame,
    address: str,
) -> np.ndarray:
    """
    Build a gas price pattern vector.
    Buckets: <20, 20-50, 50-100, 100-200, >200 Gwei.
    """
    vec = np.zeros(5)
    if "gas_price" not in df.columns:
        return vec

    addr_txs = df[df["from_address"].str.lower() == address.lower()]
    if addr_txs.empty:
        return vec

    gas = addr_txs["gas_price"].dropna()
    vec[0] = (gas < 20).sum()
    vec[1] = ((gas >= 20)  & (gas < 50)).sum()
    vec[2] = ((gas >= 50)  & (gas < 100)).sum()
    vec[3] = ((gas >= 100) & (gas < 200)).sum()
    vec[4] = (gas >= 200).sum()

    total = vec.sum()
    if total > 0:
        vec = vec / total
    return vec


# ─────────────────────────────────────────────────────────────
# 3. TRANSACTION INTERVAL TIMING
#    Bots send transactions at regular intervals.
#    Same interval pattern = same automation/bot.
# ─────────────────────────────────────────────────────────────

def compute_interval_fingerprint(
    df: pd.DataFrame,
    address: str,
) -> np.ndarray:
    """
    Build an inter-transaction interval distribution vector.
    Buckets: <1min, 1-5min, 5-30min, 30min-2h, 2-12h, 12h-24h, >24h.
    """
    vec = np.zeros(7)
    df2 = df.copy()
    df2["date"] = pd.to_datetime(df2["date"], errors="coerce")

    addr_txs = df2[df2["from_address"].str.lower() == address.lower()] \
               .dropna(subset=["date"]).sort_values("date")

    if len(addr_txs) < 2:
        return vec

    dates     = addr_txs["date"].tolist()
    intervals = [(dates[i+1] - dates[i]).total_seconds() / 60
                 for i in range(len(dates)-1)]

    for iv in intervals:
        if iv < 1:        vec[0] += 1
        elif iv < 5:      vec[1] += 1
        elif iv < 30:     vec[2] += 1
        elif iv < 120:    vec[3] += 1
        elif iv < 720:    vec[4] += 1
        elif iv < 1440:   vec[5] += 1
        else:             vec[6] += 1

    total = vec.sum()
    if total > 0:
        vec = vec / total
    return vec


# ─────────────────────────────────────────────────────────────
# 4. TOKEN SEQUENCE FINGERPRINTING
#    Same operator often uses the same tokens in the same order.
#    The "token vocabulary" of an address is a behavioral signature.
# ─────────────────────────────────────────────────────────────

COMMON_TOKENS = ["ETH","BTC","USDT","USDC","BNB","DAI","MATIC","TRX",
                 "LINK","UNI","AAVE","CRV","MKR","WETH","WBTC","SOL"]


def compute_token_fingerprint(
    df: pd.DataFrame,
    address: str,
) -> np.ndarray:
    """
    Build a token usage distribution vector.
    One element per common token.
    """
    addr_txs = df[
        (df["from_address"].str.lower() == address.lower()) |
        (df["to_address"].str.lower() == address.lower())
    ]
    vec = np.zeros(len(COMMON_TOKENS))
    if addr_txs.empty or "token" not in addr_txs.columns:
        return vec

    token_counts = addr_txs["token"].str.upper().value_counts()
    for i, tok in enumerate(COMMON_TOKENS):
        vec[i] = token_counts.get(tok, 0)

    total = vec.sum()
    if total > 0:
        vec = vec / total
    return vec


# ─────────────────────────────────────────────────────────────
# 5. AMOUNT ROUND-NUMBER PATTERN
#    Human operators tend to use round amounts.
#    Bots use precise amounts. Consistent rounding preference
#    is a behavioral signature.
# ─────────────────────────────────────────────────────────────

def compute_amount_fingerprint(
    df: pd.DataFrame,
    address: str,
) -> np.ndarray:
    """
    Build an amount pattern vector:
    [round_pct, decimal_pct, large_pct, small_pct, mean_log_amount]
    """
    vec = np.zeros(5)
    addr_txs = df[df["from_address"].str.lower() == address.lower()]
    if addr_txs.empty or "amount" not in addr_txs.columns:
        return vec

    amounts = addr_txs["amount"].dropna()
    if amounts.empty:
        return vec

    round_pct   = (amounts == amounts.round(0)).mean()
    decimal_pct = (amounts != amounts.round(2)).mean()
    large_pct   = (amounts > amounts.quantile(0.9)).mean()
    small_pct   = (amounts < amounts.quantile(0.1)).mean()
    mean_log    = np.log1p(amounts.mean()) / 10

    vec[:] = [round_pct, decimal_pct, large_pct, small_pct, mean_log]
    return vec


# ─────────────────────────────────────────────────────────────
# 6. MULTI-DIMENSIONAL INFRASTRUCTURE CLUSTERING
#    Combines all feature vectors and clusters addresses
#    by overall behavioral similarity.
# ─────────────────────────────────────────────────────────────

def build_feature_matrix(
    df: pd.DataFrame,
    addresses: List[str],
    min_txs: int = 3,
) -> Tuple[np.ndarray, List[str]]:
    """
    Build the full multi-dimensional feature matrix for clustering.
    Returns (feature_matrix, valid_addresses).
    """
    df2 = df.copy()
    df2["from_address"] = df2["from_address"].astype(str).str.lower()
    df2["to_address"]   = df2["to_address"].astype(str).str.lower()

    valid_addrs = []
    features    = []

    for addr in addresses:
        addr_lower = addr.lower()
        tx_count   = (
            (df2["from_address"] == addr_lower) |
            (df2["to_address"]   == addr_lower)
        ).sum()

        if tx_count < min_txs:
            continue

        # Build composite feature vector
        hour_vec     = compute_hourly_activity_vector(df, addr)        # 24 dims
        week_vec     = compute_weekly_activity_vector(df, addr)         # 7 dims
        gas_vec      = compute_gas_fingerprint(df, addr)                # 5 dims
        interval_vec = compute_interval_fingerprint(df, addr)           # 7 dims
        token_vec    = compute_token_fingerprint(df, addr)              # 16 dims
        amount_vec   = compute_amount_fingerprint(df, addr)             # 5 dims

        composite = np.concatenate([
            hour_vec * 2.0,      # Weight: operational hours most important
            week_vec * 1.5,      # Weight: weekly pattern
            gas_vec * 1.0,
            interval_vec * 1.5,  # Weight: timing intervals important
            token_vec * 1.0,
            amount_vec * 0.8,
        ])

        valid_addrs.append(addr)
        features.append(composite)

    if not features:
        return np.array([]), []

    return np.array(features), valid_addrs


@st.cache_data(show_spinner=False)
def cluster_by_infrastructure(
    df: pd.DataFrame,
    n_clusters: int = 6,
    min_txs: int = 3,
) -> pd.DataFrame:
    """
    Cluster addresses by shared operational infrastructure patterns.

    Uses K-Means on multi-dimensional behavioral features:
    - Operational hours (24-dim)
    - Day-of-week patterns (7-dim)
    - Gas price preferences (5-dim, if available)
    - Transaction timing intervals (7-dim)
    - Token usage patterns (16-dim)
    - Amount patterns (5-dim)

    Total: 64-dimensional behavioral fingerprint.
    """
    try:
        from sklearn.cluster import KMeans, DBSCAN
        from sklearn.preprocessing import StandardScaler
        from sklearn.decomposition import PCA
        from sklearn.metrics import silhouette_score
    except ImportError:
        return pd.DataFrame({"error": ["sklearn not installed"]})

    all_addrs = list(set(
        df["from_address"].str.lower().tolist() +
        df["to_address"].str.lower().tolist()
    ))

    X, valid_addrs = build_feature_matrix(df, all_addrs, min_txs)

    if len(valid_addrs) < 4:
        return pd.DataFrame()

    # Normalize
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(np.nan_to_num(X))

    # Determine optimal clusters (silhouette method, max n_clusters)
    actual_k = min(n_clusters, len(valid_addrs) - 1)

    # K-Means clustering
    km = KMeans(n_clusters=actual_k, random_state=42, n_init=10)
    labels = km.fit_predict(X_scaled)

    # Also try DBSCAN for outlier detection
    db = DBSCAN(eps=0.8, min_samples=2)
    db_labels = db.fit_predict(X_scaled)

    # PCA for visualization
    pca        = PCA(n_components=2, random_state=42)
    X_2d       = pca.fit_transform(X_scaled)

    # Extract feature summaries per address
    rows = []
    for i, addr in enumerate(valid_addrs):
        hour_vec  = compute_hourly_activity_vector(df, addr)
        peak_hour = int(np.argmax(hour_vec)) if hour_vec.sum() > 0 else -1
        week_vec  = compute_weekly_activity_vector(df, addr)
        is_weekday_dominant = week_vec[:5].sum() > week_vec[5:].sum()
        interval  = compute_interval_fingerprint(df, addr)
        is_bot    = interval[0] > 0.3  # >30% of txs <1 min apart = likely bot

        addr_txs  = df[df["from_address"].str.lower() == addr.lower()]
        vol_sent  = float(addr_txs["amount"].sum()) if not addr_txs.empty else 0

        risk_map  = {}
        if "risk_level" in df.columns:
            all_addr_txs = df[
                (df["from_address"].str.lower() == addr.lower()) |
                (df["to_address"].str.lower() == addr.lower())
            ]
            if not all_addr_txs.empty:
                risk_map = all_addr_txs["risk_level"].value_counts().to_dict()

        rows.append({
            "address":            addr,
            "infra_cluster":      int(labels[i]),
            "dbscan_cluster":     int(db_labels[i]),
            "is_outlier":         db_labels[i] == -1,
            "pca_x":              float(X_2d[i][0]),
            "pca_y":              float(X_2d[i][1]),
            "peak_hour_utc":      peak_hour,
            "is_weekday_operator":is_weekday_dominant,
            "is_bot_pattern":     is_bot,
            "volume_sent":        vol_sent,
            "risk_profile":       str(risk_map),
            "tx_count":           int((
                (df["from_address"].str.lower() == addr.lower()) |
                (df["to_address"].str.lower() == addr.lower())
            ).sum()),
        })

    result_df = pd.DataFrame(rows)

    # Add cluster summary info
    cluster_risk = {}
    if "risk_level" in df.columns:
        for cluster_id in result_df["infra_cluster"].unique():
            cluster_addrs = result_df[result_df["infra_cluster"] == cluster_id]["address"].tolist()
            cluster_txs   = df[
                df["from_address"].str.lower().isin(cluster_addrs) |
                df["to_address"].str.lower().isin(cluster_addrs)
            ]
            crit_count = int((cluster_txs.get("risk_level","") == "CRITICAL").sum())
            cluster_risk[cluster_id] = "CRITICAL" if crit_count > 0 else "LOW"
    result_df["cluster_risk"] = result_df["infra_cluster"].map(cluster_risk).fillna("LOW")

    logger.info(f"✅ Infrastructure clustering: {len(result_df)} addresses, {actual_k} clusters")
    return result_df.sort_values(["infra_cluster","volume_sent"], ascending=[True,False])


def plot_infrastructure_clusters(cluster_df: pd.DataFrame) -> go.Figure:
    """Visualize infrastructure clusters in 2D PCA space."""
    if cluster_df.empty or "pca_x" not in cluster_df.columns:
        return None

    RCOL = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"gold","LOW":"steelblue"}

    fig = go.Figure()
    for cluster_id in cluster_df["infra_cluster"].unique():
        mask    = cluster_df["infra_cluster"] == cluster_id
        subset  = cluster_df[mask]
        risk    = subset["cluster_risk"].mode().iloc[0] if len(subset) else "LOW"
        is_bot  = subset["is_bot_pattern"].mean() > 0.5

        fig.add_trace(go.Scatter(
            x=subset["pca_x"],
            y=subset["pca_y"],
            mode="markers+text",
            name=f"Cluster {cluster_id}" + (" 🤖" if is_bot else ""),
            text=[a[:10]+"…" for a in subset["address"]],
            textposition="top center",
            textfont=dict(size=7),
            marker=dict(
                size=[max(8, min(20, np.log1p(v)*2)) for v in subset["volume_sent"]],
                color=RCOL.get(risk,"steelblue"),
                symbol="x" if is_bot else "circle",
                line=dict(width=1, color="white"),
                opacity=0.8,
            ),
            customdata=list(zip(
                subset["address"],
                subset["peak_hour_utc"],
                subset["tx_count"],
                subset["is_bot_pattern"].map({True:"🤖 Bot",False:"👤 Human"}),
            )),
            hovertemplate=(
                "<b>%{customdata[0]}</b><br>"
                "Peak hour UTC: %{customdata[1]}:00<br>"
                "Transactions: %{customdata[2]}<br>"
                "Operator type: %{customdata[3]}<extra></extra>"
            ),
        ))

    # Outliers
    outliers = cluster_df[cluster_df["is_outlier"]]
    if not outliers.empty:
        fig.add_trace(go.Scatter(
            x=outliers["pca_x"], y=outliers["pca_y"],
            mode="markers", name="Outliers (unique behavior)",
            marker=dict(size=10, color="grey", symbol="diamond-open"),
        ))

    fig.update_layout(
        title="🏗️ Infrastructure Clusters (PCA) — size=volume, x=bot pattern",
        height=520,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(15,23,42,0.5)",
        xaxis=dict(showticklabels=False, gridcolor="rgba(255,255,255,0.1)"),
        yaxis=dict(showticklabels=False, gridcolor="rgba(255,255,255,0.1)"),
    )
    return fig


def identify_shared_operators(cluster_df: pd.DataFrame) -> List[Dict]:
    """
    Identify clusters that likely share the same operator.
    Returns a prioritized list of multi-wallet operator groups.
    """
    if cluster_df.empty:
        return []

    operators = []
    for cluster_id in cluster_df["infra_cluster"].unique():
        subset = cluster_df[cluster_df["infra_cluster"] == cluster_id]
        if len(subset) < 2:
            continue

        # Confidence score: how tightly clustered?
        pca_spread = subset[["pca_x","pca_y"]].std().mean()
        confidence = max(0, min(100, int(100 - pca_spread * 20)))

        bot_ratio    = subset["is_bot_pattern"].mean()
        weekday_ratio = subset["is_weekday_operator"].mean()
        peak_hours   = subset["peak_hour_utc"].value_counts().head(3).index.tolist()
        total_volume = float(subset["volume_sent"].sum())

        operators.append({
            "cluster_id":        int(cluster_id),
            "wallet_count":      len(subset),
            "confidence":        confidence,
            "likely_operator":   "🤖 Automated/Bot" if bot_ratio > 0.5 else "👤 Human",
            "work_pattern":      "Weekday" if weekday_ratio > 0.65 else
                                 "Weekend" if weekday_ratio < 0.35 else "Mixed",
            "peak_hours_utc":    [f"{h:02d}:00" for h in peak_hours],
            "total_volume":      total_volume,
            "cluster_risk":      subset["cluster_risk"].mode().iloc[0] if len(subset) else "LOW",
            "addresses":         subset["address"].tolist(),
        })

    operators.sort(key=lambda x: (
        ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["cluster_risk"]),
        -x["wallet_count"]
    ))
    return operators


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_netinfra_ui(df: pd.DataFrame):
    """Network infrastructure clustering UI."""
    st.markdown("### 🏗️ Network Infrastructure Clustering")
    st.caption(
        "Groups wallets by OPERATIONAL behavior rather than just transaction links. "
        "Identifies the same human operator or bot controlling multiple wallets "
        "by fingerprinting: activity hours, transaction timing, gas prices, token preferences, "
        "and amount patterns. A cluster of addresses with identical patterns = same infrastructure."
    )

    ni1, ni2, ni3 = st.columns(3)
    n_clusters = ni1.slider("Infrastructure clusters", 2, 15, 6, key="ni_k")
    min_txs    = ni2.number_input("Min transactions per address", 2, 20, 3, key="ni_min")
    show_bots  = ni3.checkbox("Highlight bot patterns", value=True, key="ni_bots")

    if st.button("🏗️ Cluster Infrastructure", type="primary", key="run_netinfra"):
        with st.spinner("Building behavioral fingerprints and clustering…"):
            ni_df = cluster_by_infrastructure(df, int(n_clusters), int(min_txs))
            if isinstance(ni_df, pd.DataFrame) and "error" in ni_df.columns:
                st.error(ni_df.iloc[0]["error"])
            elif ni_df.empty:
                st.warning("Not enough addresses with sufficient transactions for clustering.")
            else:
                st.session_state.ni_df = ni_df

    if "ni_df" not in st.session_state:
        return

    ni_df = st.session_state.ni_df
    if ni_df.empty:
        return

    n_clust   = ni_df["infra_cluster"].nunique()
    n_addrs   = len(ni_df)
    n_bots    = ni_df["is_bot_pattern"].sum()
    n_outlier = ni_df["is_outlier"].sum()

    m1,m2,m3,m4 = st.columns(4)
    m1.metric("Addresses Clustered", n_addrs)
    m2.metric("Infrastructure Groups", n_clust)
    m3.metric("Bot Pattern Detected", f"{n_bots} addresses")
    m4.metric("Unique Behavior (Outliers)", n_outlier)

    # Visualization
    fig = plot_infrastructure_clusters(ni_df)
    if fig:
        st.plotly_chart(fig, use_container_width=True)

    # Operator groups
    st.markdown("---")
    operators = identify_shared_operators(ni_df)

    if operators:
        st.markdown(f"### 👥 Identified Infrastructure Groups ({len(operators)})")
        st.caption(
            "Groups of wallets with near-identical operational patterns. "
            "Each group likely represents one operator, one bot, or one criminal enterprise."
        )

        for op in operators:
            risk_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(
                op["cluster_risk"],"⚪")
            with st.expander(
                f"{risk_icon} Group {op['cluster_id']}: {op['wallet_count']} wallets — "
                f"{op['likely_operator']} | {op['work_pattern']} | "
                f"{fmt_crypto(op['total_volume'])} volume | Confidence: {op['confidence']}%",
                expanded=op["cluster_risk"] in ("CRITICAL","HIGH")
            ):
                g1,g2,g3,g4 = st.columns(4)
                g1.metric("Wallets",    op["wallet_count"])
                g2.metric("Pattern",    op["likely_operator"])
                g3.metric("Schedule",   op["work_pattern"])
                g4.metric("Peak Hours", ", ".join(op["peak_hours_utc"][:2]))

                st.markdown("**Addresses in this group** (likely same operator):")
                for addr in op["addresses"][:10]:
                    st.code(addr)
                if len(op["addresses"]) > 10:
                    st.caption(f"…and {len(op['addresses'])-10} more")

                # Actionable intelligence
                if op["likely_operator"] == "🤖 Automated/Bot":
                    st.info(
                        "💡 **Bot/Automation detected:** All wallets in this group use "
                        "identical transaction timing. Likely same script/software. "
                        "Check for shared infrastructure: same IP, same VPN, same relay node."
                    )
                elif op["confidence"] > 70:
                    st.info(
                        f"💡 **High-confidence operator cluster:** {op['wallet_count']} wallets "
                        f"behave identically. Submit all addresses in a single subpoena — "
                        f"they likely belong to the same account holder."
                    )

    # Activity heatmap comparison
    st.markdown("---")
    st.markdown("**Compare Operational Hours Between Clusters**")
    selected_cluster = st.selectbox(
        "Select cluster to view hourly pattern",
        options=sorted(ni_df["infra_cluster"].unique()),
        format_func=lambda x: f"Cluster {x} ({len(ni_df[ni_df['infra_cluster']==x])} wallets)",
        key="ni_cluster_sel",
    )

    if selected_cluster is not None:
        cluster_addrs = ni_df[ni_df["infra_cluster"] == selected_cluster]["address"].tolist()

        # Aggregate hourly pattern for the cluster
        agg_vec = np.zeros(24)
        for addr in cluster_addrs[:20]:
            agg_vec += compute_hourly_activity_vector(df, addr)

        if agg_vec.sum() > 0:
            agg_vec = agg_vec / agg_vec.sum()
            hours   = [f"{h:02d}:00" for h in range(24)]
            fig_hr  = go.Figure(data=[go.Bar(
                x=hours, y=agg_vec,
                marker_color=[
                    "#ff4444" if v == agg_vec.max() else "#4a9eff"
                    for v in agg_vec
                ],
            )])
            fig_hr.update_layout(
                title=f"Hourly Activity Pattern — Cluster {selected_cluster}",
                height=280,
                paper_bgcolor="rgba(0,0,0,0)",
                xaxis_title="UTC Hour",
                yaxis_title="Activity Fraction",
            )
            st.plotly_chart(fig_hr, use_container_width=True)
            peak = agg_vec.argmax()
            st.caption(
                f"Peak activity: **{peak:02d}:00 UTC** — "
                f"Estimated local time: see Geolocation module for jurisdiction mapping"
            )

    # Full table
    with st.expander("📋 Full Cluster Assignment Table"):
        show_cols = [c for c in ["address","infra_cluster","cluster_risk","is_bot_pattern",
                                  "peak_hour_utc","is_weekday_operator","volume_sent","tx_count"]
                     if c in ni_df.columns]
        st.dataframe(ni_df[show_cols], width='stretch', hide_index=True)
        st.download_button("⬇️ Export Infrastructure Clusters",
            ni_df.to_csv(index=False).encode(),
            "infrastructure_clusters.csv", "text/csv")
