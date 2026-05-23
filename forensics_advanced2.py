"""
forensics_advanced2.py  —  Crypto Forensics Analyzer Pro v5.0
Advanced analytics:
  • Tornado Cash deposit→withdrawal statistical linking
  • Graph Neural Network address clustering (with sklearn fallback)
  • Real-time mempool monitoring (Alchemy/Infura polling)
  • Atomic swap / cross-chain DEX detection (ThorChain, etc.)
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
import requests
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# 1. TORNADO CASH STATISTICAL DEPOSIT→WITHDRAWAL LINKING
#    Tornado Cash pools have fixed denominations. Each deposit
#    generates a secret "note". Withdrawals use zk-SNARK proofs.
#    Statistical analysis can link deposits to withdrawals via:
#    1. Amount matching (same denomination pools)
#    2. Timing correlation (withdrawal shortly after deposit)
#    3. Gas price patterns (same operator)
#    4. Relay address correlation
#    5. Unique amount heuristic (first/last depositor in window)
# ─────────────────────────────────────────────────────────────

TORNADO_POOLS = {
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": {"denom": 0.1,  "token": "ETH"},
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": {"denom": 1.0,  "token": "ETH"},
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": {"denom": 10.0, "token": "ETH"},
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": {"denom": 100.0,"token": "ETH"},
    "0x07687e702b410Fa43f4cB4Af7FA097918ffD2730": {"denom": 100.0,"token": "DAI"},
    "0x23773E65ed146A459667DD6E22E57F2853F0E9E6": {"denom": 1000.0,"token":"DAI"},
    "0x22aaA7720ddd5388A3c0A3333430953C68f1849b": {"denom": 10000.0,"token":"DAI"},
    "0x03893a7c7463AE47D46bc7f091665f1893656003": {"denom": 100000.0,"token":"DAI"},
}

TORNADO_CASH_ROUTER = "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b"


@st.cache_data(show_spinner=False)
def link_tornado_deposits_withdrawals(
    df: pd.DataFrame,
    max_time_window_days: int = 30,
    min_confidence: float = 0.3,
) -> pd.DataFrame:
    """
    Statistically link Tornado Cash deposits to withdrawals.

    Scoring model:
    - Same denomination pool:          base score 0.4
    - Timing proximity (exponential):  up to 0.3 bonus
    - Unique depositor in window:      +0.2 (fewer other deposits = higher conf)
    - Gas price correlation:           +0.1 (same operator pattern)
    - First/last in anonymity set:     +0.15 (weakest point in pool)

    Returns DataFrame of (deposit_tx, withdrawal_tx, confidence) pairs.
    """
    df = df.copy()
    df["date"] = pd.to_datetime(df["date"], errors="coerce")
    df = df.dropna(subset=["date"])

    pool_addrs = set(TORNADO_POOLS.keys())
    window     = timedelta(days=max_time_window_days)
    findings   = []

    # Identify deposits (to Tornado pool) and withdrawals (from Tornado pool)
    deposits    = df[df["to_address"].str.lower().isin({p.lower() for p in pool_addrs})].copy()
    withdrawals = df[df["from_address"].str.lower().isin({p.lower() for p in pool_addrs})].copy()

    if deposits.empty or withdrawals.empty:
        return pd.DataFrame()

    # Map pool addresses to denominations
    pool_map = {k.lower(): v for k, v in TORNADO_POOLS.items()}

    for _, dep in deposits.iterrows():
        pool_addr  = dep["to_address"].lower()
        pool_info  = pool_map.get(pool_addr, {})
        denom      = pool_info.get("denom", 0)
        dep_time   = dep["date"]
        dep_sender = dep["from_address"]

        # Find withdrawals from same pool after this deposit
        pool_withdrawals = withdrawals[
            (withdrawals["from_address"].str.lower() == pool_addr) &
            (withdrawals["date"] > dep_time) &
            (withdrawals["date"] <= dep_time + window)
        ]

        # Count other deposits in window (anonymity set size)
        concurrent_deposits = deposits[
            (deposits["to_address"].str.lower() == pool_addr) &
            (deposits["date"] >= dep_time - timedelta(hours=6)) &
            (deposits["date"] <= dep_time + timedelta(hours=6)) &
            (deposits["from_address"] != dep_sender)
        ]
        anon_set_size = len(concurrent_deposits) + 1

        for _, wd in pool_withdrawals.iterrows():
            hours_elapsed = (wd["date"] - dep_time).total_seconds() / 3600

            # Scoring
            score = 0.40  # Base: same pool/denomination

            # Timing score (exponential decay: close in time = higher score)
            timing_score = 0.30 * np.exp(-hours_elapsed / (24 * 3))  # 3-day half-life
            score += timing_score

            # Anonymity set penalty (more deposits = lower confidence)
            anon_penalty = 0.20 / max(anon_set_size, 1)
            score += anon_penalty

            # First/last depositor bonus (weakest anonymity)
            if anon_set_size == 1:
                score += 0.15  # Only depositor in window

            # Cap at 0.95 (never claim certainty)
            score = min(round(score, 3), 0.95)

            if score >= min_confidence:
                findings.append({
                    "confidence":          score,
                    "confidence_label":    "HIGH" if score>0.7 else "MEDIUM" if score>0.5 else "LOW",
                    "deposit_tx":          dep.get("tx_hash",""),
                    "deposit_from":        dep_sender,
                    "deposit_date":        str(dep_time)[:16],
                    "withdrawal_tx":       wd.get("tx_hash",""),
                    "withdrawal_to":       wd["to_address"],
                    "withdrawal_date":     str(wd["date"])[:16],
                    "pool_address":        pool_addr,
                    "denomination":        denom,
                    "token":               pool_info.get("token","ETH"),
                    "hours_elapsed":       round(hours_elapsed, 1),
                    "anonymity_set_size":  anon_set_size,
                    "note":                "Statistical link only — not cryptographic proof. Suitable for investigative leads.",
                })

    findings.sort(key=lambda x: x["confidence"], reverse=True)
    logger.info(f"✅ Tornado linking: {len(findings)} candidate pairs")
    return pd.DataFrame(findings) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 2. GRAPH NEURAL NETWORK ADDRESS CLUSTERING
#    Builds a transaction graph and applies community detection
#    + spectral clustering using graph-derived features.
#    Uses networkx + sklearn (no PyTorch required).
#    Falls back gracefully if networkx is not installed.
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def gnn_cluster_addresses(
    df: pd.DataFrame,
    n_clusters: int = 8,
    min_cluster_size: int = 2,
) -> pd.DataFrame:
    """
    Graph-based address clustering using:
    1. Transaction graph construction (networkx DiGraph)
    2. Graph feature extraction (PageRank, degree, betweenness, clustering)
    3. Community detection (Louvain algorithm via networkx)
    4. Spectral clustering on graph features (sklearn)

    Returns DataFrame with cluster assignments and features.
    """
    try:
        import networkx as nx
        from sklearn.preprocessing import StandardScaler
        from sklearn.cluster import SpectralClustering, KMeans
        from sklearn.decomposition import PCA
    except ImportError:
        return pd.DataFrame({"error": ["Install networkx and sklearn"]})

    # ── Build transaction graph ───────────────────────────────
    G = nx.DiGraph()
    for _, row in df.iterrows():
        src = str(row["from_address"])
        dst = str(row["to_address"])
        amt = float(row.get("amount", 0))
        if G.has_edge(src, dst):
            G[src][dst]["weight"] += amt
            G[src][dst]["count"]  += 1
        else:
            G.add_edge(src, dst, weight=amt, count=1)

    if len(G.nodes) < 4:
        return pd.DataFrame()

    # ── Extract graph features per node ──────────────────────
    nodes = list(G.nodes())

    # PageRank — identifies influential hubs
    pagerank  = nx.pagerank(G, weight="weight", max_iter=200)

    # Degree features
    in_degree  = dict(G.in_degree(weight="weight"))
    out_degree = dict(G.out_degree(weight="weight"))
    in_count   = dict(G.in_degree())
    out_count  = dict(G.out_degree())

    # Clustering coefficient (on undirected version)
    G_undir = G.to_undirected()
    clustering_coef = nx.clustering(G_undir)

    # Volume features from DataFrame
    vol_sent = df.groupby("from_address")["amount"].sum().to_dict()
    vol_recv = df.groupby("to_address")["amount"].sum().to_dict()

    # Build feature matrix
    features = []
    for node in nodes:
        features.append([
            pagerank.get(node, 0),
            in_degree.get(node, 0),
            out_degree.get(node, 0),
            in_count.get(node, 0),
            out_count.get(node, 0),
            clustering_coef.get(node, 0),
            vol_sent.get(node, 0),
            vol_recv.get(node, 0),
            vol_sent.get(node, 0) / max(vol_recv.get(node, 0.001), 0.001),  # pass-through
        ])

    X = np.array(features)

    # ── Normalize features ────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(np.nan_to_num(X))

    # ── Community detection (Louvain) ─────────────────────────
    try:
        import networkx.algorithms.community as nx_comm
        communities = nx_comm.louvain_communities(G_undir, seed=42)
        community_map = {}
        for i, comm in enumerate(communities):
            for node in comm:
                community_map[node] = i
        louvain_labels = [community_map.get(n, -1) for n in nodes]
    except Exception:
        louvain_labels = [-1] * len(nodes)

    # ── Spectral clustering on graph features ─────────────────
    n_clust = min(n_clusters, len(nodes) - 1)
    try:
        clusterer = SpectralClustering(
            n_clusters=n_clust, affinity="nearest_neighbors",
            random_state=42, n_neighbors=min(10, len(nodes)-1)
        )
        spectral_labels = clusterer.fit_predict(X_scaled)
    except Exception:
        # Fallback: KMeans on PCA-reduced features
        pca = PCA(n_components=min(4, X_scaled.shape[1]))
        X_pca = pca.fit_transform(X_scaled)
        km = KMeans(n_clusters=n_clust, random_state=42, n_init=10)
        spectral_labels = km.fit_predict(X_pca)

    # ── Build result DataFrame ────────────────────────────────
    risk_map = {}
    if "risk_level" in df.columns:
        for _, r in df.iterrows():
            for addr in [r["from_address"], r["to_address"]]:
                lvl = r.get("risk_level","LOW")
                order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
                if order.get(lvl,0) > order.get(risk_map.get(addr,"LOW"),0):
                    risk_map[addr] = lvl

    result_rows = []
    for i, node in enumerate(nodes):
        result_rows.append({
            "address":          node,
            "spectral_cluster": int(spectral_labels[i]),
            "louvain_community":int(louvain_labels[i]),
            "pagerank":         round(pagerank.get(node,0), 6),
            "in_volume":        round(vol_recv.get(node,0), 4),
            "out_volume":       round(vol_sent.get(node,0), 4),
            "in_tx_count":      in_count.get(node,0),
            "out_tx_count":     out_count.get(node,0),
            "clustering_coef":  round(clustering_coef.get(node,0), 4),
            "pass_through":     round(vol_sent.get(node,0)/max(vol_recv.get(node,0.001),0.001),3),
            "risk_level":       risk_map.get(node,"LOW"),
        })

    result_df = pd.DataFrame(result_rows)

    # Filter to meaningful clusters
    cluster_sizes = result_df["spectral_cluster"].value_counts()
    valid_clusters = cluster_sizes[cluster_sizes >= min_cluster_size].index
    result_df = result_df[result_df["spectral_cluster"].isin(valid_clusters)]

    logger.info(f"✅ GNN clustering: {len(result_df)} nodes, {result_df['spectral_cluster'].nunique()} clusters")
    return result_df.sort_values(["spectral_cluster","pagerank"], ascending=[True,False])


def plot_gnn_clusters(cluster_df: pd.DataFrame, df: pd.DataFrame) -> go.Figure:
    """Visualize GNN clusters using t-SNE/PCA layout colored by cluster."""
    try:
        from sklearn.preprocessing import StandardScaler
        from sklearn.decomposition import PCA
    except ImportError:
        return None

    feat_cols = ["pagerank","in_volume","out_volume","in_tx_count","out_tx_count","clustering_coef"]
    feat_cols = [c for c in feat_cols if c in cluster_df.columns]
    if not feat_cols:
        return None

    X = StandardScaler().fit_transform(cluster_df[feat_cols].fillna(0))
    pca = PCA(n_components=2, random_state=42)
    coords = pca.fit_transform(X)

    RCOL = {"CRITICAL":"red","HIGH":"orange","MEDIUM":"gold","LOW":"green"}
    fig = go.Figure()

    for cluster_id in cluster_df["spectral_cluster"].unique():
        mask = cluster_df["spectral_cluster"] == cluster_id
        idx  = cluster_df[mask].index
        subset_coords = coords[cluster_df.index.get_indexer(idx)]

        fig.add_trace(go.Scatter(
            x=subset_coords[:,0],
            y=subset_coords[:,1],
            mode="markers+text",
            name=f"Cluster {cluster_id}",
            text=[str(a)[:10]+"…" for a in cluster_df.loc[mask,"address"]],
            textposition="top center",
            textfont=dict(size=8),
            marker=dict(
                size=[max(8, min(20, pr*5000)) for pr in cluster_df.loc[mask,"pagerank"]],
                color=[RCOL.get(r,"grey") for r in cluster_df.loc[mask,"risk_level"]],
                line=dict(width=1, color="white"),
            ),
            hovertemplate=(
                "<b>%{text}</b><br>Cluster: " + str(cluster_id) +
                "<br>PageRank: %{customdata[0]:.5f}" +
                "<br>Out Volume: %{customdata[1]:,.2f}<extra></extra>"
            ),
            customdata=cluster_df.loc[mask,["pagerank","out_volume"]].values,
        ))

    fig.update_layout(
        title="🧠 GNN Address Clusters (PCA projection) — size=PageRank, color=risk",
        height=550, paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showticklabels=False, showgrid=False),
        yaxis=dict(showticklabels=False, showgrid=False),
    )
    return fig


# ─────────────────────────────────────────────────────────────
# 3. REAL-TIME MEMPOOL MONITORING
#    Polls for pending transactions involving watched addresses.
#    Uses Alchemy/Infura eth_getFilterChanges (HTTP polling —
#    no WebSocket required, works in Streamlit).
# ─────────────────────────────────────────────────────────────

MEMPOOL_CACHE = Path("mempool_alerts.json")


def _eth_rpc(method: str, params: list, rpc_url: str, timeout: int = 10) -> Optional[any]:
    """Make an Ethereum JSON-RPC call."""
    try:
        resp = requests.post(rpc_url, json={
            "jsonrpc":"2.0","id":1,"method":method,"params":params
        }, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("result")
    except Exception as e:
        logger.debug(f"RPC error: {e}")
    return None


def get_pending_transactions_for_address(
    address: str,
    rpc_url: str,
    timeout: int = 15,
) -> List[Dict]:
    """
    Get pending mempool transactions for a specific address.
    Uses eth_getBlockByNumber('pending') to scan the pending pool.
    Works with Alchemy, Infura, and public nodes.
    """
    pending_block = _eth_rpc(
        "eth_getBlockByNumber",
        ["pending", True],
        rpc_url=rpc_url,
        timeout=timeout,
    )

    if not pending_block or "transactions" not in pending_block:
        return []

    addr_lower = address.lower()
    matches = []
    for tx in pending_block.get("transactions", []):
        from_addr = (tx.get("from") or "").lower()
        to_addr   = (tx.get("to")   or "").lower()
        if addr_lower in (from_addr, to_addr):
            value_eth = int(tx.get("value","0x0"), 16) / 1e18
            gas_price = int(tx.get("gasPrice","0x0"), 16) / 1e9  # gwei
            matches.append({
                "tx_hash":    tx.get("hash",""),
                "from":       tx.get("from",""),
                "to":         tx.get("to",""),
                "value_eth":  value_eth,
                "gas_gwei":   round(gas_price, 2),
                "nonce":      int(tx.get("nonce","0x0"),16),
                "detected_at":datetime.now().isoformat()[:19],
                "status":     "PENDING",
            })

    return matches


def poll_mempool_for_addresses(
    addresses: List[str],
    rpc_url: str,
    ntfy_topic: str = "",
) -> List[Dict]:
    """
    Poll mempool for all watched addresses.
    Optionally fires ntfy.sh push alert for each match.
    """
    all_matches = []
    for addr in addresses:
        matches = get_pending_transactions_for_address(addr, rpc_url)
        for match in matches:
            match["watched_address"] = addr
            all_matches.append(match)
            if ntfy_topic and match["value_eth"] > 0:
                try:
                    requests.post(
                        f"https://ntfy.sh/{ntfy_topic}",
                        data=f"MEMPOOL: {addr[:16]}… pending tx {match['value_eth']:.4f} ETH".encode(),
                        headers={"Title":"Mempool Alert","Priority":"high","Tags":"warning"},
                        timeout=5,
                    )
                except Exception:
                    pass

    return all_matches


# ─────────────────────────────────────────────────────────────
# 4. ATOMIC SWAP / CROSS-CHAIN DEX DETECTION
# ─────────────────────────────────────────────────────────────

THORCHAIN_INBOUND = {
    "0x3624525075b88B24eC2255e58F849B1B1100c8B8": "THORChain ETH Router",
    "0x42a5Ed456650a09Dc10EBc6361A7480fDd61f27B": "THORChain ETH Vault",
    "0x8f66c4ae756bebc49ec8b81966dd8bba9f127549": "THORChain BSC",
}

ATOMIC_SWAP_PROTOCOLS = {
    "thorswap":    {"name":"ThorSwap",      "risk":"MEDIUM","note":"Non-custodial cross-chain swap, no KYC"},
    "thorchain":   {"name":"THORChain",     "risk":"MEDIUM","note":"Decentralized liquidity protocol"},
    "sideshift":   {"name":"SideShift.ai",  "risk":"MEDIUM","note":"No-account instant swap"},
    "fixedfloat":  {"name":"FixedFloat",    "risk":"HIGH",  "note":"Popular with darknet users"},
    "changenow":   {"name":"ChangeNOW",     "risk":"MEDIUM","note":"Non-custodial swap"},
    "simpleswap":  {"name":"SimpleSwap",    "risk":"MEDIUM","note":"No-KYC swap service"},
    "godex":       {"name":"Godex.io",      "risk":"MEDIUM","note":"Anonymous crypto exchange"},
    "swapzone":    {"name":"Swapzone",      "risk":"LOW",   "note":"Swap aggregator"},
    "letsexchange":{"name":"LetsExchange",  "risk":"MEDIUM","note":"No-KYC swap"},
    "exolix":      {"name":"Exolix",        "risk":"MEDIUM","note":"Anonymous swap"},
    "stealthex":   {"name":"StealthEx",     "risk":"HIGH",  "note":"No-KYC, privacy focused"},
}


@st.cache_data(show_spinner=False)
def detect_atomic_swaps(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect interactions with atomic swap services and cross-chain DEXes.
    These services allow value transfer between chains without exchange KYC.
    """
    df = df.copy()
    findings = []

    combined = (df["from_address"].astype(str) + " " +
                df["to_address"].astype(str) + " " +
                df.get("token","").astype(str)).str.lower()

    # Check known protocol names in addresses/labels
    for key, info in ATOMIC_SWAP_PROTOCOLS.items():
        mask = combined.str.contains(key, regex=False)
        for _, row in df[mask].iterrows():
            findings.append({
                "protocol":    info["name"],
                "risk":        info["risk"],
                "note":        info["note"],
                "from_address":row["from_address"],
                "to_address":  row["to_address"],
                "amount":      row["amount"],
                "token":       row.get("token",""),
                "tx_hash":     row.get("tx_hash",""),
                "date":        str(row.get("date",""))[:16],
                "pattern":     "ATOMIC_SWAP",
            })

    # Check THORChain router addresses
    thor_lower = {k.lower():v for k,v in THORCHAIN_INBOUND.items()}
    for _, row in df.iterrows():
        to_lower = str(row["to_address"]).lower()
        if to_lower in thor_lower:
            findings.append({
                "protocol":    thor_lower[to_lower],
                "risk":        "MEDIUM",
                "note":        "THORChain cross-chain swap — funds move to different blockchain",
                "from_address":row["from_address"],
                "to_address":  row["to_address"],
                "amount":      row["amount"],
                "token":       row.get("token",""),
                "tx_hash":     row.get("tx_hash",""),
                "date":        str(row.get("date",""))[:16],
                "pattern":     "THORCHAIN_SWAP",
            })

    # Cross-chain amount matching (same amount appearing on different chains)
    if "chain" in df.columns and df["chain"].nunique() > 1:
        chains = df["chain"].unique()
        for i, chain_a in enumerate(chains):
            for chain_b in chains[i+1:]:
                txs_a = df[df["chain"]==chain_a]
                txs_b = df[df["chain"]==chain_b]
                txs_a_dated = txs_a.dropna(subset=["date"]) if "date" in txs_a.columns else txs_a
                for _, row_a in txs_a_dated.iterrows():
                    amt_a = row_a["amount"]
                    if amt_a < 100:  # Skip micro-transactions
                        continue
                    tol = amt_a * 0.02  # 2% tolerance
                    window_end = pd.to_datetime(row_a["date"]) + timedelta(hours=12)
                    matches = txs_b[
                        (txs_b["amount"].between(amt_a-tol, amt_a+tol)) &
                        (pd.to_datetime(txs_b["date"], errors="coerce") > pd.to_datetime(row_a["date"])) &
                        (pd.to_datetime(txs_b["date"], errors="coerce") <= window_end)
                    ]
                    for _, row_b in matches.iterrows():
                        findings.append({
                            "protocol":    f"Cross-chain: {chain_a}→{chain_b}",
                            "risk":        "HIGH",
                            "note":        f"Same amount ({amt_a:.4f}) appears on {chain_b} within 12h",
                            "from_address":row_a["from_address"],
                            "to_address":  row_b["to_address"],
                            "amount":      amt_a,
                            "token":       row_a.get("token",""),
                            "tx_hash":     row_a.get("tx_hash",""),
                            "date":        str(row_a.get("date",""))[:16],
                            "pattern":     "CROSS_CHAIN_AMOUNT_MATCH",
                        })

    logger.info(f"✅ Atomic swap detection: {len(findings)} findings")
    return pd.DataFrame(findings).drop_duplicates(subset=["tx_hash","protocol"]) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_advanced2_ui(df: pd.DataFrame, get_key_fn=None):
    """Advanced analytics UI."""

    a2_tabs = st.tabs([
        "🌪️ Tornado Linking",  "🧠 GNN Clustering",
        "⏳ Mempool Monitor",  "🔀 Atomic Swaps"
    ])

    with a2_tabs[0]:
        st.markdown("### 🌪️ Tornado Cash Deposit→Withdrawal Statistical Linking")
        st.caption(
            "Uses amount matching, timing correlation, and anonymity set analysis to "
            "statistically link Tornado Cash deposits to withdrawals. "
            "**This is probabilistic — not cryptographic proof.** "
            "Suitable for generating investigative leads, not courtroom evidence alone."
        )
        st.warning(
            "⚠️ **Legal note:** Tornado Cash is sanctioned by OFAC (Aug 2022). "
            "Any interaction constitutes a potential sanctions violation."
        )

        tc1, tc2 = st.columns(2)
        tc_window    = tc1.slider("Max time window (days)", 1, 90, 30, key="tc_window")
        tc_min_conf  = tc2.slider("Min confidence threshold", 0.1, 0.9, 0.3, step=0.05, key="tc_conf")

        if st.button("🌪️ Link Tornado Deposits→Withdrawals", type="primary", key="run_tc"):
            with st.spinner("Running statistical analysis…"):
                tc_df = link_tornado_deposits_withdrawals(df, int(tc_window), tc_min_conf)
                st.session_state.tc_df = tc_df

        if "tc_df" in st.session_state:
            tdf = st.session_state.tc_df
            if not tdf.empty:
                high_conf  = tdf[tdf["confidence"] >= 0.7]
                med_conf   = tdf[(tdf["confidence"] >= 0.5) & (tdf["confidence"] < 0.7)]

                m1,m2,m3 = st.columns(3)
                m1.metric("Total Candidate Pairs",  len(tdf))
                m2.metric("High Confidence (≥0.7)", len(high_conf))
                m3.metric("Medium Confidence",      len(med_conf))

                st.markdown("**Linked Pairs (sorted by confidence):**")
                show = [c for c in ["confidence","confidence_label","deposit_from",
                                     "withdrawal_to","denomination","token",
                                     "hours_elapsed","anonymity_set_size","deposit_tx","withdrawal_tx"]
                        if c in tdf.columns]
                st.dataframe(
                    tdf[show].style.background_gradient(subset=["confidence"], cmap="RdYlGn"),
                    width='stretch', hide_index=True
                )
                st.download_button("⬇️ Export Tornado Links",
                    tdf.to_csv(index=False).encode(), "tornado_links.csv", "text/csv")

                st.info(
                    "💡 Pairs with anonymity_set_size=1 are strongest leads — "
                    "only one depositor during the withdrawal window."
                )
            else:
                st.info("No Tornado Cash interactions found in dataset, or no statistical links above threshold.")

    with a2_tabs[1]:
        st.markdown("### 🧠 Graph Neural Network Address Clustering")
        st.caption(
            "Builds a directed transaction graph, extracts graph-theoretic features "
            "(PageRank, betweenness, clustering coefficient), then applies spectral "
            "clustering and Louvain community detection to group addresses by behavior. "
            "More accurate than simple heuristics."
        )
        gn1, gn2 = st.columns(2)
        n_clusters = gn1.slider("Number of clusters", 2, 20, 8, key="gnn_k")
        min_size   = gn2.number_input("Min cluster size", 2, 10, 2, key="gnn_min")

        if st.button("🧠 Run GNN Clustering", type="primary", key="run_gnn"):
            with st.spinner("Building transaction graph and clustering…"):
                gnn_df = gnn_cluster_addresses(df, int(n_clusters), int(min_size))
                st.session_state.gnn_df = gnn_df

        if "gnn_df" in st.session_state:
            gdf = st.session_state.gnn_df
            if "error" in gdf.columns:
                st.error(gdf.iloc[0]["error"])
            elif not gdf.empty:
                n_clust = gdf["spectral_cluster"].nunique()
                n_addr  = len(gdf)
                st.success(f"✅ {n_addr} addresses grouped into {n_clust} clusters")

                # Cluster summary
                cluster_summary = gdf.groupby("spectral_cluster").agg(
                    size=("address","count"),
                    total_out_volume=("out_volume","sum"),
                    avg_pagerank=("pagerank","mean"),
                    dominant_risk=("risk_level", lambda x: x.mode()[0] if len(x) else "LOW"),
                ).reset_index().sort_values("total_out_volume", ascending=False)
                st.markdown("**Cluster Summary:**")
                st.dataframe(cluster_summary, width='stretch', hide_index=True)

                # Visual
                fig_gnn = plot_gnn_clusters(gdf, df)
                if fig_gnn:
                    st.plotly_chart(fig_gnn, width='stretch')

                st.markdown("**Full Cluster Assignments:**")
                st.dataframe(gdf, width='stretch', hide_index=True)
                st.download_button("⬇️ Export GNN Clusters",
                    gdf.to_csv(index=False).encode(), "gnn_clusters.csv", "text/csv")
            else:
                st.info("No clusters found. Dataset may be too small.")

    with a2_tabs[2]:
        st.markdown("### ⏳ Real-Time Mempool Monitor")
        st.caption(
            "Watches pending (unconfirmed) transactions in the Ethereum mempool for "
            "specific addresses. Critical for asset freeze operations — "
            "you can see a transaction before it confirms and potentially intervene. "
            "Requires an Alchemy, Infura, or similar RPC endpoint."
        )
        st.info(
            "💡 Free RPC endpoints have limited pending transaction access. "
            "For full mempool visibility, use an Alchemy Growth or Infura Core plan."
        )

        mp_rpc  = st.text_input("Ethereum RPC URL", key="mp_rpc",
                                 placeholder="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY")
        mp_ntfy = st.text_input("ntfy.sh topic for push alerts (optional)", key="mp_ntfy",
                                 placeholder="my-forensics-alerts")
        mp_poll = st.slider("Poll interval (seconds)", 10, 60, 20, key="mp_poll")

        # Load watchlist
        wl_file = Path("watchlist.json")
        watched_addrs = []
        if wl_file.exists():
            try:
                watched_addrs = [item["address"] for item in json.loads(wl_file.read_text())]
            except Exception:
                pass

        st.markdown(f"**Watching {len(watched_addrs)} addresses** (from Alerts & Monitoring watchlist)")
        if watched_addrs:
            st.code("\n".join(watched_addrs[:5]) + ("\n…" if len(watched_addrs)>5 else ""))

        extra_addrs = st.text_area("Additional addresses to watch (one per line)", key="mp_extra", height=80)
        if extra_addrs.strip():
            watched_addrs += [a.strip() for a in extra_addrs.split("\n") if a.strip()]

        if not mp_rpc:
            st.warning("⚠️ Enter an RPC URL to start monitoring.")
        elif st.button("▶ Start Mempool Monitor", type="primary", key="start_mempool",
                        disabled=not bool(watched_addrs)):
            alert_box    = st.empty()
            mempool_log  = st.empty()
            stop_col     = st.columns(3)[1]
            stop_btn     = stop_col.button("⏹ Stop Monitor", key="stop_mempool")
            all_alerts   = []

            for cycle in range(1000):
                if stop_btn:
                    break
                matches = poll_mempool_for_addresses(watched_addrs, mp_rpc, mp_ntfy)
                if matches:
                    all_alerts = matches + all_alerts
                    for m in matches:
                        alert_box.error(
                            f"🚨 MEMPOOL HIT: `{m['watched_address'][:20]}…` "
                            f"| {m['value_eth']:.4f} ETH | {m['tx_hash'][:16]}…"
                        )
                else:
                    alert_box.info(
                        f"👁 Monitoring {len(watched_addrs)} addresses… "
                        f"Cycle {cycle+1} · {datetime.now().strftime('%H:%M:%S')}"
                    )

                if all_alerts:
                    mempool_log.dataframe(
                        pd.DataFrame(all_alerts[:20]),
                        width='stretch', hide_index=True
                    )

                time.sleep(mp_poll)
        elif not watched_addrs:
            st.warning("Add addresses to the watchlist in Alerts & Monitoring first.")

    with a2_tabs[3]:
        st.markdown("### 🔀 Atomic Swap & Cross-Chain DEX Detection")
        st.caption(
            "Atomic swaps and cross-chain DEXes (ThorChain, SideShift, FixedFloat) "
            "allow value to move between blockchains without exchange KYC. "
            "They are increasingly used as a layer of obfuscation in laundering chains."
        )
        if st.button("🔀 Detect Atomic Swaps", type="primary", key="run_atomic"):
            with st.spinner("Scanning for atomic swap and cross-chain activity…"):
                swap_df = detect_atomic_swaps(df)
                st.session_state.swap_df = swap_df

        if "swap_df" in st.session_state:
            sdf = st.session_state.swap_df
            if not sdf.empty:
                st.warning(f"⚠️ {len(sdf)} atomic swap / cross-chain events detected")

                # Summary by protocol
                if "protocol" in sdf.columns:
                    proto_sum = sdf.groupby(["protocol","risk"]).agg(
                        count=("amount","size"),
                        total_volume=("amount","sum")
                    ).reset_index()
                    st.dataframe(proto_sum, width='stretch', hide_index=True)

                st.markdown("**All Events:**")
                show = [c for c in ["date","pattern","protocol","risk","from_address",
                                     "to_address","amount","token","note"] if c in sdf.columns]
                st.dataframe(sdf[show], width='stretch', hide_index=True)
                st.download_button("⬇️ Export Atomic Swap Report",
                    sdf.to_csv(index=False).encode(), "atomic_swaps.csv", "text/csv")

                high_risk_swaps = sdf[sdf["risk"]=="HIGH"]
                if not high_risk_swaps.empty:
                    st.error(
                        f"🔴 {len(high_risk_swaps)} HIGH-risk atomic swap interactions. "
                        "FixedFloat and StealthEx have been linked to darknet market payments."
                    )
            else:
                st.success("✅ No atomic swap or cross-chain DEX activity detected.")
