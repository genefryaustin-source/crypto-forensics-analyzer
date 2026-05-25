"""
Advanced Forensics Pattern Detection Module
Detects: wallet clustering, circular flows, behavioral anomalies
For use with Crypto Forensics Analyzer Pro v5.0
"""

import pandas as pd
import numpy as np
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


from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime, timedelta
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import streamlit as st

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# ADDRESS CLUSTERING & FINGERPRINTING
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def cluster_addresses_by_behavior(
    df: pd.DataFrame,
    similarity_threshold: float = 0.5,
    min_cluster_size: int = 2
) -> Dict[int, List[str]]:
    """
    Cluster wallets with similar transaction patterns.
    Identifies: mixer networks, exchange sweepers, bot clusters, coordinated activity

    Features used:
    - Average transaction amount (size profile)
    - Token diversity (what they trade)
    - Recipient count (how many people they pay)
    - Transaction frequency (activity level)
    - Volume concentration (80/20 concentration)

    Returns: {cluster_id: [addresses]}
    """
    logger.info("Starting address clustering...")

    # Build feature matrix for each sending address
    features_list = []
    address_map = []

    for addr in df['from_address'].unique():
        addr_txs = df[df['from_address'] == addr]

        if len(addr_txs) < 2:
            continue  # Need at least 2 txs for clustering

        amounts = addr_txs['amount'].values
        amount_nonzero = amounts[amounts > 0]

        # Calculate concentration (Pareto: what % of txs = what % of volume)
        if len(amount_nonzero) > 0:
            sorted_amounts = np.sort(amount_nonzero)[::-1]
            cumsum = np.cumsum(sorted_amounts) / sorted_amounts.sum()
            concentration = np.where(cumsum >= 0.8)[0][0] / len(sorted_amounts) if len(np.where(cumsum >= 0.8)[0]) > 0 else 1.0
        else:
            concentration = 0

        feature_vector = [
            np.mean(amount_nonzero) if len(amount_nonzero) > 0 else 0,  # avg amount
            np.std(amount_nonzero) if len(amount_nonzero) > 1 else 0,   # volatility
            addr_txs['token'].nunique(),                                 # token diversity
            addr_txs['to_address'].nunique(),                            # recipient count
            len(addr_txs),                                               # frequency
            addr_txs['amount'].sum(),                                    # total volume
            concentration,                                               # volume concentration
        ]

        features_list.append(feature_vector)
        address_map.append(addr)

    if len(features_list) < min_cluster_size:
        logger.warning("Not enough addresses for clustering")
        return {}

    # Normalize features (important for DBSCAN)
    X = StandardScaler().fit_transform(np.array(features_list))

    # DBSCAN clustering
    # eps = distance threshold, min_samples = min wallets per cluster
    dbscan = DBSCAN(eps=similarity_threshold, min_samples=min_cluster_size, metric='euclidean')
    labels = dbscan.fit_predict(X)

    # Group addresses by cluster ID
    clusters = {}
    for addr, label in zip(address_map, labels):
        if label == -1:  # Skip noise points
            continue
        if label not in clusters:
            clusters[label] = []
        clusters[label].append(addr)

    logger.info(f"✅ Identified {len(clusters)} clusters from {len(address_map)} addresses")

    return clusters


def analyze_cluster_characteristics(df: pd.DataFrame, clusters: Dict[int, List[str]]) -> List[Dict]:
    """
    Analyze each cluster to identify its purpose/type
    Returns detailed profile of each cluster
    """
    cluster_profiles = []

    for cluster_id, addresses in clusters.items():
        cluster_df = df[df['from_address'].isin(addresses)]

        inter_cluster_txs = 0
        for addr in addresses:
            outgoing = df[df['from_address'] == addr]
            inter_cluster_txs += len(outgoing[outgoing['to_address'].isin(addresses)])

        profile = {
            'cluster_id': cluster_id,
            'member_count': len(addresses),
            'total_volume': cluster_df['amount'].sum(),
            'avg_tx_size': cluster_df['amount'].mean(),
            'token_diversity': cluster_df['token'].nunique(),
            'primary_token': cluster_df['token'].mode()[0] if len(cluster_df) > 0 else 'UNKNOWN',
            'transaction_count': len(cluster_df),
            'unique_recipients': cluster_df['to_address'].nunique(),
            'intra_cluster_ratio': inter_cluster_txs / max(1, len(cluster_df)),
            'risk_level': cluster_df['risk_level'].mode()[0] if len(cluster_df) > 0 else 'LOW',
            'avg_risk_score': cluster_df['risk_score'].mean(),
            'members': addresses[:5] + (['...'] if len(addresses) > 5 else []),
        }

        # Classify cluster type
        if profile['intra_cluster_ratio'] > 0.5:
            profile['classification'] = '🔄 INTERNAL_NETWORK (high internal transfers)'
        elif profile['token_diversity'] > 10 and profile['unique_recipients'] > 20:
            profile['classification'] = '🤖 MIXER_PATTERN (high diversification)'
        elif profile['member_count'] > 10 and profile['intra_cluster_ratio'] < 0.1:
            profile['classification'] = '🏦 EXCHANGE_SWEEP (many sources, external focus)'
        elif profile['avg_tx_size'] > 100000:
            profile['classification'] = '💰 WHALE_POOL (large transaction profile)'
        elif profile['transaction_count'] > 100:
            profile['classification'] = '🤖 BOT_NETWORK (high frequency, low diversity)'
        else:
            profile['classification'] = '❓ UNKNOWN_PATTERN'

        cluster_profiles.append(profile)

    return sorted(cluster_profiles, key=lambda x: x['total_volume'], reverse=True)


# ─────────────────────────────────────────────────────────────
# CIRCULAR FLOW & MONEY LAUNDERING DETECTION
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def detect_circular_flows(
    df: pd.DataFrame,
    min_cycle_length: int = 2,
    max_cycle_length: int = 6,
    time_window_hours: int = 24
) -> List[Dict]:
    """
    Detect circular transactions: A→B→C→A patterns
    Red flags for: wash trading, self-dealing, mixer testing, round-tripping

    Args:
        df: Transaction dataframe
        min_cycle_length: Minimum number of participants in cycle
        max_cycle_length: Maximum depth to search (performance vs coverage)
        time_window_hours: Only consider cycles within this time window

    Returns: List of detected cycles with details
    """
    logger.info("Scanning for circular flows...")

    df = df.copy()
    df['date'] = pd.to_datetime(df['date'], errors='coerce')

    circular_flows = []
    processed_cycles = set()  # Avoid duplicates

    # Build transaction graph
    graph = {}
    tx_index = {}

    for idx, row in df.iterrows():
        fr = str(row['from_address']).lower().strip()
        to = str(row['to_address']).lower().strip()

        if fr == to:  # Skip self-transfers
            continue

        if fr not in graph:
            graph[fr] = []

        graph[fr].append({
            'to': to,
            'amount': row['amount'],
            'date': row['date'],
            'token': row['token'],
            'tx_hash': row['tx_hash'],
            'risk_level': row['risk_level'],
        })

        tx_index[f"{fr}-{to}"] = row

    logger.info(f"Built graph with {len(graph)} addresses, scanning for cycles...")

    # DFS to find cycles
    def find_cycles_dfs(
        start: str,
        current: str,
        path: List[str],
        edges_info: List[Dict],
        visited_global: Set[str],
        depth: int = 0
    ) -> List[Tuple[List[str], List[Dict]]]:
        """Depth-first search for cycles"""
        if depth > max_cycle_length:
            return []

        if current not in graph:
            return []

        cycles = []

        for next_tx in graph[current]:
            next_addr = next_tx['to']

            # Check if we've completed a cycle
            if next_addr == start and len(path) >= min_cycle_length:
                cycle_path = path + [start]
                cycle_key = tuple(sorted(cycle_path[:-1]))  # Normalize for dedup

                if cycle_key not in processed_cycles:
                    processed_cycles.add(cycle_key)

                    # Validate time window
                    time_span = (next_tx['date'] - edges_info[0]['date']).total_seconds() / 3600
                    if time_span <= time_window_hours:
                        cycles.append((cycle_path, edges_info + [next_tx]))

            # Avoid revisiting nodes in current path (except start)
            elif next_addr not in path or (next_addr == start and len(path) < min_cycle_length):
                new_edges = edges_info + [next_tx]
                cycles.extend(
                    find_cycles_dfs(
                        start, next_addr, path + [next_addr],
                        new_edges, visited_global, depth + 1
                    )
                )

        return cycles

    # Scan from each address (limit to top 200 by volume to avoid explosion)
    top_addresses = df.groupby('from_address')['amount'].sum().nlargest(200).index.tolist()

    for start_addr in top_addresses:
        if start_addr in graph:
            found_cycles = find_cycles_dfs(start_addr, start_addr, [], [], set())

            for cycle_path, edge_info in found_cycles:
                total_volume = sum(e['amount'] for e in edge_info[:-1])
                avg_volume = total_volume / len(edge_info[:-1]) if edge_info else 0

                # Calculate risk metrics
                critical_count = sum(1 for e in edge_info if e['risk_level'] == 'CRITICAL')
                high_count = sum(1 for e in edge_info if e['risk_level'] == 'HIGH')

                circular_flows.append({
                    'cycle': cycle_path,
                    'cycle_length': len(cycle_path) - 1,
                    'participants': len(set(cycle_path[:-1])),
                    'total_volume': total_volume,
                    'avg_per_hop': avg_volume,
                    'time_span_hours': (edge_info[-1]['date'] - edge_info[0]['date']).total_seconds() / 3600,
                    'tokens': list(set(e['token'] for e in edge_info)),
                    'critical_hops': critical_count,
                    'high_risk_hops': high_count,
                    'avg_risk_score': np.mean([e.get('risk_level', 'LOW') for e in edge_info]),
                    'dates': [e['date'] for e in edge_info],
                    'tx_hashes': [e['tx_hash'] for e in edge_info],
                    'severity_score': min(100, (critical_count * 25 + high_count * 15) + (len(cycle_path) * 5)),
                })

    logger.info(f"✅ Found {len(circular_flows)} circular flows")
    return sorted(circular_flows, key=lambda x: x['severity_score'], reverse=True)


def classify_circular_flow(flow: Dict) -> str:
    """Classify the type of circular flow"""
    severity = flow['severity_score']
    cycle_len = flow['cycle_length']
    time_span = flow['time_span_hours']
    volume = flow['total_volume']

    if severity >= 80:
        return '🔴 CRITICAL_CYCLE'
    elif cycle_len == 2 and volume > 10000:
        return '⚠️ TWO_PARTY_WASH (likely artificial)'
    elif time_span < 1:
        return '⚡ RAPID_CYCLE (likely automated)'
    elif cycle_len >= 5:
        return '🔄 COMPLEX_CHAIN (sophisticated layering)'
    elif len(flow['tokens']) > 1:
        return '💱 MULTI_TOKEN_CYCLE (token swapping)'
    else:
        return '🤔 SUSPICIOUS_CYCLE'


# ─────────────────────────────────────────────────────────────
# BEHAVIORAL ANOMALY DETECTION
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def detect_behavioral_anomalies(df: pd.DataFrame, lookback_pct: float = 0.33) -> List[Dict]:
    """
    Detect addresses with unusual behavior shifts:
    - Sudden volume spikes
    - Recipient diversification explosions
    - Token switching patterns
    - Activity timing anomalies

    Args:
        df: Transaction dataframe
        lookback_pct: Percentage of transactions to use as "baseline"

    Returns: List of anomalies with severity scores
    """
    logger.info("Scanning for behavioral anomalies...")

    df = df.copy()
    df['date'] = pd.to_datetime(df['date'], errors='coerce')
    anomalies = []

    for addr in df['from_address'].unique():
        addr_txs = df[df['from_address'] == addr].sort_values('date').reset_index(drop=True)

        if len(addr_txs) < 5:
            continue

        split_idx = int(len(addr_txs) * lookback_pct)
        early_txs = addr_txs.iloc[:split_idx]
        late_txs = addr_txs.iloc[split_idx:]

        if len(late_txs) == 0:
            continue

        # 1. VOLUME SPIKE DETECTION
        if len(early_txs) > 2:
            early_mean = early_txs['amount'].mean()
            early_std = early_txs['amount'].std()

            for idx, tx in late_txs.iterrows():
                z_score = abs((tx['amount'] - early_mean) / max(early_std, 1))
                if z_score > 3:  # 3 sigma event
                    anomalies.append({
                        'address': addr,
                        'type': 'VOLUME_SPIKE',
                        'severity': min(100, int(z_score * 20)),
                        'detail': f"{fmt_crypto(tx['amount'])} (mean: {fmt_crypto(early_mean)}, std: {fmt_crypto(early_std)})",
                        'timestamp': tx['date'],
                        'tx_hash': tx['tx_hash'],
                    })

        # 2. RECIPIENT DIVERSIFICATION SURGE
        early_recipients = early_txs['to_address'].nunique()
        late_recipients = late_txs['to_address'].nunique()

        if early_recipients > 0 and late_recipients / max(early_recipients, 1) > 3:
            anomalies.append({
                'address': addr,
                'type': 'RECIPIENT_EXPLOSION',
                'severity': min(100, int((late_recipients / early_recipients) * 15)),
                'detail': f"{late_recipients} recipients vs baseline {early_recipients}",
                'timestamp': late_txs.iloc[-1]['date'],
                'tx_hash': late_txs.iloc[-1]['tx_hash'],
            })

        # 3. TOKEN SWITCHING (suddenly uses new tokens)
        early_tokens = set(early_txs['token'].unique())
        late_tokens = set(late_txs['token'].unique())
        new_tokens = late_tokens - early_tokens

        if len(new_tokens) >= 3:
            anomalies.append({
                'address': addr,
                'type': 'TOKEN_DIVERSIFICATION',
                'severity': min(100, len(new_tokens) * 15),
                'detail': f"Switched to {len(new_tokens)} new tokens: {', '.join(list(new_tokens)[:5])}",
                'timestamp': late_txs.iloc[-1]['date'],
                'tx_hash': late_txs.iloc[-1]['tx_hash'],
            })

        # 4. FREQUENCY SPIKE
        early_freq = len(early_txs) / max((early_txs['date'].max() - early_txs['date'].min()).days, 1)
        late_freq = len(late_txs) / max((late_txs['date'].max() - late_txs['date'].min()).days, 1)

        if early_freq > 0 and late_freq / early_freq > 5:
            anomalies.append({
                'address': addr,
                'type': 'ACTIVITY_SURGE',
                'severity': min(100, int((late_freq / early_freq) * 15)),
                'detail': f"{late_freq:.1f} tx/day vs baseline {early_freq:.1f}",
                'timestamp': late_txs.iloc[-1]['date'],
                'tx_hash': late_txs.iloc[-1]['tx_hash'],
            })

    logger.info(f"✅ Detected {len(anomalies)} behavioral anomalies")
    return sorted(anomalies, key=lambda x: x['severity'], reverse=True)


# ─────────────────────────────────────────────────────────────
# MIXER/TUMBLER DETECTION
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def detect_mixer_patterns(df: pd.DataFrame) -> List[Dict]:
    """
    Identify addresses exhibiting mixer/tumbler characteristics:
    - Many inputs, many outputs (fan-in/fan-out)
    - Similar amounts in/out
    - Low recipient reuse
    - Time-based pattern matching
    """
    logger.info("Scanning for mixer patterns...")

    mixer_candidates = []

    for addr in df['from_address'].unique():
        outgoing = df[df['from_address'] == addr]
        incoming = df[df['to_address'] == addr]

        if len(outgoing) < 5 or len(incoming) < 5:
            continue

        # Mixer signature: high fan-in and fan-out
        fan_in = incoming['from_address'].nunique()
        fan_out = outgoing['to_address'].nunique()

        # Low recipient reuse
        reuse_ratio = len(outgoing[outgoing['to_address'].isin(incoming['from_address'])]) / max(1, len(outgoing))

        # Calculate score
        mixer_score = 0

        if fan_in > 10:
            mixer_score += min(30, fan_in * 2)
        if fan_out > 10:
            mixer_score += min(30, fan_out * 2)
        if reuse_ratio < 0.1:
            mixer_score += 20

        # Amount similarity (input ~= output)
        in_total = incoming['amount'].sum()
        out_total = outgoing['amount'].sum()
        if in_total > 0:
            amount_diff = abs(in_total - out_total) / in_total
            if amount_diff < 0.2:  # Within 20%
                mixer_score += 20

        if mixer_score >= 40:
            mixer_candidates.append({
                'address': addr,
                'mixer_score': min(100, mixer_score),
                'fan_in': fan_in,
                'fan_out': fan_out,
                'reuse_ratio': reuse_ratio,
                'total_volume': outgoing['amount'].sum(),
                'transaction_count': len(outgoing),
                'classification': '🔄 MIXER' if mixer_score >= 70 else '⚠️ MIXER_SUSPECT',
            })

    logger.info(f"✅ Found {len(mixer_candidates)} mixer candidates")
    return sorted(mixer_candidates, key=lambda x: x['mixer_score'], reverse=True)
