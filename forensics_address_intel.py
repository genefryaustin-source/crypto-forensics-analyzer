"""
forensics_address_intel.py  —  Crypto Forensics Analyzer Pro v5.0
Address intelligence layer:
  • Bitcoin common-input-ownership (UTXO co-spending heuristic)
  • Heuristic address type classifier (Exchange / Mixer / DEX / Individual / Bridge)
  • Exchange deposit address pattern detection
  • Darknet market address intelligence
  • Change address detection
  • Address reputation aggregator
"""

import pandas as pd
import numpy as np
import streamlit as st
import requests
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# KNOWN ADDRESS DATABASES
# ─────────────────────────────────────────────────────────────

KNOWN_EXCHANGES = {
    # Binance
    "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be": "Binance",
    "0xd551234ae421e3bcba99a0da6d736074f22192ff": "Binance 2",
    "0x564286362092d8e7936f0549571a803b203aaced": "Binance 3",
    "0x0681d8db095565fe8a346fa0277bffde9c0edbbf": "Binance 4",
    "0xfe9e8709d3215310075d67e3ed32a380ccf451c8": "Binance 5",
    "0x4e9ce36e442e55ecd9025b9a6e0d88485d628a67": "Binance 6",
    "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8": "Binance Cold",
    "0xf977814e90da44bfa03b6295a0616a897441acec": "Binance 8",
    # Coinbase
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": "Coinbase",
    "0xa090e606e30bd747d4e6245a1517ebe430f0057e": "Coinbase 2",
    "0x77696bb39917c91a0c3908d577d5e322095425ca": "Coinbase 3",
    "0x503828976d22510aad0201ac7ec88293211d23da": "Coinbase 4",
    "0xddfabcdc4d8ffc6d5beaf154f18b778f892a0740": "Coinbase 5",
    # Kraken
    "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0": "Kraken",
    "0xfa52274dd61e1643d2205169732f29114bc240b3": "Kraken 2",
    "0x53d284357ec70ce289d6d64134dfac8e511c8a3d": "Kraken Cold",
    # OKX
    "0x5041ed759dd4afc3a72b8192c143f72f4724081f": "OKX",
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": "OKX 2",
    # Huobi
    "0xab5c66752a9e8167967685f1450532fb96d5d24f": "Huobi",
    "0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b": "Huobi 2",
    "0x7758e507850da48cd47df1fb5f875c23e3340c50": "Huobi 3",
    # Gate.io
    "0x0d0707963952f2fba59dd06f2b425ace40b492fe": "Gate.io",
    # Bitfinex
    "0x742d35cc6634c0532925a3b844bc454e4438f44e": "Bitfinex",
    "0x876eabf441b2ee5b5b0554fd502a8e0600950cfa": "Bitfinex 2",
    # KuCoin
    "0xd6216fc19db775df9774a6e33526131da7d19a2c": "KuCoin",
    "0xa1d8d972560c2f8144af871db508f0b0b10a3fbf": "KuCoin 2",
}

KNOWN_DARKNET = {
    # AlphaBay (seized 2017)
    "14KZsABFTL9s6gMpzkiJ7KMaQXqkSEPMR": "AlphaBay Market",
    "1BADmnFDEx1MP8zqAMDRbLH1TKYeJsXD6P": "AlphaBay Wallet",
    # Hydra Market (seized 2022)
    "0x296cD06a6a0b5A7FE29fE9a625C6CD1A44Df6e86": "Hydra Market",
    # Silk Road (seized 2013)
    "1FfmbHfnpaZjKFvyi1okTjJJusN455paPH": "Silk Road",
    # Generic darknet patterns
    "OMG!OMG!": "OMG!OMG! Darknet Market",
    "Hydra": "Hydra Market",
    "Empire": "Empire Market",
    "WhiteHouse": "WhiteHouse Market",
}

KNOWN_MIXERS = {
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 0.1 ETH",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 1 ETH",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado Cash 10 ETH",
    "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": "Tornado Cash 100 ETH",
    "0xba214c1c1928a32bffe790263e38b4af9bfcd659": "Tornado Cash Router",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": "Wasabi Coordinator",
    "bc1qs604c7jv6amk4cxqlnvuxv26hv3e48cds4m0ew": "JoinMarket",
}


# ─────────────────────────────────────────────────────────────
# 1. BITCOIN COMMON-INPUT-OWNERSHIP HEURISTIC
#    If two addresses appear as inputs in the same transaction,
#    they must be controlled by the same private key holder.
#    This is the foundational Bitcoin clustering technique.
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def bitcoin_common_input_ownership(df: pd.DataFrame) -> Dict[str, Set[str]]:
    """
    Apply the common-input-ownership heuristic to Bitcoin transactions.
    Groups addresses that appear as co-inputs into entity clusters.

    For EVM datasets, uses co-sender detection (same from_address in
    same time window sending to related addresses).

    Returns: {cluster_id: {address1, address2, ...}}
    """
    df = df.copy()
    df["date"] = pd.to_datetime(df["date"], errors="coerce")

    clusters = {}
    address_to_cluster = {}
    cluster_id = 0

    def union(a, b):
        nonlocal cluster_id
        ca = address_to_cluster.get(a)
        cb = address_to_cluster.get(b)
        if ca is None and cb is None:
            clusters[cluster_id] = {a, b}
            address_to_cluster[a] = cluster_id
            address_to_cluster[b] = cluster_id
            cluster_id += 1
        elif ca is None:
            clusters[cb].add(a)
            address_to_cluster[a] = cb
        elif cb is None:
            clusters[ca].add(b)
            address_to_cluster[b] = ca
        elif ca != cb:
            # Merge two clusters
            clusters[ca].update(clusters[cb])
            for addr in clusters[cb]:
                address_to_cluster[addr] = ca
            del clusters[cb]

    # For Bitcoin: group by tx_hash — all from_addresses in same tx are co-inputs
    if "tx_hash" in df.columns:
        tx_groups = df.groupby("tx_hash")["from_address"].apply(list)
        for tx_hash, addrs in tx_groups.items():
            unique = list(set(str(a) for a in addrs if pd.notna(a)))
            for i in range(len(unique) - 1):
                union(unique[i], unique[i+1])

    # Heuristic: same sender sending to multiple addresses within 1 minute
    # (suggests automated wallet sweeping = same controller)
    df_sorted = df.sort_values("date")
    for addr in df_sorted["from_address"].unique():
        addr_txs = df_sorted[df_sorted["from_address"] == addr].sort_values("date")
        recipients = addr_txs["to_address"].tolist()
        dates      = addr_txs["date"].tolist()
        for i in range(len(dates) - 1):
            if pd.notna(dates[i]) and pd.notna(dates[i+1]):
                gap = abs((dates[i+1] - dates[i]).total_seconds())
                if gap < 60:  # within 60 seconds → likely automated, same entity
                    union(str(recipients[i]), str(recipients[i+1]))

    logger.info(f"✅ Co-spending: {len(clusters)} entity clusters found")
    return clusters


def summarize_clusters(
    clusters: Dict[str, Set[str]],
    df: pd.DataFrame,
    min_size: int = 2,
) -> pd.DataFrame:
    """Convert cluster dict into a summary DataFrame."""
    rows = []
    vol_map = {}
    for addr in df["from_address"].unique():
        vol_map[addr] = df[df["from_address"] == addr]["amount"].sum()

    for cid, addrs in clusters.items():
        if len(addrs) < min_size:
            continue
        total_vol = sum(vol_map.get(a, 0) for a in addrs)
        rows.append({
            "cluster_id":      cid,
            "address_count":   len(addrs),
            "total_volume":    total_vol,
            "sample_addresses": list(addrs)[:3],
            "heuristic":       "common-input-ownership",
        })

    return pd.DataFrame(rows).sort_values("total_volume", ascending=False) if rows else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 2. ADDRESS TYPE CLASSIFIER
#    Heuristic-based classification without ML training data.
#    Categories: Exchange / Mixer / Bridge / DEX / Individual / Unknown
# ─────────────────────────────────────────────────────────────

ADDRESS_TYPE_RULES = {
    "EXCHANGE": {
        "min_unique_counterparties": 50,
        "min_tx_count":             100,
        "fan_in_ratio_min":          0.3,
        "fan_out_ratio_min":         0.3,
    },
    "MIXER": {
        "min_unique_counterparties": 20,
        "fan_in_fan_out_balance":    0.8,  # in ≈ out count
        "amount_uniformity_min":     0.6,  # txs cluster around same amounts
    },
    "BRIDGE": {
        "min_tx_count":              10,
        "cross_chain_indicator":     True,
        "large_amount_threshold":    10000,
    },
    "DEX": {
        "token_variety_min":         3,
        "known_defi_interaction":    True,
    },
}


@st.cache_data(show_spinner=False)
def classify_addresses(df: pd.DataFrame) -> pd.DataFrame:
    """
    Classify every unique address in the dataset by behavioral type.
    Uses heuristics — no ML training required.
    """
    all_addrs = set(df["from_address"].tolist() + df["to_address"].tolist())
    rows = []

    for addr in all_addrs:
        addr_str = str(addr)

        # Check known databases first
        if addr_str.lower() in {k.lower() for k in KNOWN_EXCHANGES}:
            label = next((v for k,v in KNOWN_EXCHANGES.items() if k.lower() == addr_str.lower()), "Exchange")
            rows.append({"address": addr_str, "type": "EXCHANGE", "label": label,
                         "confidence": 99, "source": "known_db"})
            continue
        if addr_str.lower() in {k.lower() for k in KNOWN_MIXERS}:
            label = next((v for k,v in KNOWN_MIXERS.items() if k.lower() == addr_str.lower()), "Mixer")
            rows.append({"address": addr_str, "type": "MIXER", "label": label,
                         "confidence": 99, "source": "known_db"})
            continue

        # Compute behavioral metrics
        outbound = df[df["from_address"] == addr_str]
        inbound  = df[df["to_address"]   == addr_str]
        total    = len(outbound) + len(inbound)

        if total == 0:
            continue

        unique_sent_to   = outbound["to_address"].nunique()
        unique_recv_from = inbound["from_address"].nunique()
        tokens_used      = pd.concat([outbound["token"], inbound["token"]]).nunique()
        out_vol          = outbound["amount"].sum()
        in_vol           = inbound["amount"].sum()
        out_count        = len(outbound)
        in_count         = len(inbound)

        # Amount uniformity — mixers tend to have txs cluster around same values
        if out_count > 3:
            out_amounts = outbound["amount"].values
            cv = out_amounts.std() / max(out_amounts.mean(), 0.001)
            amount_uniformity = 1 / (1 + cv)  # 0=random, 1=perfectly uniform
        else:
            amount_uniformity = 0

        # Fan-in / fan-out balance (mixers: nearly equal)
        fan_balance = 1 - abs(in_count - out_count) / max(in_count + out_count, 1)

        # Pass-through ratio
        pass_through = out_vol / max(in_vol, 0.001)

        # Classify
        addr_type   = "INDIVIDUAL"
        label       = "Individual Wallet"
        confidence  = 50

        if unique_sent_to > 100 and unique_recv_from > 50:
            addr_type = "EXCHANGE"; label = "Exchange (hot wallet)"; confidence = 80
        elif unique_sent_to > 30 and unique_recv_from > 30 and fan_balance > 0.7 and amount_uniformity > 0.5:
            addr_type = "MIXER"; label = "Potential Mixer"; confidence = 75
        elif tokens_used >= 4 and (unique_sent_to > 10 or unique_recv_from > 10):
            addr_type = "DEX_USER"; label = "Active DeFi User"; confidence = 65
        elif out_vol > 100000 and in_vol > 100000 and pass_through > 0.85:
            addr_type = "BRIDGE_OR_RELAY"; label = "Bridge/Relay"; confidence = 70
        elif total > 50 and unique_sent_to < 5:
            addr_type = "COLLECTOR"; label = "Collector/Consolidator"; confidence = 60
        elif total <= 10:
            addr_type = "INDIVIDUAL"; label = "Individual Wallet"; confidence = 55

        rows.append({
            "address":          addr_str,
            "type":             addr_type,
            "label":            label,
            "confidence":       confidence,
            "tx_count":         total,
            "unique_sent_to":   unique_sent_to,
            "unique_recv_from": unique_recv_from,
            "tokens_used":      tokens_used,
            "out_volume":       out_vol,
            "in_volume":        in_vol,
            "fan_balance":      round(fan_balance, 3),
            "amount_uniformity":round(amount_uniformity, 3),
            "pass_through_ratio": round(pass_through, 3),
            "source":           "heuristic",
        })

    return pd.DataFrame(rows).sort_values("confidence", ascending=False)


# ─────────────────────────────────────────────────────────────
# 3. EXCHANGE DEPOSIT ADDRESS DETECTION
#    When funds flow to an exchange deposit address, the trail
#    ends — exchange has KYC. Identifying this is a key step.
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_walletexplorer_labels(address: str) -> Optional[str]:
    """Query WalletExplorer.com for Bitcoin address labels (free, no key)."""
    try:
        resp = requests.get(
            f"https://www.walletexplorer.com/api/1/address",
            params={"address": address, "caller": "forensics_analyzer"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("label") or data.get("wallet", {}).get("label")
    except Exception:
        pass
    return None


def detect_exchange_endpoints(df: pd.DataFrame) -> pd.DataFrame:
    """
    Find transactions where funds flow to known exchange addresses.
    These are investigation endpoints — exchange has KYC on the recipient.
    """
    df = df.copy()
    exchange_map = {k.lower(): v for k, v in KNOWN_EXCHANGES.items()}

    df["to_exchange"]    = df["to_address"].str.lower().map(exchange_map).fillna("")
    df["from_exchange"]  = df["from_address"].str.lower().map(exchange_map).fillna("")
    df["exchange_endpoint"] = (df["to_exchange"] != "") | (df["from_exchange"] != "")

    exchange_txs = df[df["exchange_endpoint"]].copy()
    exchange_txs["exchange_name"] = exchange_txs["to_exchange"].where(
        exchange_txs["to_exchange"] != "", exchange_txs["from_exchange"]
    )

    return exchange_txs


# ─────────────────────────────────────────────────────────────
# 4. DARKNET INTELLIGENCE
#    Multi-source darknet address screening beyond OFAC.
#    Includes community-maintained lists and behavioral patterns.
# ─────────────────────────────────────────────────────────────

DARKNET_PATTERNS = [
    "alphabay", "hydra", "omgomg", "whitehouse", "empire",
    "darknet", "darkweb", "silk road", "dream market", "hansa",
    "versus", "world market", "darkode", "genesis market",
]


@st.cache_data(ttl=7200, show_spinner=False)
def fetch_community_blacklist() -> Set[str]:
    """
    Fetch community-maintained crypto blacklist from GitHub.
    https://github.com/CryptoScamDB/blacklist
    Returns set of blacklisted addresses.
    """
    blacklist = set()
    try:
        resp = requests.get(
            "https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/urls.yaml",
            timeout=15,
        )
        if resp.status_code == 200:
            # Parse YAML-style address list (simple format)
            for line in resp.text.split("\n"):
                line = line.strip()
                if line.startswith("- ") and ("0x" in line or len(line) > 25):
                    addr = line.replace("- ", "").strip().lower()
                    if addr:
                        blacklist.add(addr)
    except Exception:
        pass

    # Also check known darknet addresses
    for addr in KNOWN_DARKNET:
        blacklist.add(addr.lower())

    logger.info(f"✅ Community blacklist: {len(blacklist)} addresses")
    return blacklist


def screen_darknet_intelligence(df: pd.DataFrame) -> pd.DataFrame:
    """Screen addresses against darknet intelligence sources."""
    df = df.copy()

    # Pattern matching in address labels
    combined = (df["from_address"].astype(str) + " " + df["to_address"].astype(str)).str.lower()
    df["darknet_pattern_hit"] = combined.apply(
        lambda x: any(p in x for p in DARKNET_PATTERNS)
    )

    # Known darknet address matching
    darknet_lower = {k.lower(): v for k, v in KNOWN_DARKNET.items()}
    df["darknet_entity"] = (
        df["from_address"].str.lower().map(darknet_lower).fillna("") +
        df["to_address"].str.lower().map(darknet_lower).fillna("")
    ).str.strip()
    df["darknet_hit"] = (df["darknet_pattern_hit"]) | (df["darknet_entity"] != "")

    return df


# ─────────────────────────────────────────────────────────────
# 5. CHANGE ADDRESS DETECTION (Bitcoin-focused)
#    In Bitcoin, change from a transaction goes to a new address
#    controlled by the same wallet. Identifying change addresses
#    reveals more wallet addresses for the same entity.
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def detect_change_addresses(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect likely change addresses in a transaction set.
    Change address heuristics:
    1. Address appears only once as a recipient (first-use rule)
    2. Amount is a remainder (not round number)
    3. Same transaction has a round-number output (the payment)
    """
    df = df.copy()
    df["date"] = pd.to_datetime(df["date"], errors="coerce")

    # Count how many times each address appears
    addr_counts = pd.concat([
        df["from_address"].value_counts(),
        df["to_address"].value_counts()
    ]).groupby(level=0).sum()

    # First-use: address appears exactly once as recipient
    to_counts = df["to_address"].value_counts()
    first_use_addrs = set(to_counts[to_counts == 1].index)

    # Non-round amounts (change is rarely a round number)
    df["is_round"] = df["amount"].apply(lambda x: x == round(x, -2) and x > 100)

    # Flag potential change addresses
    change_candidates = []
    for _, tx in df.iterrows():
        to_addr = tx["to_address"]
        if (to_addr in first_use_addrs and
            not df["is_round"].loc[df["to_address"] == to_addr].any()):

            # Check if same transaction has a round-number sibling (the real payment)
            same_time = df[
                (df["from_address"] == tx["from_address"]) &
                (abs((df["date"] - tx["date"]).dt.total_seconds()) < 10) &
                (df["to_address"] != to_addr)
            ]
            has_round_sibling = same_time["is_round"].any()

            if has_round_sibling:
                change_candidates.append({
                    "likely_change_address": to_addr,
                    "from_address":          tx["from_address"],
                    "change_amount":         tx["amount"],
                    "tx_hash":               tx.get("tx_hash", ""),
                    "date":                  str(tx["date"]),
                    "confidence":            75,
                    "note":                  "First-use address with non-round amount alongside round payment",
                })

    logger.info(f"✅ Change address detection: {len(change_candidates)} candidates")
    return pd.DataFrame(change_candidates) if change_candidates else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 6. ADDRESS REPUTATION AGGREGATOR
#    Combines all intelligence sources into a single score.
# ─────────────────────────────────────────────────────────────

def get_address_reputation(
    address: str,
    df: pd.DataFrame,
    ofac_addrs: Optional[Set[str]] = None,
    ransomware_addrs: Optional[Set[str]] = None,
    community_blacklist: Optional[Set[str]] = None,
) -> Dict:
    """
    Aggregate all intelligence sources for a single address.
    Returns a comprehensive reputation profile.
    """
    addr_lower = address.lower()
    reputation = {
        "address":         address,
        "reputation_score": 0,    # 0 = clean, 100 = confirmed malicious
        "flags":           [],
        "entity_type":     "UNKNOWN",
        "entity_name":     "",
        "sources_checked": [],
        "risk_level":      "LOW",
    }

    score = 0

    # Known exchanges (positive signal — investigation endpoint)
    if addr_lower in {k.lower() for k in KNOWN_EXCHANGES}:
        name = next((v for k,v in KNOWN_EXCHANGES.items() if k.lower() == addr_lower), "Exchange")
        reputation["entity_type"] = "EXCHANGE"
        reputation["entity_name"] = name
        reputation["flags"].append(f"Known exchange: {name}")
        reputation["sources_checked"].append("known_exchanges_db")
        reputation["risk_level"] = "LOW"
        reputation["reputation_score"] = 10
        return reputation

    # Known mixers
    if addr_lower in {k.lower() for k in KNOWN_MIXERS}:
        name = next((v for k,v in KNOWN_MIXERS.items() if k.lower() == addr_lower), "Mixer")
        score += 95
        reputation["entity_type"] = "MIXER"
        reputation["entity_name"] = name
        reputation["flags"].append(f"Known mixer: {name}")
        reputation["sources_checked"].append("known_mixers_db")

    # OFAC SDN
    if ofac_addrs and addr_lower in ofac_addrs:
        score += 100
        reputation["flags"].append("⚠️ OFAC SDN MATCH — SANCTIONED ENTITY")
        reputation["sources_checked"].append("OFAC_SDN")
        reputation["entity_type"] = "SANCTIONED"

    # Ransomware
    if ransomware_addrs and addr_lower in ransomware_addrs:
        score += 95
        reputation["flags"].append("☠️ RANSOMWARE ADDRESS (Ransomwhere.co)")
        reputation["sources_checked"].append("Ransomwhere")
        reputation["entity_type"] = "RANSOMWARE"

    # Community blacklist
    if community_blacklist and addr_lower in community_blacklist:
        score += 70
        reputation["flags"].append("🚫 Community blacklist (CryptoScamDB)")
        reputation["sources_checked"].append("CryptoScamDB")

    # Darknet patterns
    if any(p in addr_lower for p in DARKNET_PATTERNS):
        score += 85
        reputation["flags"].append("🕵️ Darknet pattern match")
        reputation["sources_checked"].append("darknet_patterns")

    # Behavioral score from dataset
    outbound = df[df["from_address"].str.lower() == addr_lower]
    inbound  = df[df["to_address"].str.lower() == addr_lower]
    if "risk_level" in df.columns:
        crit = ((outbound["risk_level"] == "CRITICAL").sum() +
                (inbound["risk_level"] == "CRITICAL").sum())
        if crit > 0:
            score += min(40, crit * 10)
            reputation["flags"].append(f"{crit} CRITICAL-risk transactions")
            reputation["sources_checked"].append("dataset_risk_scoring")

    reputation["reputation_score"] = min(100, score)
    if score >= 85:   reputation["risk_level"] = "CRITICAL"
    elif score >= 60: reputation["risk_level"] = "HIGH"
    elif score >= 35: reputation["risk_level"] = "MEDIUM"
    else:             reputation["risk_level"] = "LOW"

    return reputation


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_address_intel_ui(df: pd.DataFrame):
    """Full address intelligence UI."""
    st.markdown("### 🏷️ Address Intelligence")
    st.caption(
        "Advanced address analysis: entity clustering, type classification, "
        "exchange endpoint detection, darknet screening, and change address identification."
    )

    ai_tabs = st.tabs([
        "🔗 Co-spending Clusters", "🏷️ Address Classifier",
        "🏦 Exchange Endpoints",   "🕵️ Darknet Intel",
        "♻️ Change Addresses",     "⭐ Reputation Score"
    ])

    with ai_tabs[0]:
        st.markdown("**Bitcoin Common-Input-Ownership Heuristic**")
        st.caption(
            "If two addresses appear as co-inputs in the same transaction, they must be "
            "controlled by the same entity. Groups wallets belonging to the same controller."
        )
        min_cluster = st.number_input("Min addresses per cluster", 2, 10, 2, key="min_cluster")
        if st.button("🔗 Find Entity Clusters", type="primary", key="run_cio"):
            with st.spinner("Applying co-spending heuristic…"):
                clusters = bitcoin_common_input_ownership(df)
                summary  = summarize_clusters(clusters, df, min_size=int(min_cluster))
                st.session_state.cio_clusters = clusters
                st.session_state.cio_summary  = summary
            st.success(f"✅ Found {len(clusters)} entity clusters")

        if "cio_summary" in st.session_state:
            s = st.session_state.cio_summary
            if not s.empty:
                st.dataframe(s, use_container_width=True, hide_index=True)
                st.download_button("⬇️ Export Clusters CSV",
                    s.to_csv(index=False).encode(), "entity_clusters.csv", "text/csv")
            else:
                st.info("No multi-address clusters found.")

    with ai_tabs[1]:
        st.markdown("**Heuristic Address Type Classifier**")
        st.caption(
            "Classifies every address as Exchange / Mixer / Bridge / DEX User / "
            "Collector / Individual using behavioral heuristics."
        )
        if st.button("🏷️ Classify All Addresses", type="primary", key="run_classify"):
            with st.spinner("Classifying addresses…"):
                class_df = classify_addresses(df)
                st.session_state.class_df = class_df

        if "class_df" in st.session_state:
            cdf = st.session_state.class_df
            # Summary
            type_counts = cdf["type"].value_counts().reset_index()
            type_counts.columns = ["Type","Count"]
            c1, c2 = st.columns([1,2])
            with c1:
                st.dataframe(type_counts, use_container_width=True, hide_index=True)
            with c2:
                st.bar_chart(type_counts.set_index("Type")["Count"])

            st.markdown("**Full Classification Results**")
            show_cols = [c for c in ["address","type","label","confidence",
                                      "tx_count","out_volume","tokens_used"] if c in cdf.columns]
            st.dataframe(cdf[show_cols], use_container_width=True, hide_index=True)
            st.download_button("⬇️ Export Classifications",
                cdf.to_csv(index=False).encode(), "address_types.csv", "text/csv")

    with ai_tabs[2]:
        st.markdown("**Exchange Endpoint Detection**")
        st.caption(
            "Identifies transactions flowing to known exchange addresses. "
            "These are investigation endpoints — the exchange holds KYC on the recipient. "
            "Present findings to the exchange with a legal process request."
        )
        if st.button("🏦 Find Exchange Endpoints", type="primary", key="run_exchange"):
            with st.spinner("Matching exchange addresses…"):
                exc_df = detect_exchange_endpoints(df)
                st.session_state.exc_df = exc_df

        if "exc_df" in st.session_state:
            edf = st.session_state.exc_df
            if not edf.empty:
                st.success(f"✅ {len(edf)} transactions reach exchange endpoints")
                exc_summary = edf.groupby("exchange_name").agg(
                    tx_count=("amount","size"),
                    total_volume=("amount","sum")
                ).reset_index().sort_values("total_volume", ascending=False)
                st.dataframe(exc_summary, use_container_width=True, hide_index=True)

                show = [c for c in ["date","from_address","to_address","amount",
                                     "token","exchange_name","risk_level"] if c in edf.columns]
                st.dataframe(edf[show], use_container_width=True, hide_index=True)
                st.download_button("⬇️ Export Exchange Endpoints",
                    edf[show].to_csv(index=False).encode(),
                    "exchange_endpoints.csv", "text/csv")

                st.info(
                    "💡 **Next step:** Serve legal process (subpoena/MLATs) to exchanges "
                    "listed above to obtain KYC identity of the account holder."
                )
            else:
                st.info("No known exchange endpoints detected in dataset.")

    with ai_tabs[3]:
        st.markdown("**Darknet Intelligence Screening**")
        st.caption(
            "Screens addresses against darknet market address databases, "
            "community blacklists (CryptoScamDB), and behavioral patterns."
        )
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            if st.button("🕵️ Screen Darknet Intel", type="primary", key="run_dark"):
                with st.spinner("Screening darknet intelligence…"):
                    dark_df = screen_darknet_intelligence(df)
                    st.session_state.dark_df = dark_df
                    hits = dark_df["darknet_hit"].sum()
                st.success(f"Found {hits} darknet-related transactions") if hits else st.success("✅ No hits")
        with col_d2:
            if st.button("🌐 Fetch Community Blacklist", key="run_blacklist"):
                with st.spinner("Downloading CryptoScamDB blacklist…"):
                    bl = fetch_community_blacklist()
                    st.session_state.community_bl = bl
                st.success(f"✅ {len(bl)} addresses in blacklist")

        if "dark_df" in st.session_state:
            ddf = st.session_state.dark_df
            hits = ddf[ddf["darknet_hit"]]
            if not hits.empty:
                show = [c for c in ["date","from_address","to_address","amount",
                                     "token","darknet_entity","risk_level"] if c in hits.columns]
                st.dataframe(hits[show], use_container_width=True, hide_index=True)

    with ai_tabs[4]:
        st.markdown("**Change Address Detection**")
        st.caption(
            "Identifies likely change addresses — the 'leftover' from Bitcoin transactions "
            "sent back to a new address controlled by the sender. Reveals additional wallet addresses."
        )
        if st.button("♻️ Detect Change Addresses", type="primary", key="run_change"):
            with st.spinner("Detecting change addresses…"):
                chg_df = detect_change_addresses(df)
                st.session_state.chg_df = chg_df
            if not chg_df.empty:
                st.warning(f"⚠️ {len(chg_df)} likely change addresses found")
            else:
                st.success("✅ No change addresses detected")

        if "chg_df" in st.session_state and not st.session_state.chg_df.empty:
            st.dataframe(st.session_state.chg_df, use_container_width=True, hide_index=True)
            st.download_button("⬇️ Export Change Addresses",
                st.session_state.chg_df.to_csv(index=False).encode(),
                "change_addresses.csv", "text/csv")

    with ai_tabs[5]:
        st.markdown("**Address Reputation Score**")
        st.caption("Aggregate reputation score combining all intelligence sources for a single address.")
        rep_addr = st.text_input("Address to score", key="rep_addr",
                                  placeholder="Paste any address from the dataset")
        if st.button("⭐ Get Reputation", type="primary", key="run_rep") and rep_addr.strip():
            ofac_set = set(st.session_state.get("ofac_df", {}).get("from_address", []))
            rw_set   = set(st.session_state.get("rw_df", {}).get("from_address", []))
            bl_set   = st.session_state.get("community_bl", set())
            rep = get_address_reputation(rep_addr.strip(), df, ofac_set, rw_set, bl_set)

            colors = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
            st.markdown(
                f"### {colors.get(rep['risk_level'],'⚪')} `{rep['address'][:30]}…`"
            )
            rc1, rc2, rc3 = st.columns(3)
            rc1.metric("Reputation Score", f"{rep['reputation_score']}/100")
            rc2.metric("Risk Level",       rep["risk_level"])
            rc3.metric("Entity Type",      rep["entity_type"])
            if rep["entity_name"]:
                st.info(f"**Identified as:** {rep['entity_name']}")
            st.markdown("**Intelligence flags:**")
            for flag in rep["flags"]:
                st.markdown(f"- {flag}")
            st.caption(f"Sources checked: {', '.join(rep['sources_checked']) or 'none'}")
