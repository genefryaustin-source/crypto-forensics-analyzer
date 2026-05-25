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
import time
import re
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




# ─────────────────────────────────────────────────────────────
# 4b. GOPLUS SECURITY  (free, no API key required)
#     30M+ flagged addresses across ETH/BSC/Polygon/Avalanche/
#     Optimism/Arbitrum/Tron. Covers: malicious, phishing,
#     honeypot-related, cybercrime, money laundering, mixer,
#     sanctioned, darkweb transactions, financial crime.
#     https://gopluslabs.io
# ─────────────────────────────────────────────────────────────

GOPLUS_API   = "https://api.gopluslabs.io/api/v1/address_security"
GOPLUS_CHAIN_IDS = {
    "ethereum":  "1",
    "bsc":       "56",
    "polygon":   "137",
    "avalanche": "43114",
    "arbitrum":  "42161",
    "optimism":  "10",
    "tron":      "tron",
    "solana":    "solana",
}

# GoPlus result fields that indicate a risk — "1" = flagged
GOPLUS_RISK_FIELDS = {
    "malicious_address":               "Malicious Address",
    "phishing_activities":             "Phishing",
    "honeypot_related_address":        "Honeypot Related",
    "blacklist_doubt":                 "Blacklist",
    "cybercrime":                      "Cybercrime",
    "money_laundering":                "Money Laundering",
    "financial_crime":                 "Financial Crime",
    "darkweb_transactions":            "Dark Web Transactions",
    "mixer":                           "Mixer",
    "sanctioned":                      "Sanctioned",
    "stealing_attack":                 "Stealing Attack",
    "fake_kyc":                        "Fake KYC",
    "malicious_mining_activities":     "Malicious Mining",
}


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_goplus_address(address: str, chain: str = "ethereum") -> Dict:
    """
    Check a single address against GoPlus Security (free, no key).
    Returns dict of risk flags and a combined risk score.
    """
    chain_id = GOPLUS_CHAIN_IDS.get(chain.lower(), "1")
    result = {
        "address":     address,
        "chain":       chain,
        "goplus_hit":  False,
        "risk_flags":  [],
        "risk_labels": "",
        "risk_score":  0,
        "source":      "GoPlus Security",
    }
    try:
        resp = requests.get(
            f"{GOPLUS_API}/{address}",
            params={"chain_id": chain_id},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("code") == 1:
                r = data.get("result", {})
                flags = []
                for field, label in GOPLUS_RISK_FIELDS.items():
                    if str(r.get(field, "0")) == "1":
                        flags.append(label)
                result["risk_flags"]  = flags
                result["risk_labels"] = ", ".join(flags)
                result["goplus_hit"]  = bool(flags)
                result["risk_score"]  = min(100, len(flags) * 20)
    except Exception as e:
        logger.debug(f"GoPlus check failed for {address}: {e}")
    return result


@st.cache_data(ttl=3600, show_spinner=False)
def bulk_screen_goplus(df: pd.DataFrame, chain: str = "ethereum") -> pd.DataFrame:
    """
    Screen all unique addresses in dataset via GoPlus Security.
    GoPlus accepts comma-separated addresses — batches of 50 per call.
    Returns DataFrame: address | goplus_hit | risk_labels | risk_score
    """
    chain_id = GOPLUS_CHAIN_IDS.get(chain.lower(), "1")
    all_addrs = list(set(
        df["from_address"].astype(str).tolist() +
        df["to_address"].astype(str).tolist()
    ))
    # Filter to valid-looking addresses only
    all_addrs = [a for a in all_addrs if a and a != "nan" and len(a) > 10]

    rows = []
    BATCH = 50
    for i in range(0, len(all_addrs), BATCH):
        batch = all_addrs[i:i + BATCH]
        addr_str = ",".join(batch)
        try:
            resp = requests.get(
                f"{GOPLUS_API}/{addr_str}",
                params={"chain_id": chain_id},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("code") == 1:
                    result_map = data.get("result", {})
                    for addr in batch:
                        r     = result_map.get(addr.lower(), {})
                        flags = [label for field, label in GOPLUS_RISK_FIELDS.items()
                                 if str(r.get(field, "0")) == "1"]
                        rows.append({
                            "address":      addr,
                            "goplus_hit":   bool(flags),
                            "risk_labels":  ", ".join(flags),
                            "risk_score":   min(100, len(flags) * 20),
                            "source":       "GoPlus Security",
                        })
        except Exception as e:
            logger.warning(f"GoPlus batch failed ({i}–{i+BATCH}): {e}")
            for addr in batch:
                rows.append({"address": addr, "goplus_hit": False,
                             "risk_labels": "", "risk_score": 0, "source": "GoPlus Security"})
        time.sleep(0.2)   # Respect free-tier rate limit

    logger.info(f"✅ GoPlus: screened {len(rows)} addresses")
    return pd.DataFrame(rows) if rows else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 4c. USDC / USDT ON-CHAIN BLACKLISTS
#     Circle (USDC) and Tether (USDT) can freeze addresses
#     at the contract level. Frozen addresses cannot send
#     or receive stablecoins. These blacklists are authoritative
#     and public — fetchable via Etherscan event logs.
# ─────────────────────────────────────────────────────────────

USDC_CONTRACT  = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
USDT_CONTRACT  = "0xdac17f958d2ee523a2206206994597c13d831ec7"

# keccak256("Blacklisted(address)") — USDC contract event
USDC_BLACKLIST_TOPIC = "0xffa4e6181777692565cf28528fc88fd1516ea86b56da075a6462694dced20482"
# keccak256("AddedBlackList(address)") — USDT contract event
USDT_BLACKLIST_TOPIC = "0x42e160154868087d6bfdc0ca23d96a1c1cfa32f1b72ba9ba27b69b98a0d819d"
USDT_REMOVE_TOPIC    = "0xd7e9ec6e6ecd65492dce6bf513cd6867560d49544421d0783ddf06e76c24470c"

STABLECOIN_CACHE = Path("stablecoin_blacklist_cache.json")


@st.cache_data(ttl=43200, show_spinner=False)   # 12-hour cache
def fetch_stablecoin_blacklists(api_key: str = "") -> Dict[str, Set[str]]:
    """
    Fetch USDC and USDT on-chain blacklisted addresses via Etherscan getLogs.
    Returns: {"USDC": {addr, ...}, "USDT": {addr, ...}}
    These addresses are frozen at the contract level — cannot transact.
    """
    # Check disk cache
    if STABLECOIN_CACHE.exists():
        try:
            cached = json.loads(STABLECOIN_CACHE.read_text())
            if datetime.now().timestamp() - cached.get("ts", 0) < 43200:
                logger.info("✅ Stablecoin blacklists loaded from cache")
                return {k: set(v) for k, v in cached.get("lists", {}).items()}
        except Exception:
            pass

    lists: Dict[str, Set[str]] = {"USDC": set(), "USDT": set()}

    if not api_key:
        logger.warning("No Etherscan API key — stablecoin blacklist unavailable")
        return lists

    # Fetch USDC blacklist events
    try:
        resp = requests.get(
            "https://api.etherscan.io/v2/api",
            params={
                "chainid":   1,
                "module":    "logs",
                "action":    "getLogs",
                "address":   USDC_CONTRACT,
                "topic0":    USDC_BLACKLIST_TOPIC,
                "fromBlock": "0",
                "toBlock":   "latest",
                "offset":    1000,
                "apikey":    api_key,
            },
            timeout=20,
        ).json()
        if resp.get("status") == "1":
            for log in resp.get("result", []):
                # Address is in topic1, padded to 32 bytes
                raw = log.get("topics", ["", ""])
                if len(raw) > 1:
                    addr = "0x" + raw[1][-40:]
                    lists["USDC"].add(addr.lower())
        logger.info(f"✅ USDC blacklist: {len(lists['USDC'])} addresses")
    except Exception as e:
        logger.warning(f"USDC blacklist fetch failed: {e}")

    # Fetch USDT blacklist events (AddedBlackList minus RemovedBlackList)
    usdt_added   = set()
    usdt_removed = set()
    for topic, target in [(USDT_BLACKLIST_TOPIC, usdt_added),
                          (USDT_REMOVE_TOPIC,    usdt_removed)]:
        try:
            resp = requests.get(
                "https://api.etherscan.io/v2/api",
                params={
                    "chainid":   1,
                    "module":    "logs",
                    "action":    "getLogs",
                    "address":   USDT_CONTRACT,
                    "topic0":    topic,
                    "fromBlock": "0",
                    "toBlock":   "latest",
                    "offset":    1000,
                    "apikey":    api_key,
                },
                timeout=20,
            ).json()
            if resp.get("status") == "1":
                for log in resp.get("result", []):
                    raw = log.get("topics", ["", ""])
                    if len(raw) > 1:
                        addr = "0x" + raw[1][-40:]
                        target.add(addr.lower())
        except Exception as e:
            logger.warning(f"USDT blacklist event fetch failed: {e}")

    lists["USDT"] = usdt_added - usdt_removed
    logger.info(f"✅ USDT blacklist: {len(lists['USDT'])} addresses")

    # Persist cache
    try:
        STABLECOIN_CACHE.write_text(json.dumps({
            "ts":    datetime.now().timestamp(),
            "lists": {k: list(v) for k, v in lists.items()},
        }))
    except Exception:
        pass

    return lists


# ─────────────────────────────────────────────────────────────
# 4d. HOP PROTOCOL SANCTIONS LIST  (free, GitHub)
#     Hop Protocol publishes its OFAC-compliant sanctions list
#     on GitHub. Well-maintained, EVM addresses.
# ─────────────────────────────────────────────────────────────

HOP_CACHE = Path("hop_sanctions_cache.json")


@st.cache_data(ttl=7200, show_spinner=False)
def fetch_hop_sanctions_list() -> Set[str]:
    """
    Fetch Hop Protocol's public sanctions list from GitHub.
    EVM addresses blocked from using the Hop bridge due to
    OFAC SDN designation.
    """
    if HOP_CACHE.exists():
        try:
            cached = json.loads(HOP_CACHE.read_text())
            if datetime.now().timestamp() - cached.get("ts", 0) < 7200:
                return set(cached.get("addrs", []))
        except Exception:
            pass

    addrs: Set[str] = set()
    urls = [
        "https://raw.githubusercontent.com/hop-protocol/hop/develop/packages/frontend/src/config/sanctions.ts",
        "https://raw.githubusercontent.com/hop-protocol/hop/master/packages/frontend/src/config/sanctions.ts",
    ]
    for url in urls:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                for line in resp.text.split("\n"):
                    line = line.strip()
                    # Lines look like: '0xABCD...',
                    if line.startswith("'0x") or line.startswith('"0x'):
                        addr = line.strip("'\",").strip()
                        if len(addr) == 42:
                            addrs.add(addr.lower())
                if addrs:
                    break
        except Exception:
            pass

    # Also check Uniswap blocked addresses list
    try:
        resp = requests.get(
            "https://raw.githubusercontent.com/Uniswap/interface/main/src/constants/addresses.ts",
            timeout=10,
        )
        if resp.status_code == 200:
            for line in resp.text.split("\n"):
                line = line.strip()
                if "'0x" in line and len(line) < 60:
                    import re
                    found = re.findall(r"0x[a-fA-F0-9]{40}", line)
                    for addr in found:
                        addrs.add(addr.lower())
    except Exception:
        pass

    try:
        HOP_CACHE.write_text(json.dumps(
            {"ts": datetime.now().timestamp(), "addrs": list(addrs)}
        ))
    except Exception:
        pass

    logger.info(f"✅ Hop/Uniswap sanctions: {len(addrs)} addresses")
    return addrs


# ─────────────────────────────────────────────────────────────
# 4e. AGGREGATED INTEL SCREEN
#     Runs GoPlus + Stablecoin blacklists + Hop sanctions +
#     existing CryptoScamDB in one combined pass.
#     Adds columns to df for each source and a unified hit flag.
# ─────────────────────────────────────────────────────────────

def screen_all_intel_sources(
    df: pd.DataFrame,
    api_key: str = "",
    chain:   str = "ethereum",
) -> pd.DataFrame:
    """
    Run all intelligence sources and merge into a single enriched DataFrame.

    New columns added:
      goplus_hit          bool   — GoPlus Security flagged this address
      goplus_labels       str    — comma-separated GoPlus risk categories
      usdc_frozen         bool   — address is frozen by Circle (USDC)
      usdt_frozen         bool   — address is frozen by Tether (USDT)
      stablecoin_frozen   bool   — frozen by either stablecoin issuer
      hop_sanctions_hit   bool   — on Hop Protocol / Uniswap sanctions list
      community_bl_hit    bool   — on CryptoScamDB community blacklist
      intel_hit           bool   — flagged by ANY source
      intel_sources       str    — which sources flagged this address
    """
    df = df.copy()
    from_lower = df["from_address"].astype(str).str.lower()
    to_lower   = df["to_address"].astype(str).str.lower()

    # ── GoPlus ────────────────────────────────────────────────
    with st.spinner("🔍 GoPlus Security screening…"):
        gp_df = bulk_screen_goplus(df, chain)

    if not gp_df.empty and "goplus_hit" in gp_df.columns:
        gp_map_hit    = gp_df.set_index("address")["goplus_hit"].to_dict()
        gp_map_labels = gp_df.set_index("address")["risk_labels"].to_dict()
        df["goplus_hit"]    = (from_lower.map(gp_map_hit).fillna(False) |
                               to_lower.map(gp_map_hit).fillna(False))
        df["goplus_labels"] = (from_lower.map(gp_map_labels).fillna("") + " " +
                               to_lower.map(gp_map_labels).fillna("")).str.strip()
    else:
        df["goplus_hit"]    = False
        df["goplus_labels"] = ""

    # ── Stablecoin blacklists ─────────────────────────────────
    with st.spinner("🔒 Fetching USDC/USDT on-chain blacklists…"):
        sc_lists = fetch_stablecoin_blacklists(api_key)

    usdc_addrs = sc_lists.get("USDC", set())
    usdt_addrs = sc_lists.get("USDT", set())
    df["usdc_frozen"]       = from_lower.isin(usdc_addrs) | to_lower.isin(usdc_addrs)
    df["usdt_frozen"]       = from_lower.isin(usdt_addrs) | to_lower.isin(usdt_addrs)
    df["stablecoin_frozen"] = df["usdc_frozen"] | df["usdt_frozen"]

    # ── Hop / Uniswap sanctions ───────────────────────────────
    with st.spinner("🌉 Fetching Hop/Uniswap sanctions list…"):
        hop_addrs = fetch_hop_sanctions_list()

    df["hop_sanctions_hit"] = from_lower.isin(hop_addrs) | to_lower.isin(hop_addrs)

    # ── CryptoScamDB (existing) ───────────────────────────────
    with st.spinner("🌐 Fetching CryptoScamDB blacklist…"):
        bl_addrs = fetch_community_blacklist()

    df["community_bl_hit"] = from_lower.isin(bl_addrs) | to_lower.isin(bl_addrs)

    # ── Combined flag ─────────────────────────────────────────
    df["intel_hit"] = (df["goplus_hit"] | df["stablecoin_frozen"] |
                       df["hop_sanctions_hit"] | df["community_bl_hit"])

    def _sources(row):
        parts = []
        if row.get("goplus_hit"):        parts.append(f"GoPlus({row.get('goplus_labels','')})")
        if row.get("usdc_frozen"):       parts.append("USDC Frozen")
        if row.get("usdt_frozen"):       parts.append("USDT Frozen")
        if row.get("hop_sanctions_hit"): parts.append("Hop/Uniswap Sanctions")
        if row.get("community_bl_hit"):  parts.append("CryptoScamDB")
        return ", ".join(parts)

    df["intel_sources"] = df.apply(_sources, axis=1)

    total = int(df["intel_hit"].sum())
    logger.info(
        f"✅ Intel aggregate: {total} hits — "
        f"GoPlus:{int(df['goplus_hit'].sum())} / "
        f"USDC:{int(df['usdc_frozen'].sum())} / "
        f"USDT:{int(df['usdt_frozen'].sum())} / "
        f"Hop:{int(df['hop_sanctions_hit'].sum())} / "
        f"ScamDB:{int(df['community_bl_hit'].sum())}"
    )
    return df

def screen_darknet_intelligence(df: pd.DataFrame) -> pd.DataFrame:
    """Screen addresses against darknet intelligence sources."""
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
                st.dataframe(s, use_container_width=True,
    hide_index=True,
    column_config={
        col: st.column_config.TextColumn(
            col,
            width="medium"
        )
        for col in df.columns
    }
)
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
                st.dataframe(type_counts, use_container_width=True,
    hide_index=True,
    column_config={
        col: st.column_config.TextColumn(
            col,
            width="medium"
        )
        for col in df.columns
    }
)
            with c2:
                st.bar_chart(type_counts.set_index("Type")["Count"])

            st.markdown("**Full Classification Results**")
            show_cols = [c for c in ["address","type","label","confidence",
                                      "tx_count","out_volume","tokens_used"] if c in cdf.columns]
            st.dataframe(cdf[show_cols], use_container_width=True,
    hide_index=True,
    column_config={
        col: st.column_config.TextColumn(
            col,
            width="medium"
        )
        for col in df.columns
    }
)
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
                st.dataframe(exc_summary, use_container_width=True,
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

                show = [c for c in ["date","from_address","to_address","amount",
                                     "token","exchange_name","risk_level"] if c in edf.columns]
                st.dataframe(edf[show], use_container_width=True,
    hide_index=True,
    column_config={
        col: st.column_config.TextColumn(
            col,
            width="medium"
        )
        for col in df.columns
    }
)
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
        st.markdown("**Address Intelligence Screening — 5 Sources**")
        st.caption(
            "Screens all addresses against GoPlus Security (30M+ addresses), "
            "USDC/USDT on-chain freeze lists, Hop/Uniswap sanctions, "
            "CryptoScamDB, and darknet market databases."
        )

        # Source overview
        s1, s2, s3, s4, s5 = st.columns(5)
        s1.info("🔍 **GoPlus**\n30M+ addresses\nFree · No key")
        s2.info("💵 **USDC Frozen**\nCircle blacklist\nNeeds ETH key")
        s3.info("💵 **USDT Frozen**\nTether blacklist\nNeeds ETH key")
        s4.info("🌉 **Hop/Uniswap**\nSanctions list\nFree · GitHub")
        s5.info("🌐 **CryptoScamDB**\nCommunity list\nFree · GitHub")

        # Get API key for stablecoin blacklists
        _eth_key = ""
        try:
            from CryptoAnalyzerApp import get_key
            _eth_key = get_key("etherscan_key")
        except Exception:
            pass

        # ── Full aggregated screen ────────────────────────────
        st.markdown("---")
        if st.button("🔍 Run Full Intel Screen (All 5 Sources)", type="primary", key="run_intel_all"):
            intel_df = screen_all_intel_sources(df, api_key=_eth_key)
            st.session_state.intel_df = intel_df
            hits = int(intel_df["intel_hit"].sum())
            if hits > 0:
                st.error(f"🚨 {hits} addresses flagged across all sources")
                mi1,mi2,mi3,mi4,mi5 = st.columns(5)
                mi1.metric("GoPlus",          int(intel_df["goplus_hit"].sum()))
                mi2.metric("USDC Frozen",      int(intel_df["usdc_frozen"].sum()))
                mi3.metric("USDT Frozen",      int(intel_df["usdt_frozen"].sum()))
                mi4.metric("Hop/Uniswap",      int(intel_df["hop_sanctions_hit"].sum()))
                mi5.metric("CryptoScamDB",     int(intel_df["community_bl_hit"].sum()))
            else:
                st.success("✅ No flags across any source")

        if "intel_df" in st.session_state:
            idf  = st.session_state.intel_df
            hits = idf[idf["intel_hit"]] if "intel_hit" in idf.columns else pd.DataFrame()
            if not hits.empty:
                it1, it2 = st.tabs(["🔍 All Hits", "📊 Source Breakdown"])
                with it1:
                    show = [c for c in ["date","from_address","to_address","amount","token",
                                        "intel_sources","goplus_labels","risk_level"]
                            if c in hits.columns]
                    st.dataframe(hits[show], use_container_width=True,
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
                    st.download_button("⬇️ Export Intel Hits",
                        hits[show].to_csv(index=False).encode(),
                        "intel_hits.csv", "text/csv")
                with it2:
                    source_map = {
                        "GoPlus Security":      ("goplus_hit",        "goplus_labels"),
                        "USDC Frozen":          ("usdc_frozen",       None),
                        "USDT Frozen":          ("usdt_frozen",       None),
                        "Hop/Uniswap Sanctions":("hop_sanctions_hit", None),
                        "CryptoScamDB":         ("community_bl_hit",  None),
                    }
                    for src_name, (hit_col, label_col) in source_map.items():
                        if hit_col in hits.columns:
                            src_hits = hits[hits[hit_col]]
                            if not src_hits.empty:
                                st.markdown(f"**{src_name}** — {len(src_hits)} hits")
                                extra = [label_col] if label_col and label_col in src_hits.columns else []
                                scols = [c for c in ["from_address","to_address","amount","token"] + extra
                                         if c in src_hits.columns]
                                st.dataframe(src_hits[scols].head(20),
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
                                st.markdown("---")

        # ── Individual source buttons ─────────────────────────
        st.markdown("**Or run individual sources:**")
        icol1, icol2, icol3 = st.columns(3)

        with icol1:
            if st.button("🕵️ Darknet Patterns Only", key="run_dark"):
                with st.spinner("Screening darknet intelligence…"):
                    dark_df = screen_darknet_intelligence(df)
                    st.session_state.dark_df = dark_df
                    hits = int(dark_df["darknet_hit"].sum())
                st.success(f"Found {hits} hits") if hits else st.success("✅ No hits")

        with icol2:
            if st.button("🌐 CryptoScamDB Only", key="run_blacklist"):
                with st.spinner("Downloading CryptoScamDB…"):
                    bl = fetch_community_blacklist()
                    st.session_state.community_bl = bl
                st.success(f"✅ {len(bl)} addresses in blacklist")

        with icol3:
            if st.button("🔍 GoPlus Single Address", key="run_gp_single"):
                gp_addr = st.session_state.get("rep_addr","")
                if gp_addr:
                    with st.spinner(f"Checking {gp_addr[:20]}… via GoPlus…"):
                        gp_result = fetch_goplus_address(gp_addr)
                    if gp_result["goplus_hit"]:
                        st.error(f"🚨 GoPlus flags: {gp_result['risk_labels']}")
                    else:
                        st.success("✅ GoPlus: no flags")
                else:
                    st.info("Enter an address in the Reputation Score tab first.")

        if "dark_df" in st.session_state:
            ddf  = st.session_state.dark_df
            dhits = ddf[ddf["darknet_hit"]] if "darknet_hit" in ddf.columns else pd.DataFrame()
            if not dhits.empty:
                show = [c for c in ["date","from_address","to_address","amount",
                                     "token","darknet_entity","risk_level"] if c in dhits.columns]
                st.dataframe(dhits[show], use_container_width=True,
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
            st.dataframe(st.session_state.chg_df, use_container_width=True,
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