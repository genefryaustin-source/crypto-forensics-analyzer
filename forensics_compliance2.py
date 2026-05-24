"""
forensics_compliance2.py  —  Crypto Forensics Analyzer Pro v5.0
Regulatory compliance & advanced chain support:
  • FATF Travel Rule compliance (VASP-to-VASP data packages)
  • Layer 2 chain support (Arbitrum, Optimism, Base, zkSync)
  • Multi-signature wallet analysis
  • Privacy coin ingress/egress tracking
  • Regulatory case management dashboard
  • Chainalysis / TRM Labs API integration stubs
"""

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import requests
import json
import io
import hashlib
import logging
import base64
import mimetypes
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# 1. FATF TRAVEL RULE COMPLIANCE
#    FATF Recommendation 16 requires VASPs to share sender
#    and receiver identity information for transfers >$1,000.
#    Generates proper Travel Rule data packages (IVMS101 format).
# ─────────────────────────────────────────────────────────────

TRAVEL_RULE_THRESHOLD_USD = 1000   # $1,000 threshold (FATF standard)
TRAVEL_RULE_THRESHOLD_BTC = 0.023  # approximate BTC equivalent

IVMS101_TEMPLATE = {
    "originator": {
        "originatorPersons": [{
            "naturalPerson": {
                "name": [{"nameIdentifier": [{"primaryIdentifier": "", "secondaryIdentifier": ""}]}],
                "geographicAddress": [{"addressType": "HOME", "country": ""}],
                "nationalIdentification": {"nationalIdentifier": "", "nationalIdentifierType": "DRLC"},
                "dateAndPlaceOfBirth": {"dateOfBirth": "", "placeOfBirth": ""},
            }
        }],
        "accountNumber": [{"accountNumber": ""}],
    },
    "beneficiary": {
        "beneficiaryPersons": [{
            "naturalPerson": {
                "name": [{"nameIdentifier": [{"primaryIdentifier": "", "secondaryIdentifier": ""}]}],
            }
        }],
        "accountNumber": [{"accountNumber": ""}],
    },
    "originatingVASP": {
        "originatingVASP": {
            "legalPerson": {"name": [{"legalPersonNameIdentifier": [{"legalPersonName": "", "legalPersonNameIdentifierType": "LEGL"}]}]},
        }
    },
    "beneficiaryVASP": {
        "beneficiaryVASP": {
            "legalPerson": {"name": [{"legalPersonNameIdentifier": [{"legalPersonName": "", "legalPersonNameIdentifierType": "LEGL"}]}]},
        }
    },
    "transferPath": None,
    "paymentId": "",
}


@st.cache_data(show_spinner=False)
def identify_travel_rule_transactions(df: pd.DataFrame) -> pd.DataFrame:
    """
    Identify transactions that require Travel Rule compliance.
    Flags transfers above the $1,000 threshold between VASPs.
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

    # Use USD value if available, otherwise approximate
    if "usd_value" in df.columns:
        above_threshold = df["usd_value"] >= TRAVEL_RULE_THRESHOLD_USD
    else:
        # Conservative: flag all transactions above threshold
        above_threshold = df["amount"] >= TRAVEL_RULE_THRESHOLD_USD

    # Also flag known VASP-to-VASP transfers (from exchange to exchange)
    KNOWN_VASP_ADDRS = {
        "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be",  # Binance
        "0x71660c4005ba85c37ccec55d0c4493e66fe775d3",  # Coinbase
        "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0",  # Kraken
        "0x5041ed759dd4afc3a72b8192c143f72f4724081f",  # OKX
    }
    from_vasp = df["from_address"].str.lower().isin({v.lower() for v in KNOWN_VASP_ADDRS})
    to_vasp   = df["to_address"].str.lower().isin({v.lower() for v in KNOWN_VASP_ADDRS})

    df["travel_rule_required"]  = above_threshold
    df["vasp_to_vasp"]          = from_vasp & to_vasp
    df["travel_rule_compliant"] = False  # Unknown by default — requires VASP confirmation
    df["jurisdiction_note"]     = ""

    # Add jurisdiction notes for amounts above threshold
    for idx, row in df[df["travel_rule_required"]].iterrows():
        notes = []
        amt = row.get("usd_value", row["amount"])
        if amt >= 3000:
            notes.append("FinCEN CIP required ($3,000+)")
        if amt >= 10000:
            notes.append("CTR required ($10,000+)")
        df.at[idx, "jurisdiction_note"] = "; ".join(notes)

    return df


def generate_ivms101_package(
    tx_hash: str,
    originator_address: str,
    beneficiary_address: str,
    amount: float,
    token: str,
    originating_vasp: str,
    beneficiary_vasp: str,
    originator_name: str = "",
    beneficiary_name: str = "",
) -> Dict:
    """Generate an IVMS101-compliant Travel Rule data package."""
    package = json.loads(json.dumps(IVMS101_TEMPLATE))  # deep copy

    # Populate originator
    package["originator"]["originatorPersons"][0]["naturalPerson"]["name"][0][
        "nameIdentifier"][0]["primaryIdentifier"] = originator_name.split()[-1] if originator_name else "UNKNOWN"
    package["originator"]["originatorPersons"][0]["naturalPerson"]["name"][0][
        "nameIdentifier"][0]["secondaryIdentifier"] = " ".join(originator_name.split()[:-1]) if originator_name else ""
    package["originator"]["accountNumber"][0]["accountNumber"] = originator_address

    # Populate beneficiary
    package["beneficiary"]["beneficiaryPersons"][0]["naturalPerson"]["name"][0][
        "nameIdentifier"][0]["primaryIdentifier"] = beneficiary_name.split()[-1] if beneficiary_name else "UNKNOWN"
    package["beneficiary"]["accountNumber"][0]["accountNumber"] = beneficiary_address

    # Populate VASPs
    package["originatingVASP"]["originatingVASP"]["legalPerson"]["name"][0][
        "legalPersonNameIdentifier"][0]["legalPersonName"] = originating_vasp
    package["beneficiaryVASP"]["beneficiaryVASP"]["legalPerson"]["name"][0][
        "legalPersonNameIdentifier"][0]["legalPersonName"] = beneficiary_vasp

    package["paymentId"] = tx_hash

    return {
        "ivms101": package,
        "metadata": {
            "generated_at":  datetime.now().isoformat(),
            "tx_hash":       tx_hash,
            "amount":        amount,
            "asset":         token,
            "standard":      "IVMS101 v1.0",
            "fatf_rule":     "FATF Recommendation 16 — Travel Rule",
            "threshold_usd": TRAVEL_RULE_THRESHOLD_USD,
        }
    }


# ─────────────────────────────────────────────────────────────
# 2. LAYER 2 CHAIN SUPPORT
#    Arbitrum, Optimism, Base, zkSync Era, Polygon zkEVM
#    These chains use the same Etherscan v2 API format.
# ─────────────────────────────────────────────────────────────

L2_CHAINS = {
    "arbitrum":     {"chain_id": 42161, "native": "ETH", "name": "Arbitrum One",    "explorer": "arbiscan.io"},
    "optimism":     {"chain_id": 10,    "native": "ETH", "name": "Optimism",        "explorer": "optimistic.etherscan.io"},
    "base":         {"chain_id": 8453,  "native": "ETH", "name": "Base",            "explorer": "basescan.org"},
    "zksync":       {"chain_id": 324,   "native": "ETH", "name": "zkSync Era",      "explorer": "explorer.zksync.io"},
    "polygon_zkevm":{"chain_id": 1101,  "native": "ETH", "name": "Polygon zkEVM",   "explorer": "zkevm.polygonscan.com"},
    "linea":        {"chain_id": 59144, "native": "ETH", "name": "Linea",           "explorer": "lineascan.build"},
    "scroll":       {"chain_id": 534352,"native": "ETH", "name": "Scroll",          "explorer": "scrollscan.com"},
    "mantle":       {"chain_id": 5000,  "native": "MNT", "name": "Mantle",          "explorer": "mantlescan.info"},
}


def fetch_l2_transactions(
    address: str,
    chain: str,
    api_key: str,
    limit: int = 50,
) -> pd.DataFrame:
    """
    Fetch transactions from any L2 chain using Etherscan v2 unified API.
    One API key works for all EVM chains.
    """
    chain_info = L2_CHAINS.get(chain.lower(), {})
    chain_id   = chain_info.get("chain_id", 42161)
    native     = chain_info.get("native", "ETH")
    chain_name = chain_info.get("name", chain)

    rows = []
    for action in ["txlist", "tokentx"]:
        try:
            resp = requests.get(
                "https://api.etherscan.io/v2/api",
                params={
                    "chainid": chain_id,
                    "module":  "account",
                    "action":  action,
                    "address": address,
                    "sort":    "desc",
                    "offset":  limit,
                    "apikey":  api_key,
                },
                timeout=15,
            ).json()

            if resp.get("status") == "1":
                for tx in resp.get("result", [])[:limit]:
                    if action == "txlist":
                        val = int(tx.get("value","0")) / 1e18
                        tok = native
                    else:
                        dec = int(tx.get("tokenDecimal","18") or 18)
                        val = int(tx.get("value","0")) / (10**dec)
                        tok = tx.get("tokenSymbol","UNKNOWN")

                    if val > 0:
                        rows.append({
                            "date":         datetime.fromtimestamp(int(tx["timeStamp"])).strftime("%Y-%m-%d %H:%M"),
                            "from_address": tx["from"],
                            "to_address":   tx.get("to","") or tx.get("contractAddress",""),
                            "amount":       val,
                            "token":        tok,
                            "tx_hash":      tx["hash"],
                            "chain":        chain_name,
                            "chain_id":     chain_id,
                            "l2_chain":     chain,
                        })
        except Exception as e:
            logger.warning(f"L2 fetch failed for {chain}: {e}")

    return pd.DataFrame(rows) if rows else pd.DataFrame()


def trace_l2_bridge_activity(
    address: str,
    api_key: str,
) -> Dict:
    """
    Trace an address across all supported L2 chains to find bridge activity.
    Essential — funds often bridge to L2 to avoid trace.
    """
    results = {}
    for chain_name in L2_CHAINS:
        df = fetch_l2_transactions(address, chain_name, api_key, limit=20)
        if not df.empty:
            results[chain_name] = {
                "tx_count":   len(df),
                "total_volume": df["amount"].sum(),
                "native_token": L2_CHAINS[chain_name]["native"],
                "transactions": df,
            }
            logger.info(f"✅ {chain_name}: {len(df)} transactions found")

    return results


# ─────────────────────────────────────────────────────────────
# 3. MULTI-SIGNATURE WALLET ANALYSIS
#    Multi-sig wallets require M-of-N signers to authorize.
#    Identifying signers reveals hidden relationships and
#    organizational structure of the target.
# ─────────────────────────────────────────────────────────────

KNOWN_MULTISIG_CONTRACTS = {
    "gnosis_safe":         "0xa6b71e26c5e0845f74c812102ca7114b6a896ab2",
    "gnosis_safe_factory": "0x76e2cfc1f5fa8f6a5b3fc4c8f4788d0657516f43",
    "multisig_proxy":      "0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67",
}

GNOSIS_SAFE_API = "https://safe-transaction-mainnet.safe.global/api/v1"


@st.cache_data(ttl=300, show_spinner=False)
def analyze_gnosis_safe(safe_address: str, chain: str = "ethereum") -> Dict:
    """
    Analyze a Gnosis Safe multi-sig wallet.
    Returns: signers, threshold, pending transactions, history.
    """
    API_URLS = {
        "ethereum": "https://safe-transaction-mainnet.safe.global/api/v1",
        "bsc":      "https://safe-transaction-bsc.safe.global/api/v1",
        "polygon":  "https://safe-transaction-polygon.safe.global/api/v1",
        "arbitrum": "https://safe-transaction-arbitrum.safe.global/api/v1",
        "optimism": "https://safe-transaction-optimism.safe.global/api/v1",
    }
    base_url = API_URLS.get(chain, API_URLS["ethereum"])

    result = {
        "address":          safe_address,
        "is_multisig":      False,
        "owners":           [],
        "threshold":        0,
        "nonce":            0,
        "pending_tx_count": 0,
        "historical_tx_count": 0,
        "chain":            chain,
    }

    try:
        # Get Safe info
        info_resp = requests.get(
            f"{base_url}/safes/{safe_address}/",
            timeout=10,
        ).json()

        if "owners" in info_resp:
            result["is_multisig"]  = True
            result["owners"]       = info_resp["owners"]
            result["threshold"]    = info_resp["threshold"]
            result["nonce"]        = info_resp["nonce"]

        # Get pending transactions
        pending_resp = requests.get(
            f"{base_url}/safes/{safe_address}/multisig-transactions/",
            params={"executed": "false", "limit": 5},
            timeout=10,
        ).json()
        result["pending_tx_count"] = pending_resp.get("count", 0)
        result["pending_txs"]      = pending_resp.get("results", [])[:3]

        # Historical count
        hist_resp = requests.get(
            f"{base_url}/safes/{safe_address}/multisig-transactions/",
            params={"executed": "true", "limit": 1},
            timeout=10,
        ).json()
        result["historical_tx_count"] = hist_resp.get("count", 0)

    except Exception as e:
        result["error"] = str(e)

    return result


def detect_multisig_patterns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Identify addresses in the dataset that exhibit multi-sig patterns:
    - Transactions requiring multiple confirmations (same tx_hash, multiple signers)
    - Gnosis Safe factory interactions
    - CREATE2 deployment patterns
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
    findings = []

    # Check for known multi-sig contract interactions
    safe_factory = KNOWN_MULTISIG_CONTRACTS["gnosis_safe_factory"].lower()
    safe_txs = df[
        (df["to_address"].str.lower() == safe_factory) |
        (df["from_address"].str.lower() == safe_factory)
    ]

    for _, tx in safe_txs.iterrows():
        findings.append({
            "address":    tx["to_address"] if tx["from_address"].lower() == safe_factory else tx["from_address"],
            "pattern":    "GNOSIS_SAFE_DEPLOYMENT",
            "evidence":   "Interacted with Gnosis Safe factory — likely multi-sig creation",
            "tx_hash":    tx.get("tx_hash",""),
            "date":       str(tx.get("date","")),
            "severity":   20,
            "note":       "Multi-sig ≠ suspicious; flag for investigator awareness",
        })

    # Same tx_hash appearing multiple times = multi-sig confirmation pattern
    if "tx_hash" in df.columns:
        tx_counts = df["tx_hash"].value_counts()
        multisig_txs = tx_counts[tx_counts > 1]
        for tx_hash, count in multisig_txs.items():
            group = df[df["tx_hash"] == tx_hash]
            findings.append({
                "address":     group["from_address"].iloc[0],
                "pattern":     "MULTI_SIGNER_TX",
                "evidence":    f"Transaction {tx_hash[:16]}… appears {count}× — may indicate multi-sig confirmation",
                "tx_hash":     tx_hash,
                "signer_count": count,
                "date":        str(group["date"].iloc[0]),
                "severity":    30,
            })

    return pd.DataFrame(findings) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 4. PRIVACY COIN INGRESS/EGRESS TRACKING
#    Can't trace inside Monero (XMR) or Zcash (ZEC) shielded pools,
#    but CAN track when funds enter or exit from transparent chains.
# ─────────────────────────────────────────────────────────────

PRIVACY_COIN_INDICATORS = {
    "XMR":  "Monero — completely private, untraceble",
    "ZEC":  "Zcash — shielded transactions untraceable",
    "DASH": "Dash — PrivateSend mixing available",
    "BEAM": "Beam — Mimblewimble privacy protocol",
    "GRIN": "Grin — Mimblewimble privacy protocol",
    "OXEN": "Oxen — privacy-focused platform",
    "PIVX": "PIVX — zk-SNARK private transactions",
}

KNOWN_ATOMIC_SWAP_SERVICES = [
    "atomicswap", "atomicdex", "thorswap", "thorchain", "sideshift",
    "fixedfloat", "changenow", "godex", "swapzone", "simpleswap",
]


@st.cache_data(show_spinner=False)
def detect_privacy_coin_activity(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect interactions with privacy coins and atomic swap services.
    Entry/exit points from transparent chains to privacy coins are traceable.
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
    findings = []

    # Check for privacy coin tokens in dataset
    token_upper = df["token"].str.upper()
    for coin, description in PRIVACY_COIN_INDICATORS.items():
        coin_txs = df[token_upper == coin]
        if not coin_txs.empty:
            for _, tx in coin_txs.iterrows():
                findings.append({
                    "type":        "PRIVACY_COIN_TRANSFER",
                    "coin":        coin,
                    "description": description,
                    "from_address":tx["from_address"],
                    "to_address":  tx["to_address"],
                    "amount":      tx["amount"],
                    "date":        str(tx.get("date","")),
                    "tx_hash":     tx.get("tx_hash",""),
                    "severity":    75,
                    "note":        f"Funds entering {coin} become untraceable. This is the last visible transaction.",
                })

    # Check for atomic swap / cross-chain DEX interactions
    combined = (df["from_address"].astype(str) + " " + df["to_address"].astype(str)).str.lower()
    for service in KNOWN_ATOMIC_SWAP_SERVICES:
        mask = combined.str.contains(service, regex=False)
        for _, tx in df[mask].iterrows():
            findings.append({
                "type":        "ATOMIC_SWAP_SERVICE",
                "coin":        tx.get("token",""),
                "description": f"Interaction with {service} — chain-hop without exchange KYC",
                "from_address":tx["from_address"],
                "to_address":  tx["to_address"],
                "amount":      tx["amount"],
                "date":        str(tx.get("date","")),
                "tx_hash":     tx.get("tx_hash",""),
                "severity":    65,
                "note":        "Atomic swaps bypass exchange KYC/AML requirements",
            })

    logger.info(f"✅ Privacy coin activity: {len(findings)} findings")
    return pd.DataFrame(findings) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 5. PROFESSIONAL API INTEGRATION STUBS
#    Chainalysis, TRM Labs, and Elliptic provide 400M+
#    labeled addresses. When you have a key, these replace
#    manual heuristics with ground-truth entity labels.
# ─────────────────────────────────────────────────────────────

def check_chainalysis(address: str, api_key: str) -> Dict:
    """
    Chainalysis KYT (Know Your Transaction) API.
    Returns entity labels, risk scores, and exposure information.
    Requires Chainalysis API subscription.
    """
    if not api_key:
        return {"error": "No Chainalysis API key provided"}
    try:
        resp = requests.post(
            "https://api.chainalysis.com/api/kyt/v1/users/placeholder/transfers",
            headers={"Token": api_key, "Accept": "application/json",
                     "Content-Type": "application/json"},
            json={"network":"ethereum","asset":"ETH","transferReference":address,
                  "direction":"received"},
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}", "detail": resp.text[:200]}
    except Exception as e:
        return {"error": str(e)}


def check_trmlabs(address: str, chain: str, api_key: str) -> Dict:
    """
    TRM Labs Blockchain Intelligence API.
    Returns risk score, ownership categories, and counterparty exposure.
    Requires TRM Labs API subscription.
    """
    if not api_key:
        return {"error": "No TRM Labs API key provided"}
    try:
        resp = requests.post(
            "https://api.trmlabs.com/public/v2/screening/addresses",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json=[{"address": address, "chain": chain.upper()}],
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────
# 6. REGULATORY CASE DASHBOARD
#    Track multiple cases, SAR filing status, LE referrals,
#    and case disposition across your full investigation portfolio.
# ─────────────────────────────────────────────────────────────

CASES_FILE = Path("regulatory_cases.json")


def load_cases() -> List[Dict]:
    if CASES_FILE.exists():
        try:
            return json.loads(CASES_FILE.read_text())
        except Exception:
            pass
    return []


def save_cases(cases: List[Dict]):
    CASES_FILE.write_text(json.dumps(cases, indent=2, default=str))



# ─────────────────────────────────────────────────────────────
# 7. OFF-CHAIN PAYMENT EVIDENCE & FILE ATTACHMENTS
#    Documents fiat payment evidence (Zelle, PayPal, CashApp,
#    Venmo, wire transfers, money orders) and attaches
#    screenshots/documents directly to cases.
#    Files stored as base64 inside the case JSON so they
#    persist across sessions without a separate filesystem.
# ─────────────────────────────────────────────────────────────

OFFCHAIN_PLATFORMS = [
    "Zelle", "PayPal", "CashApp", "Venmo", "Apple Pay",
    "Google Pay", "Wire Transfer", "ACH Transfer",
    "Money Order", "Western Union", "MoneyGram",
    "Bank Deposit", "Check", "Other",
]

ALLOWED_EVIDENCE_TYPES = {
    "image/png":       "🖼 PNG Image",
    "image/jpeg":      "🖼 JPEG Image",
    "image/jpg":       "🖼 JPEG Image",
    "image/gif":       "🖼 GIF Image",
    "image/webp":      "🖼 WebP Image",
    "application/pdf": "📄 PDF Document",
    "text/plain":      "📝 Text File",
    "text/csv":        "📊 CSV File",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "📝 Word Document",
}

MAX_FILE_SIZE_MB = 10


def _encode_file(file_bytes: bytes) -> str:
    """Encode file bytes to base64 string for JSON storage."""
    return base64.b64encode(file_bytes).decode("utf-8")


def _decode_file(b64_str: str) -> bytes:
    """Decode base64 string back to file bytes."""
    return base64.b64decode(b64_str.encode("utf-8"))


def add_offchain_payment(
    cases:    List[Dict],
    case_idx: int,
    platform:       str,
    tx_id:          str,
    sender_name:    str,
    sender_account: str,
    receiver_name:  str,
    receiver_account: str,
    amount:         float,
    currency:       str,
    payment_date:   str,
    description:    str,
    linked_address: str,
    linked_tx_hash: str,
    notes:          str,
    screenshot_bytes: Optional[bytes] = None,
    screenshot_name:  str = "",
    screenshot_type:  str = "",
) -> List[Dict]:
    """Add an off-chain payment record to a case."""
    payment = {
        "id":               f"pay_{uuid.uuid4().hex[:12]}",
        "platform":         platform,
        "transaction_id":   tx_id,
        "sender_name":      sender_name,
        "sender_account":   sender_account,
        "receiver_name":    receiver_name,
        "receiver_account": receiver_account,
        "amount":           amount,
        "currency":         currency,
        "payment_date":     payment_date,
        "description":      description,
        "linked_crypto_address": linked_address,
        "linked_tx_hash":   linked_tx_hash,
        "notes":            notes,
        "screenshot":       _encode_file(screenshot_bytes) if screenshot_bytes else None,
        "screenshot_name":  screenshot_name,
        "screenshot_type":  screenshot_type,
        "added_at":         datetime.now().isoformat()[:19],
    }
    cases[case_idx].setdefault("offchain_payments", []).append(payment)
    return cases


def add_evidence_file(
    cases:     List[Dict],
    case_idx:  int,
    file_bytes: bytes,
    filename:   str,
    file_type:  str,
    description: str,
    linked_address: str = "",
) -> List[Dict]:
    """Attach a file to a case as base64-encoded evidence."""
    size_mb = len(file_bytes) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise ValueError(f"File too large ({size_mb:.1f} MB). Max {MAX_FILE_SIZE_MB} MB.")

    evidence = {
        "id":              f"ev_{uuid.uuid4().hex[:12]}",
        "filename":        filename,
        "file_type":       file_type,
        "size_bytes":      len(file_bytes),
        "data":            _encode_file(file_bytes),
        "description":     description,
        "linked_address":  linked_address,
        "added_at":        datetime.now().isoformat()[:19],
    }
    cases[case_idx].setdefault("evidence_files", []).append(evidence)
    return cases


def render_offchain_payments_ui(cases: List[Dict], case_idx: int) -> List[Dict]:
    """
    UI for adding and viewing off-chain payment evidence.
    Returns updated cases list.
    """
    case = cases[case_idx]
    payments = case.get("offchain_payments", [])

    # ── Existing payments ─────────────────────────────────────
    if payments:
        st.markdown(f"**{len(payments)} off-chain payment record(s):**")
        for pidx, pay in enumerate(payments):
            icon = {"Zelle":"💚","PayPal":"🔵","CashApp":"💲","Venmo":"🔷",
                    "Wire Transfer":"🏦","Apple Pay":"🍎","Google Pay":"🟡"}.get(pay["platform"],"💳")
            with st.expander(
                f"{icon} {pay['platform']} — ${pay['amount']:,.2f} {pay['currency']} "
                f"| {pay['payment_date']} | {pay.get('sender_name','?')} → {pay.get('receiver_name','?')}",
                expanded=False
            ):
                p1,p2,p3 = st.columns(3)
                p1.markdown(f"**Transaction ID:** `{pay.get('transaction_id','—')}`")
                p2.markdown(f"**Platform:** {pay['platform']}")
                p3.markdown(f"**Amount:** ${pay['amount']:,.2f} {pay['currency']}")

                p4,p5 = st.columns(2)
                p4.markdown(f"**Sender:** {pay.get('sender_name','—')} ({pay.get('sender_account','—')})")
                p5.markdown(f"**Receiver:** {pay.get('receiver_name','—')} ({pay.get('receiver_account','—')})")

                if pay.get("linked_crypto_address"):
                    st.markdown(f"**Linked address:** `{pay['linked_crypto_address']}`")
                if pay.get("linked_tx_hash"):
                    st.markdown(f"**Linked tx:** `{pay['linked_tx_hash']}`")
                if pay.get("description"):
                    st.markdown(f"**Description:** {pay['description']}")
                if pay.get("notes"):
                    st.caption(f"📝 {pay['notes']}")

                # Show screenshot if present
                if pay.get("screenshot"):
                    try:
                        img_bytes = _decode_file(pay["screenshot"])
                        st.image(img_bytes, caption=pay.get("screenshot_name","Screenshot"),
                                 width='stretch')
                    except Exception:
                        st.caption("⚠️ Screenshot could not be displayed")

                # Delete button
                if st.button(f"🗑 Delete payment #{pidx+1}", key=f"del_pay_{case_idx}_{pidx}"):
                    cases[case_idx]["offchain_payments"].pop(pidx)
                    save_cases(cases)
                    st.rerun()
    else:
        st.info("No off-chain payment records yet.")

    # ── Fraud Database Search ─────────────────────────────────
    # Uses the platform from the most recent payment, or lets
    # the user pick which platform to search
    existing_platforms = list({p["platform"] for p in payments}) if payments else []
    search_platform = OFFCHAIN_PLATFORMS[0]
    if existing_platforms:
        search_platform = existing_platforms[0]

    with st.expander("🔍 Search Fraud Databases for this Platform", expanded=False):
        sel_platform = st.selectbox(
            "Platform to search",
            OFFCHAIN_PLATFORMS,
            index=OFFCHAIN_PLATFORMS.index(search_platform) if search_platform in OFFCHAIN_PLATFORMS else 0,
            key=f"fraud_platform_sel_{case_idx}",
        )
        # Pass the most recent payment amount as a search hint
        hint_amount = payments[-1]["amount"] if payments else 0.0
        hint_term   = payments[-1].get("sender_name","") if payments else ""
        render_fraud_intelligence_panel(sel_platform, hint_amount, hint_term)

    st.markdown("---")
    st.markdown("**➕ Add Off-chain Payment Record**")

    with st.form(key=f"offchain_form_{case_idx}"):
        fa1, fa2, fa3 = st.columns(3)
        platform     = fa1.selectbox("Platform", OFFCHAIN_PLATFORMS, key=f"plat_{case_idx}")
        currency     = fa2.selectbox("Currency", ["USD","EUR","GBP","CAD","AUD","Other"], key=f"curr_{case_idx}")
        payment_date = fa3.date_input("Payment Date", key=f"pdate_{case_idx}")

        fb1, fb2 = st.columns(2)
        tx_id  = fb1.text_input("Transaction / Reference ID", key=f"txid_{case_idx}",
                                  placeholder="e.g. Zelle ref# or PayPal txn ID")
        amount = fb2.number_input("Amount", min_value=0.0, step=0.01, key=f"amt_{case_idx}")

        fc1, fc2 = st.columns(2)
        sender_name    = fc1.text_input("Sender Full Name",    key=f"sname_{case_idx}")
        receiver_name  = fc2.text_input("Receiver Full Name",  key=f"rname_{case_idx}")

        fd1, fd2 = st.columns(2)
        sender_account   = fd1.text_input("Sender Account / Phone / Email",   key=f"sacct_{case_idx}",
                                           placeholder="e.g. 555-123-4567 or email@example.com")
        receiver_account = fd2.text_input("Receiver Account / Phone / Email", key=f"racct_{case_idx}")

        fe1, fe2 = st.columns(2)
        linked_address = fe1.text_input("Linked Crypto Address (if known)", key=f"laddr_{case_idx}",
                                         placeholder="0x… or Bitcoin address")
        linked_tx_hash = fe2.text_input("Linked On-chain Tx Hash (if known)", key=f"ltx_{case_idx}")

        description = st.text_input("Payment Description / Memo", key=f"desc_{case_idx}",
                                     placeholder="e.g. 'For consulting services' — memo from payment app")
        notes       = st.text_area("Investigator Notes", key=f"inotes_{case_idx}", height=70,
                                    placeholder="e.g. Amount just under $10k — possible structuring. Sender linked to subject address.")

        screenshot_file = st.file_uploader(
            "📎 Attach Screenshot (PNG, JPG, PDF — max 10 MB)",
            type=["png","jpg","jpeg","pdf","gif","webp"],
            key=f"ss_{case_idx}",
        )

        submitted = st.form_submit_button("💾 Add Payment Record", type="primary")

    if submitted:
        ss_bytes = None
        ss_name  = ""
        ss_type  = ""
        if screenshot_file:
            ss_bytes = screenshot_file.read()
            ss_name  = screenshot_file.name
            ss_type  = screenshot_file.type or "image/png"

        cases = add_offchain_payment(
            cases, case_idx,
            platform=platform,
            tx_id=tx_id,
            sender_name=sender_name,
            sender_account=sender_account,
            receiver_name=receiver_name,
            receiver_account=receiver_account,
            amount=float(amount),
            currency=currency,
            payment_date=str(payment_date),
            description=description,
            linked_address=linked_address,
            linked_tx_hash=linked_tx_hash,
            notes=notes,
            screenshot_bytes=ss_bytes,
            screenshot_name=ss_name,
            screenshot_type=ss_type,
        )
        save_cases(cases)
        st.success(f"✅ {platform} payment record added")
        st.rerun()

    return cases


def render_evidence_gallery_ui(cases: List[Dict], case_idx: int) -> List[Dict]:
    """
    UI for uploading and viewing attached evidence files.
    Returns updated cases list.
    """
    case  = cases[case_idx]
    files = case.get("evidence_files", [])

    # ── Existing files ────────────────────────────────────────
    if files:
        st.markdown(f"**{len(files)} attached file(s):**")
        img_files = [f for f in files if f["file_type"].startswith("image/")]
        doc_files = [f for f in files if not f["file_type"].startswith("image/")]

        # Image gallery
        if img_files:
            st.markdown("**📸 Screenshots & Images**")
            cols = st.columns(min(3, len(img_files)))
            for idx, ev in enumerate(img_files):
                with cols[idx % 3]:
                    try:
                        img_bytes = _decode_file(ev["data"])
                        st.image(img_bytes, caption=ev.get("description") or ev["filename"],
                                 width='stretch')
                        st.caption(f"Added: {ev['added_at'][:10]}")
                        if ev.get("linked_address"):
                            st.caption(f"Linked: `{ev['linked_address'][:20]}…`")
                        # Download button
                        st.download_button(
                            "⬇️", img_bytes, ev["filename"],
                            key=f"dl_img_{case_idx}_{idx}"
                        )
                    except Exception:
                        st.caption(f"⚠️ {ev['filename']} — cannot display")

        # Document list
        if doc_files:
            st.markdown("**📄 Documents**")
            for idx, ev in enumerate(doc_files):
                doc_icon = {"application/pdf":"📄","text/csv":"📊","text/plain":"📝"}.get(
                    ev["file_type"],"📎")
                dcol1, dcol2, dcol3 = st.columns([3,2,1])
                dcol1.markdown(f"{doc_icon} **{ev['filename']}** — {ev.get('description','')}")
                dcol2.caption(f"{ev['size_bytes']/1024:.1f} KB | {ev['added_at'][:10]}")
                try:
                    doc_bytes = _decode_file(ev["data"])
                    dcol3.download_button("⬇️", doc_bytes, ev["filename"],
                                          key=f"dl_doc_{case_idx}_{idx}")
                except Exception:
                    dcol3.caption("error")

                if st.button(f"🗑 Remove {ev['filename']}", key=f"del_ev_{case_idx}_{idx}"):
                    cases[case_idx]["evidence_files"].pop(idx)
                    save_cases(cases)
                    st.rerun()
    else:
        st.info("No evidence files attached yet.")

    st.markdown("---")
    st.markdown("**➕ Attach Evidence File**")

    ev_file = st.file_uploader(
        "Upload screenshot, PDF, Word doc, or CSV (max 10 MB)",
        type=["png","jpg","jpeg","gif","webp","pdf","txt","csv","docx"],
        key=f"ev_upload_{case_idx}",
    )
    ev_desc    = st.text_input("Description", key=f"ev_desc_{case_idx}",
                                placeholder="e.g. Bank statement showing $9,500 withdrawal on Jan 15")
    ev_address = st.text_input("Linked Crypto Address (optional)", key=f"ev_addr_{case_idx}",
                                placeholder="0x… or Bitcoin address this evidence relates to")

    if st.button("📎 Attach File", type="primary", key=f"attach_{case_idx}") and ev_file:
        try:
            file_bytes = ev_file.read()
            cases = add_evidence_file(
                cases, case_idx,
                file_bytes=file_bytes,
                filename=ev_file.name,
                file_type=ev_file.type or "application/octet-stream",
                description=ev_desc,
                linked_address=ev_address,
            )
            save_cases(cases)
            st.success(f"✅ {ev_file.name} attached to case")
            st.rerun()
        except ValueError as e:
            st.error(str(e))

    return cases



# ─────────────────────────────────────────────────────────────
# 8. PAYMENT PLATFORM FRAUD INTELLIGENCE
#    Searches public fraud databases for complaints related
#    to specific payment platforms and accounts.
#    Sources:
#      • CFPB Complaint Database (free REST API, no key)
#      • BBB Scam Tracker (free, public)
#      • Quick-link index to FBI IC3, FTC, Action Fraud
# ─────────────────────────────────────────────────────────────

# Maps each platform to its CFPB company name and search terms
PLATFORM_CFPB_MAP = {
    "Zelle":           {"company": "Early Warning Services, LLC", "term": "Zelle"},
    "PayPal":          {"company": "PayPal",                       "term": "PayPal"},
    "CashApp":         {"company": "Square",                       "term": "Cash App"},
    "Venmo":           {"company": "PayPal",                       "term": "Venmo"},
    "Apple Pay":       {"company": "Apple",                        "term": "Apple Pay"},
    "Google Pay":      {"company": "Google",                       "term": "Google Pay"},
    "Wire Transfer":   {"company": "",                             "term": "wire transfer fraud"},
    "ACH Transfer":    {"company": "",                             "term": "ACH fraud"},
    "Western Union":   {"company": "Western Union",                "term": "Western Union"},
    "MoneyGram":       {"company": "MoneyGram",                    "term": "MoneyGram"},
    "Money Order":     {"company": "",                             "term": "money order fraud"},
    "Bank Deposit":    {"company": "",                             "term": "bank deposit fraud"},
}

# Quick reference links opened externally
PLATFORM_FRAUD_LINKS = {
    "Zelle":         [
        ("CFPB — Zelle Complaints",      "https://www.consumerfinance.gov/data-research/consumer-complaints/search/?search_term=zelle"),
        ("BBB Scam Tracker — Zelle",     "https://www.bbb.org/scamtracker?text=zelle"),
        ("FTC — Report Zelle Fraud",     "https://reportfraud.ftc.gov/"),
        ("FBI IC3 — File Complaint",     "https://www.ic3.gov/"),
    ],
    "PayPal":        [
        ("CFPB — PayPal Complaints",     "https://www.consumerfinance.gov/data-research/consumer-complaints/search/?company=paypal"),
        ("BBB Scam Tracker — PayPal",    "https://www.bbb.org/scamtracker?text=paypal"),
        ("FTC — Report PayPal Fraud",    "https://reportfraud.ftc.gov/"),
    ],
    "CashApp":       [
        ("CFPB — CashApp Complaints",    "https://www.consumerfinance.gov/data-research/consumer-complaints/search/?search_term=cash+app"),
        ("BBB Scam Tracker — CashApp",   "https://www.bbb.org/scamtracker?text=cash+app"),
        ("FTC — Report CashApp Fraud",   "https://reportfraud.ftc.gov/"),
    ],
    "Venmo":         [
        ("CFPB — Venmo Complaints",      "https://www.consumerfinance.gov/data-research/consumer-complaints/search/?search_term=venmo"),
        ("BBB Scam Tracker — Venmo",     "https://www.bbb.org/scamtracker?text=venmo"),
    ],
    "Wire Transfer": [
        ("CFPB — Wire Transfer",         "https://www.consumerfinance.gov/data-research/consumer-complaints/search/?search_term=wire+transfer+fraud"),
        ("FBI IC3 — Wire Fraud",         "https://www.ic3.gov/"),
        ("FinCEN — Report",              "https://www.fincen.gov/report-suspicious-activity"),
    ],
    "Western Union": [
        ("CFPB — Western Union",         "https://www.consumerfinance.gov/data-research/consumer-complaints/search/?company=western+union"),
        ("BBB Scam Tracker",             "https://www.bbb.org/scamtracker?text=western+union"),
        ("FTC — WU Fraud Refund",        "https://www.ftc.gov/western-union"),
    ],
    "MoneyGram":     [
        ("CFPB — MoneyGram",             "https://www.consumerfinance.gov/data-research/consumer-complaints/search/?company=moneygram"),
        ("FTC — MoneyGram Refund",       "https://www.ftc.gov/moneygram"),
    ],
}

CFPB_API = "https://api.consumerfinance.gov/data/complaints.json"


@st.cache_data(ttl=1800, show_spinner=False)
def search_cfpb_complaints(
    platform:    str,
    search_term: str = "",
    date_from:   str = "",
    page_size:   int = 20,
) -> Dict:
    """
    Search the CFPB Consumer Complaint Database for fraud complaints
    related to a payment platform. Free API — no key required.
    Returns dict with total count and list of complaint records.
    """
    mapping  = PLATFORM_CFPB_MAP.get(platform, {})
    company  = mapping.get("company", "")
    base_term = mapping.get("term", platform)
    query    = search_term.strip() or base_term

    params = {
        "search_term": query,
        "size":        page_size,
        "sort":        "created_date_desc",
        "no_aggs":     "true",
    }
    if company:
        params["company"] = company
    if date_from:
        params["date_received_min"] = date_from

    try:
        resp = requests.get(CFPB_API, params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            hits = data.get("hits", {})
            total = hits.get("total", 0)
            # Handle both int and dict total formats
            if isinstance(total, dict):
                total = total.get("value", 0)

            records = []
            for h in hits.get("hits", []):
                src = h.get("_source", {})
                records.append({
                    "complaint_id":      src.get("complaint_id", ""),
                    "date_received":     src.get("date_received", "")[:10],
                    "company":           src.get("company", ""),
                    "product":           src.get("product", ""),
                    "issue":             src.get("issue", ""),
                    "sub_issue":         src.get("sub_issue", ""),
                    "state":             src.get("state", ""),
                    "narrative":         (src.get("complaint_what_happened", "") or "")[:300],
                    "company_response":  src.get("company_response", ""),
                    "timely_response":   src.get("timely", ""),
                    "consumer_disputed": src.get("consumer_disputed", ""),
                })
            return {"total": total, "records": records, "source": "CFPB"}
    except Exception as e:
        logger.warning(f"CFPB search failed for {platform}: {e}")

    return {"total": 0, "records": [], "source": "CFPB", "error": str(e) if "e" in dir() else "Request failed"}


@st.cache_data(ttl=1800, show_spinner=False)
def search_bbb_scam_tracker(
    platform:  str,
    search_term: str = "",
    page_size: int = 20,
) -> Dict:
    """
    Search the BBB Scam Tracker for reports mentioning the platform.
    Free public API — no key required.
    """
    mapping   = PLATFORM_CFPB_MAP.get(platform, {})
    query     = search_term.strip() or mapping.get("term", platform)

    try:
        resp = requests.get(
            "https://www.bbb.org/scamtracker/api/lookupscams",
            params={"query": query, "page": 1},
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; ForensicsAnalyzer/5.0)",
                "Accept":     "application/json",
            },
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            records = []
            for item in (data.get("scams") or data.get("data") or [])[:page_size]:
                records.append({
                    "title":       item.get("title", item.get("scamType", "")),
                    "date":        str(item.get("reportedOn", item.get("date", "")))[:10],
                    "amount_lost": item.get("amountLost", item.get("amount", 0)),
                    "state":       item.get("state", ""),
                    "description": (item.get("description", item.get("body", "")) or "")[:300],
                    "scam_type":   item.get("scamType", item.get("type", "")),
                })
            total = data.get("total", data.get("count", len(records)))
            return {"total": total, "records": records, "source": "BBB Scam Tracker"}
    except Exception as e:
        logger.debug(f"BBB search failed for {platform}: {e}")

    return {"total": 0, "records": [], "source": "BBB Scam Tracker", "error": "BBB API unavailable"}


def render_fraud_intelligence_panel(platform: str, amount: float = 0.0, search_hint: str = ""):
    """
    Render the fraud database search panel for a given payment platform.
    Called within render_offchain_payments_ui.
    """
    st.markdown(f"### 🔍 Fraud Intelligence — {platform}")
    st.caption(
        "Search public fraud complaint databases to find reports matching "
        "this platform, account, or transaction pattern."
    )

    fi1, fi2, fi3 = st.columns(3)
    custom_term = fi1.text_input(
        "Search term (optional)",
        value=search_hint,
        key=f"fi_term_{platform}",
        placeholder=f"e.g. {platform} scam romance fraud",
    )
    date_from = fi2.text_input(
        "Complaints from date",
        key=f"fi_date_{platform}",
        placeholder="YYYY-MM-DD",
    )
    result_count = fi3.selectbox("Results", [10, 20, 50], index=1, key=f"fi_count_{platform}")

    run_col1, run_col2 = st.columns(2)

    # ── CFPB Search ───────────────────────────────────────────
    if run_col1.button(f"📋 Search CFPB Database", type="primary", key=f"cfpb_search_{platform}"):
        with st.spinner("Searching CFPB Complaint Database…"):
            cfpb = search_cfpb_complaints(platform, custom_term, date_from, int(result_count))
        st.session_state[f"cfpb_result_{platform}"] = cfpb

    if f"cfpb_result_{platform}" in st.session_state:
        cfpb = st.session_state[f"cfpb_result_{platform}"]
        total = cfpb.get("total", 0)
        records = cfpb.get("records", [])

        if cfpb.get("error") and not records:
            st.warning(f"CFPB search unavailable: {cfpb['error']}")
        elif records:
            st.success(f"✅ CFPB: {total:,} total complaints — showing {len(records)}")
            cfpb_df = pd.DataFrame(records)
            show_cols = [c for c in ["date_received","company","issue","sub_issue",
                                      "state","narrative","company_response"]
                         if c in cfpb_df.columns]
            st.dataframe(cfpb_df[show_cols], width='stretch', hide_index=True)
            st.download_button(
                "⬇️ Export CFPB Results",
                cfpb_df.to_csv(index=False).encode(),
                f"cfpb_{platform.lower()}_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv",
                key=f"dl_cfpb_{platform}",
            )

            # Narrative count note
            narratives = cfpb_df[cfpb_df["narrative"].str.len() > 10]
            if not narratives.empty:
                st.caption(
                    f"💡 {len(narratives)} complaints include consumer narratives — "
                    "read the 'narrative' column for detailed fraud descriptions."
                )
        else:
            st.info(f"No CFPB complaints found for {platform} with those search terms.")

    # ── BBB Search ────────────────────────────────────────────
    if run_col2.button(f"🛡 Search BBB Scam Tracker", type="primary", key=f"bbb_search_{platform}"):
        with st.spinner("Searching BBB Scam Tracker…"):
            bbb = search_bbb_scam_tracker(platform, custom_term, int(result_count))
        st.session_state[f"bbb_result_{platform}"] = bbb

    if f"bbb_result_{platform}" in st.session_state:
        bbb = st.session_state[f"bbb_result_{platform}"]
        total = bbb.get("total", 0)
        records = bbb.get("records", [])

        if bbb.get("error") and not records:
            st.warning(f"BBB Scam Tracker unavailable: {bbb['error']}")
        elif records:
            st.success(f"✅ BBB: {total:,} scam reports — showing {len(records)}")
            bbb_df = pd.DataFrame(records)
            show_cols = [c for c in ["date","scam_type","amount_lost","state","description"]
                         if c in bbb_df.columns]
            st.dataframe(bbb_df[show_cols], width='stretch', hide_index=True)
            st.download_button(
                "⬇️ Export BBB Results",
                bbb_df.to_csv(index=False).encode(),
                f"bbb_{platform.lower()}_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv",
                key=f"dl_bbb_{platform}",
            )
        else:
            st.info(f"No BBB reports found for {platform}.")

    # ── Quick reference links ─────────────────────────────────
    st.markdown("---")
    st.markdown("**🔗 Additional Fraud Databases (open in browser)**")
    links = PLATFORM_FRAUD_LINKS.get(platform, [
        ("CFPB Complaint Database", f"https://www.consumerfinance.gov/data-research/consumer-complaints/search/?search_term={platform.replace(' ','+')}"),
        ("BBB Scam Tracker",        f"https://www.bbb.org/scamtracker?text={platform.replace(' ','+')}"),
        ("FBI IC3",                  "https://www.ic3.gov/"),
        ("FTC Report Fraud",        "https://reportfraud.ftc.gov/"),
    ])
    link_cols = st.columns(min(4, len(links)))
    for idx, (label, url) in enumerate(links):
        link_cols[idx % 4].markdown(f"[{label}]({url})")

    # Amount-specific note
    if amount > 0:
        st.caption(
            f"💡 Search tip: Filter CFPB results by amount — complaints near "
            f"${amount:,.2f} may indicate the same fraud ring."
        )


def render_case_dashboard():
    """Full regulatory case management dashboard."""
    cases = load_cases()

    st.markdown("### 📊 Regulatory Case Dashboard")
    st.caption(
        "Track all active investigations: SAR filing status, law enforcement referrals, "
        "asset freeze orders, and case disposition across your portfolio."
    )

    # Summary metrics
    if cases:
        total       = len(cases)
        open_cases  = sum(1 for c in cases if c.get("status") == "OPEN")
        sar_filed   = sum(1 for c in cases if c.get("sar_filed"))
        le_referred = sum(1 for c in cases if c.get("le_referral"))
        frozen      = sum(1 for c in cases if c.get("assets_frozen"))

        m1,m2,m3,m4,m5 = st.columns(5)
        m1.metric("Total Cases",      total)
        m2.metric("Open",             open_cases)
        m3.metric("SARs Filed",       sar_filed)
        m4.metric("LE Referrals",     le_referred)
        m5.metric("Assets Frozen",    frozen)
    else:
        st.info("No cases yet. Create your first case below.")

    # Case creation
    with st.expander("➕ Create New Case", expanded=not bool(cases)):
        c1,c2 = st.columns(2)
        with c1:
            case_id     = st.text_input("Case ID",   value=f"CASE-{datetime.now().strftime('%Y%m%d-%H%M')}", key="new_case_id")
            case_name   = st.text_input("Case Name", key="new_case_name")
            case_type   = st.selectbox("Type", ["Money Laundering","Ransomware","Fraud/Scam",
                                                  "Sanctions Evasion","Market Manipulation",
                                                  "DarkNet Activity","Tax Evasion","Other"],
                                        key="new_case_type")
            priority    = st.selectbox("Priority", ["CRITICAL","HIGH","MEDIUM","LOW"], key="new_priority")
        with c2:
            analyst     = st.text_input("Lead Analyst", key="new_analyst")
            total_value = st.number_input("Estimated Value ($)", min_value=0.0, key="new_value")
            description = st.text_area("Description", height=80, key="new_desc")

        if st.button("➕ Create Case", type="primary", key="create_case"):
            new_case = {
                "case_id":       case_id,
                "name":          case_name,
                "type":          case_type,
                "priority":      priority,
                "analyst":       analyst,
                "total_value":   total_value,
                "description":   description,
                "status":        "OPEN",
                "created_at":    datetime.now().isoformat(),
                "updated_at":    datetime.now().isoformat(),
                "sar_filed":     False,
                "sar_date":      None,
                "le_referral":   False,
                "le_date":       None,
                "le_agency":     "",
                "assets_frozen": False,
                "freeze_amount": 0,
                "disposition":   "PENDING",
                "notes":         [],
                "offchain_payments": [],
                "evidence_files":    [],
            }
            cases.append(new_case)
            save_cases(cases)
            st.success(f"✅ Case {case_id} created")
            st.rerun()

    # Case list and management
    if cases:
        st.markdown("---")
        st.markdown("**Active Cases**")

        for i, case in enumerate(cases):
            priority_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(case.get("priority",""),"⚪")
            status_icon   = {"OPEN":"📂","CLOSED":"✅","ESCALATED":"⬆️","SUSPENDED":"⏸️"}.get(case.get("status",""),"❓")

            with st.expander(
                f"{priority_icon} {case['case_id']} — {case.get('name','Untitled')} {status_icon}",
                expanded=False
            ):
                # Case summary metrics
                ec1,ec2,ec3,ec4 = st.columns(4)
                ec1.metric("Type",            case.get("type",""))
                ec2.metric("Value",           f"${case.get('total_value',0):,.0f}")
                ec3.metric("Analyst",         case.get("analyst",""))
                ec4.metric("Off-chain Pymts", len(case.get("offchain_payments",[])))

                # Four tabs per case
                ctab1, ctab2, ctab3, ctab4 = st.tabs([
                    "📋 Status", "💳 Off-chain Payments",
                    "📎 Evidence Files", "📝 Notes"
                ])

                # ── Tab 1: Status ─────────────────────────────
                with ctab1:
                    upd1,upd2,upd3,upd4 = st.columns(4)
                    if upd1.checkbox("SAR Filed",     value=case.get("sar_filed",False),   key=f"sar_{i}"):
                        cases[i]["sar_filed"] = True
                        cases[i]["sar_date"]  = datetime.now().isoformat()[:10]
                    if upd2.checkbox("LE Referral",   value=case.get("le_referral",False), key=f"le_{i}"):
                        cases[i]["le_referral"] = True
                        cases[i]["le_date"]     = datetime.now().isoformat()[:10]
                    if upd3.checkbox("Assets Frozen", value=case.get("assets_frozen",False),key=f"frz_{i}"):
                        cases[i]["assets_frozen"] = True
                    new_status = upd4.selectbox(
                        "Status", ["OPEN","ESCALATED","SUSPENDED","CLOSED"],
                        index=["OPEN","ESCALATED","SUSPENDED","CLOSED"].index(
                            case.get("status","OPEN")), key=f"status_{i}"
                    )
                    cases[i]["status"] = new_status

                    if case.get("le_referral"):
                        cases[i]["le_agency"] = st.text_input(
                            "LE Agency", value=case.get("le_agency",""), key=f"agency_{i}",
                            placeholder="e.g. FBI Cyber Division, DOJ, USSS"
                        )

                    cases[i]["disposition"] = st.selectbox(
                        "Disposition",
                        ["PENDING","UNDER_INVESTIGATION","CHARGES_FILED","CONVICTED",
                         "ACQUITTED","NO_CHARGES","CIVIL_SETTLEMENT","DISMISSED"],
                        index=["PENDING","UNDER_INVESTIGATION","CHARGES_FILED","CONVICTED",
                               "ACQUITTED","NO_CHARGES","CIVIL_SETTLEMENT","DISMISSED"].index(
                            case.get("disposition","PENDING")
                        ) if case.get("disposition","PENDING") in
                            ["PENDING","UNDER_INVESTIGATION","CHARGES_FILED","CONVICTED",
                             "ACQUITTED","NO_CHARGES","CIVIL_SETTLEMENT","DISMISSED"] else 0,
                        key=f"disp_{i}"
                    )

                    if st.button("💾 Save Status", key=f"save_status_{i}", type="primary"):
                        cases[i]["updated_at"] = datetime.now().isoformat()
                        save_cases(cases)
                        st.success("Status saved ✅")
                        st.rerun()

                # ── Tab 2: Off-chain Payments ─────────────────
                with ctab2:
                    st.caption(
                        "Document Zelle, PayPal, CashApp, Venmo, wire transfers, and other "
                        "fiat payments linked to this investigation. Attach screenshots as evidence."
                    )
                    cases = render_offchain_payments_ui(cases, i)

                # ── Tab 3: Evidence Files ─────────────────────
                with ctab3:
                    st.caption(
                        "Attach screenshots, bank statements, PDFs, and any other documentary "
                        "evidence. Files are stored securely inside the case record."
                    )
                    cases = render_evidence_gallery_ui(cases, i)

                # ── Tab 4: Notes ──────────────────────────────
                with ctab4:
                    note_text = st.text_input("Add note", key=f"note_{i}",
                                               placeholder="Quick investigation note…")
                    if st.button("💾 Add Note", key=f"save_{i}"):
                        if note_text.strip():
                            cases[i].setdefault("notes",[]).append({
                                "timestamp": datetime.now().isoformat()[:19],
                                "text":      note_text,
                            })
                            cases[i]["updated_at"] = datetime.now().isoformat()
                            save_cases(cases)
                            st.success("Note added ✅")
                            st.rerun()

                    all_notes = case.get("notes", [])
                    if all_notes:
                        for note in reversed(all_notes[-20:]):
                            st.markdown(
                                f"<small style='color:#94a3b8'>{note['timestamp']}</small> "
                                f"— {note['text']}",
                                unsafe_allow_html=True
                            )
                    else:
                        st.info("No notes yet.")

        # Export all cases
        st.markdown("---")
        cases_df = pd.DataFrame([{k:v for k,v in c.items() if k != "notes"} for c in cases])
        st.download_button("⬇️ Export All Cases CSV",
            cases_df.to_csv(index=False).encode(), "regulatory_cases.csv", "text/csv")


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_compliance2_ui(df: pd.DataFrame, get_key_fn=None):
    """Advanced compliance and chain support UI."""
    api_key = get_key_fn("etherscan_key") if get_key_fn else ""

    comp2_tabs = st.tabs([
        "✈️ Travel Rule",       "🔵 Layer 2 Chains",
        "🔐 Multi-sig Analysis","🔒 Privacy Coins",
        "🔌 Pro API Integration","📊 Case Dashboard"
    ])

    with comp2_tabs[0]:
        st.markdown("### ✈️ FATF Travel Rule Compliance")
        st.caption(
            "FATF Recommendation 16 requires VASPs to collect and transmit originator/beneficiary "
            "information for transfers ≥$1,000. Now mandatory in 60+ jurisdictions. "
            "Generates IVMS101-compliant data packages for VASP-to-VASP sharing."
        )
        if st.button("✈️ Identify Travel Rule Transactions", type="primary", key="run_tr"):
            with st.spinner("Analyzing transactions for Travel Rule requirements…"):
                tr_df = identify_travel_rule_transactions(df)
                st.session_state.tr_df = tr_df

        if "tr_df" in st.session_state:
            tdf = st.session_state.tr_df
            required = tdf[tdf["travel_rule_required"]]
            vasp2vasp = tdf[tdf.get("vasp_to_vasp", pd.Series(False, index=tdf.index))]
            t1,t2,t3 = st.columns(3)
            t1.metric("Travel Rule Required", len(required))
            t2.metric("VASP-to-VASP Txs",    len(vasp2vasp))
            t3.metric("CTR Threshold Hit",    len(required[required["amount"] >= 10000]))

            st.dataframe(required[["date","from_address","to_address","amount","token",
                                    "jurisdiction_note"]].head(50),
                         width='stretch', hide_index=True)

            # Generate IVMS101 package for selected transaction
            st.markdown("**Generate IVMS101 Package**")
            tx_hash_input  = st.text_input("Transaction hash", key="ivms_tx")
            orig_addr      = st.text_input("Originator address", key="ivms_orig_addr")
            bene_addr      = st.text_input("Beneficiary address", key="ivms_bene_addr")
            orig_vasp      = st.text_input("Originating VASP name", key="ivms_orig_vasp")
            bene_vasp      = st.text_input("Beneficiary VASP name", key="ivms_bene_vasp")
            orig_name      = st.text_input("Originator full name (for package)", key="ivms_orig_name")
            bene_name      = st.text_input("Beneficiary full name (if known)", key="ivms_bene_name")

            if st.button("📦 Generate IVMS101 Package", key="gen_ivms"):
                if all([orig_addr, bene_addr, orig_vasp, bene_vasp]):
                    package = generate_ivms101_package(
                        tx_hash=tx_hash_input or "UNKNOWN",
                        originator_address=orig_addr,
                        beneficiary_address=bene_addr,
                        amount=100.0,
                        token="ETH",
                        originating_vasp=orig_vasp,
                        beneficiary_vasp=bene_vasp,
                        originator_name=orig_name,
                        beneficiary_name=bene_name,
                    )
                    pkg_json = json.dumps(package, indent=2)
                    st.download_button("⬇️ Download IVMS101 Package",
                        pkg_json.encode(), f"travel_rule_{tx_hash_input[:8]}.json", "application/json")
                    st.json(package)
                else:
                    st.warning("Fill in all required fields.")

    with comp2_tabs[1]:
        st.markdown("### 🔵 Layer 2 Chain Support")
        st.caption(
            "Over 70% of DeFi volume now flows through L2 chains. Funds often bridge to L2 "
            "to reduce fees and — sometimes — to evade surveillance tools that only cover Ethereum mainnet."
        )
        if not api_key:
            st.warning("⚠️ Etherscan v2 API key required (works for all L2 chains).")
        else:
            l2_addr = st.text_input("Address to trace across L2 chains",
                                     value=st.session_state.get("live_wallet",""),
                                     key="l2_addr")
            selected_l2s = st.multiselect(
                "Chains to check",
                options=list(L2_CHAINS.keys()),
                default=["arbitrum","optimism","base"],
                key="l2_chains_sel"
            )

            if st.button("🔵 Trace L2 Activity", type="primary", key="run_l2") and l2_addr.strip():
                results = {}
                prog = st.progress(0)
                for i, chain in enumerate(selected_l2s):
                    prog.progress((i+1)/len(selected_l2s), f"Checking {chain}…")
                    df_chain = fetch_l2_transactions(l2_addr.strip(), chain, api_key)
                    if not df_chain.empty:
                        results[chain] = df_chain
                prog.empty()
                st.session_state.l2_results = results

                if results:
                    st.success(f"✅ Activity found on {len(results)} L2 chain(s)")
                    for chain, chain_df in results.items():
                        with st.expander(f"**{L2_CHAINS[chain]['name']}** — {len(chain_df)} transactions"):
                            st.dataframe(chain_df.head(20), width='stretch', hide_index=True)
                            # Merge into main dataset option
                            if st.button(f"➕ Add {chain} txs to dataset", key=f"add_{chain}"):
                                st.session_state.raw_df = pd.concat(
                                    [st.session_state.get("raw_df", pd.DataFrame()), chain_df],
                                    ignore_index=True
                                )
                                st.session_state.pop("processed_df", None)
                                st.success(f"Added {len(chain_df)} {chain} transactions")
                else:
                    st.info("No L2 activity found for this address.")

    with comp2_tabs[2]:
        st.markdown("### 🔐 Multi-Signature Wallet Analysis")
        st.caption(
            "Multi-sig wallets require multiple signers — identifying signers reveals "
            "hidden relationships, organizational structure, and shared control. "
            "Common in organized crime (requires all members to sign) and DAO treasuries."
        )

        ms1, ms2 = st.columns([2,1])
        safe_addr = ms1.text_input("Safe/Multi-sig address", key="safe_addr",
                                    placeholder="0x… Gnosis Safe address")
        safe_chain = ms2.selectbox("Chain", ["ethereum","bsc","polygon","arbitrum","optimism"],
                                    key="safe_chain")

        if st.button("🔐 Analyze Multi-sig", type="primary", key="run_safe") and safe_addr.strip():
            with st.spinner("Querying Gnosis Safe API…"):
                safe_info = analyze_gnosis_safe(safe_addr.strip(), safe_chain)
                st.session_state.safe_info = safe_info

        if "safe_info" in st.session_state:
            si = st.session_state.safe_info
            if si.get("is_multisig"):
                s1,s2,s3 = st.columns(3)
                s1.metric("Signers Required",  f"{si['threshold']} of {len(si['owners'])}")
                s2.metric("Total Signers",     len(si['owners']))
                s3.metric("Historical Txs",    si['historical_tx_count'])
                st.markdown("**Signer Addresses** — each is a potential investigative lead:")
                for j, owner in enumerate(si["owners"]):
                    st.code(f"Signer {j+1}: {owner}")
                if si.get("pending_tx_count", 0) > 0:
                    st.warning(f"⚠️ {si['pending_tx_count']} pending transactions awaiting signatures")
            elif "error" in si:
                st.info(f"Not a Gnosis Safe or API error: {si['error']}")
            else:
                st.info("Address is not a recognized Gnosis Safe multi-sig.")

        # Pattern detection in dataset
        st.markdown("**Detect Multi-sig Patterns in Dataset**")
        if st.button("🔍 Scan Dataset for Multi-sig Patterns", key="run_ms_scan"):
            ms_df = detect_multisig_patterns(df)
            if not ms_df.empty:
                st.dataframe(ms_df, width='stretch', hide_index=True)
            else:
                st.info("No multi-sig patterns detected in dataset.")

    with comp2_tabs[3]:
        st.markdown("### 🔒 Privacy Coin & Atomic Swap Tracking")
        st.caption(
            "The moment funds enter a privacy coin (Monero, Zcash shielded pool) they become "
            "permanently untraceable. Track ingress/egress points — these are the last and "
            "first visible transactions before/after the privacy layer."
        )
        if st.button("🔒 Detect Privacy Coin Activity", type="primary", key="run_priv"):
            with st.spinner("Scanning for privacy coin and atomic swap activity…"):
                priv_df = detect_privacy_coin_activity(df)
                st.session_state.priv_df = priv_df

        if "priv_df" in st.session_state:
            pdf = st.session_state.priv_df
            if not pdf.empty:
                pc = pdf[pdf["type"]=="PRIVACY_COIN_TRANSFER"]
                at = pdf[pdf["type"]=="ATOMIC_SWAP_SERVICE"]
                p1,p2 = st.columns(2)
                p1.metric("Privacy Coin Entries/Exits", len(pc))
                p2.metric("Atomic Swap Services",        len(at))
                st.dataframe(pdf, width='stretch', hide_index=True)

                if not pc.empty:
                    st.error(
                        "🔴 FUNDS ENTERING PRIVACY COIN — **trace ends here**. "
                        "Request assistance from specialized agencies (Europol EC3, "
                        "FBI Cyber, IRS-CI) that have XMR tracing capabilities."
                    )
                st.download_button("⬇️ Export Privacy Coin Report",
                    pdf.to_csv(index=False).encode(), "privacy_coins.csv", "text/csv")
            else:
                st.success("✅ No privacy coin or atomic swap activity detected.")

    with comp2_tabs[4]:
        st.markdown("### 🔌 Professional API Integration")
        st.caption(
            "Chainalysis KYT and TRM Labs provide 400M+ labeled addresses with ground-truth "
            "entity identification. These APIs replace manual heuristics with definitive labels."
        )

        api_service = st.radio("Service", ["Chainalysis KYT", "TRM Labs"], horizontal=True, key="pro_api_svc")
        pro_addr    = st.text_input("Address to screen", key="pro_addr")

        if api_service == "Chainalysis KYT":
            pro_key = st.text_input("Chainalysis API Key", type="password", key="ch_key")
            if st.button("🔍 Screen via Chainalysis", type="primary", key="run_ch") and pro_addr and pro_key:
                with st.spinner("Querying Chainalysis KYT…"):
                    result = check_chainalysis(pro_addr, pro_key)
                st.json(result)
        else:
            trm_key   = st.text_input("TRM Labs API Key", type="password", key="trm_key")
            trm_chain = st.selectbox("Chain", ["ethereum","bitcoin","tron","solana"], key="trm_chain")
            if st.button("🔍 Screen via TRM Labs", type="primary", key="run_trm") and pro_addr and trm_key:
                with st.spinner("Querying TRM Labs…"):
                    result = check_trmlabs(pro_addr, trm_chain, trm_key)
                st.json(result)

        st.markdown("---")
        st.markdown("**API Pricing Reference**")
        pricing_data = {
            "Service":     ["Chainalysis KYT", "TRM Labs", "Elliptic Navigator", "CipherTrace"],
            "Model":       ["Per transaction", "Per address", "Per address", "Enterprise"],
            "Cost":        ["~$0.10/tx", "~$0.01-0.05/addr", "Custom", "Custom"],
            "Coverage":    ["400M+ addresses", "300M+ addresses", "200M+ addresses", "150M+ addresses"],
            "Speciality":  ["DeFi + CEX", "Risk scoring", "Sanctions focus", "Crypto-fiat"],
        }
        st.dataframe(pd.DataFrame(pricing_data), width='stretch', hide_index=True)

    with comp2_tabs[5]:
        render_case_dashboard()
