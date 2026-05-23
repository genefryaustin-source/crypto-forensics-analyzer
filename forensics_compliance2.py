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
                ec1,ec2,ec3 = st.columns(3)
                ec1.metric("Type",     case.get("type",""))
                ec2.metric("Value",    f"${case.get('total_value',0):,.0f}")
                ec3.metric("Analyst",  case.get("analyst",""))

                # Update controls
                upd1,upd2,upd3,upd4 = st.columns(4)
                if upd1.checkbox("SAR Filed",       value=case.get("sar_filed",False),       key=f"sar_{i}"):
                    cases[i]["sar_filed"] = True
                    cases[i]["sar_date"]  = datetime.now().isoformat()[:10]
                if upd2.checkbox("LE Referral",     value=case.get("le_referral",False),     key=f"le_{i}"):
                    cases[i]["le_referral"] = True
                    cases[i]["le_date"]     = datetime.now().isoformat()[:10]
                if upd3.checkbox("Assets Frozen",   value=case.get("assets_frozen",False),   key=f"frz_{i}"):
                    cases[i]["assets_frozen"] = True
                new_status = upd4.selectbox("Status", ["OPEN","ESCALATED","SUSPENDED","CLOSED"],
                                             index=["OPEN","ESCALATED","SUSPENDED","CLOSED"].index(
                                                 case.get("status","OPEN")), key=f"status_{i}")
                cases[i]["status"] = new_status

                # LE agency
                if case.get("le_referral"):
                    cases[i]["le_agency"] = st.text_input(
                        "LE Agency", value=case.get("le_agency",""), key=f"agency_{i}",
                        placeholder="e.g. FBI Cyber Division, DOJ, USSS"
                    )

                # Disposition
                cases[i]["disposition"] = st.selectbox(
                    "Disposition",
                    ["PENDING","UNDER_INVESTIGATION","CHARGES_FILED","CONVICTED",
                     "ACQUITTED","NO_CHARGES","CIVIL_SETTLEMENT","DISMISSED"],
                    index=0, key=f"disp_{i}"
                )

                # Quick note
                note_text = st.text_input("Add note", key=f"note_{i}",
                                           placeholder="Quick investigation note…")
                if st.button("💾 Save", key=f"save_{i}"):
                    if note_text.strip():
                        cases[i].setdefault("notes",[]).append({
                            "timestamp": datetime.now().isoformat()[:19],
                            "text": note_text,
                        })
                    cases[i]["updated_at"] = datetime.now().isoformat()
                    save_cases(cases)
                    st.success("Saved ✅")
                    st.rerun()

                # Show notes
                for note in case.get("notes",[])[-3:]:
                    st.caption(f"📝 {note['timestamp']} — {note['text']}")

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
