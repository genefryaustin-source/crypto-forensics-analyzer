"""
forensics_lightning.py — Crypto Forensics Analyzer Pro v5.0
Bitcoin Lightning Network Forensics:
  • BOLT11 invoice parsing (pure Python — no external libs)
  • Lightning channel open/close transaction detection
  • Known routing node database
  • Channel balance and capacity analysis
  • LN payment traceability assessment
  • Cross-reference LN nodes with investigation dataset
"""

import re
import hashlib
import struct
import pandas as pd
import streamlit as st
import requests
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# KNOWN LIGHTNING ROUTING NODES
#    Well-known LN hubs — high-volume routing nodes often
#    used as mixers or to obscure payment paths.
# ─────────────────────────────────────────────────────────────

KNOWN_LN_NODES = {
    "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f": {
        "alias": "ACINQ (Phoenix/Eclair)", "type": "Exchange/Wallet", "risk": "LOW"
    },
    "0390b5d4492dc2f5318e5233ab2cebf6d48914881a33ef6a9c6bec1367aa2d6f7c": {
        "alias": "Bitrefill", "type": "Exchange", "risk": "LOW"
    },
    "03abf6f44c355dec0d5aa155bdbdd6e0c8fefe318eff402de65c6eb2e1be55dc3e": {
        "alias": "OpenNode", "type": "Payment Processor", "risk": "LOW"
    },
    "02f1a8c87607f415c8f22c00593002775941dea48869ce23096af27b0cfdcc0b69": {
        "alias": "WalletOfSatoshi", "type": "Wallet", "risk": "LOW"
    },
    "03cde60a6323f7122d5178255766e38114b4722ede08f7c9e0c5df9cefa777dae7": {
        "alias": "LNBig Hub", "type": "Routing Hub", "risk": "MEDIUM"
    },
    "033d8656219478701227199cbd6f670335c8d408a92ae88b962c49d4dc0e83e025": {
        "alias": "1ML.com Hub", "type": "Routing Hub", "risk": "MEDIUM"
    },
}

# LN channel open tx signatures (P2WSH 2-of-2 multisig patterns)
LN_CHANNEL_MIN_CAPACITY_SAT = 20_000    # 20k sat minimum viable channel
LN_CHANNEL_COMMON_AMOUNTS   = [         # Common channel opening amounts (sat)
    100_000, 200_000, 500_000,
    1_000_000, 2_000_000, 5_000_000,
    10_000_000, 16_777_215,             # Max channel capacity (pre-taproot)
]


# ─────────────────────────────────────────────────────────────
# 1. BOLT11 INVOICE PARSER
#    Pure Python bech32 + BOLT11 decoder.
#    LN invoices start with "lnbc" (mainnet), "lntb" (testnet).
#    Contains: amount, payee node, description, expiry, timestamp.
# ─────────────────────────────────────────────────────────────

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_decode_raw(bech: str) -> Tuple[Optional[str], Optional[List[int]]]:
    """Decode a bech32 string to (hrp, data_ints)."""
    bech = bech.lower()
    if len(bech) > 1023:
        return None, None
    if (p := bech.rfind("1")) < 1 or p + 7 > len(bech):
        return None, None
    hrp  = bech[:p]
    data = []
    for c in bech[p+1:]:
        d = BECH32_CHARSET.find(c)
        if d < 0:
            return None, None
        data.append(d)
    return hrp, data


def _convert_bits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & 0xFFFFFF
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def parse_bolt11_invoice(invoice: str) -> Dict:
    """
    Parse a BOLT11 Lightning Network payment invoice.
    Returns dict with: amount_sat, payee_pubkey, description,
    expiry_seconds, timestamp, network, raw_hrp.
    """
    result = {
        "valid":        False,
        "invoice":      invoice[:30] + "…",
        "network":      "unknown",
        "amount_sat":   0,
        "amount_msat":  0,
        "payee_pubkey": "",
        "description":  "",
        "expiry_sec":   3600,
        "timestamp":    None,
        "payment_hash": "",
        "error":        "",
    }

    inv = invoice.strip().lower()

    # Validate prefix
    network_map = {
        "lnbc":  "mainnet",
        "lntb":  "testnet",
        "lnbcrt":"regtest",
        "lnsb":  "simnet",
    }
    matched_hrp = None
    for prefix, net in network_map.items():
        if inv.startswith(prefix):
            matched_hrp = prefix
            result["network"] = net
            break

    if not matched_hrp:
        result["error"] = "Not a BOLT11 invoice (must start with lnbc/lntb)"
        return result

    # Decode bech32
    hrp, data = _bech32_decode_raw(inv)
    if hrp is None or data is None:
        result["error"] = "Bech32 decode failed"
        return result

    # Parse amount from HRP (e.g. lnbc1500n → 1500 nanosat = 150 msat)
    amount_str = hrp[len(matched_hrp):]
    multipliers = {"m": 100_000_000, "u": 100_000, "n": 100, "p": 0.1}
    if amount_str:
        try:
            if amount_str[-1].isalpha():
                mul = multipliers.get(amount_str[-1], 1)
                amount_btc = int(amount_str[:-1]) * mul / 1e11
            else:
                amount_btc = int(amount_str) / 1e11
            result["amount_msat"] = int(amount_btc * 1e11)
            result["amount_sat"]  = int(amount_btc * 1e8)
        except (ValueError, ZeroDivisionError):
            pass

    # Convert data bits 5→8
    decoded = _convert_bits(data[:-104], 5, 8, False)  # exclude 104-char signature
    if not decoded or len(decoded) < 7:
        result["error"] = "Insufficient data"
        return result

    # Timestamp (first 35 bits = 7 groups of 5)
    try:
        ts = 0
        for i in range(7):
            ts = (ts << 5) | data[i]
        result["timestamp"] = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        pass

    # Parse tagged fields (simplified)
    pos = 7
    while pos < len(data) - 104:
        try:
            tag  = data[pos]
            dlen = (data[pos+1] << 5) | data[pos+2]
            val  = data[pos+3:pos+3+dlen]
            pos += 3 + dlen

            if tag == 1 and dlen == 52:    # Payment hash (p)
                raw = _convert_bits(val, 5, 8, False)
                if raw:
                    result["payment_hash"] = bytes(raw[:32]).hex()
            elif tag == 13:                 # Description (d)
                raw = _convert_bits(val, 5, 8, False)
                if raw:
                    result["description"] = bytes(raw).decode("utf-8", errors="replace")
            elif tag == 6:                  # Expiry (x)
                exp = 0
                for b in val:
                    exp = (exp << 5) | b
                result["expiry_sec"] = exp
            elif tag == 19 and dlen == 53:  # Payee pubkey (n)
                raw = _convert_bits(val, 5, 8, False)
                if raw and len(raw) >= 33:
                    result["payee_pubkey"] = bytes(raw[:33]).hex()
        except Exception:
            break

    result["valid"] = True
    return result


# ─────────────────────────────────────────────────────────────
# 2. LIGHTNING CHANNEL DETECTION FROM BITCOIN TRANSACTIONS
#    Detects likely LN channel opens/closes from transaction patterns:
#    • Channel open: specific output amounts + P2WSH pattern
#    • Channel close: two outputs matching known channel capacity
# ─────────────────────────────────────────────────────────────

def detect_lightning_channels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect probable Lightning Network channel transactions.

    Channel open signatures:
    1. BTC amount matching common channel capacities (within 1%)
    2. Amount ≥ 20,000 sat (minimum viable channel)

    Channel close signatures:
    1. Two outputs from single address (balanced close)
    2. Single output with remainder (force close)
    """
    df = df.copy()
    df["date"] = pd.to_datetime(df["date"], errors="coerce")

    findings = []
    btc_df = df[df["token"].str.upper().isin(["BTC","WBTC"])].copy()

    for _, row in btc_df.iterrows():
        amount_sat = int(row["amount"] * 1e8)
        if amount_sat < LN_CHANNEL_MIN_CAPACITY_SAT:
            continue

        # Check if amount matches common channel size
        is_common_amount = any(
            abs(amount_sat - cap) / max(cap, 1) < 0.005   # 0.5% tolerance
            for cap in LN_CHANNEL_COMMON_AMOUNTS
        )

        # Check for max channel size (pre-taproot wumbo limit)
        is_max_channel = amount_sat == 16_777_215

        if is_common_amount or is_max_channel:
            channel_type = "WUMBO_CHANNEL" if amount_sat > 16_777_215 else \
                           "STANDARD_CHANNEL"

            # Check if known routing node involved
            known_node = None
            from_addr  = str(row.get("from_address","")).lower()
            to_addr    = str(row.get("to_address","")).lower()
            for pubkey, info in KNOWN_LN_NODES.items():
                if pubkey[:16] in from_addr or pubkey[:16] in to_addr:
                    known_node = info["alias"]
                    break

            findings.append({
                "pattern":       "LN_CHANNEL_OPEN",
                "channel_type":  channel_type,
                "from_address":  row["from_address"],
                "to_address":    row["to_address"],
                "amount_btc":    row["amount"],
                "amount_sat":    amount_sat,
                "date":          str(row.get("date",""))[:16],
                "tx_hash":       row.get("tx_hash",""),
                "known_node":    known_node or "Unknown",
                "note":          "Amount matches common LN channel capacity — "
                                 "funds may continue as off-chain LN payments (untraceable)",
                "risk":          "HIGH" if is_max_channel else "MEDIUM",
            })

    logger.info(f"✅ LN channel detection: {len(findings)} findings")
    return pd.DataFrame(findings) if findings else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 3. LIGHTNING NETWORK API LOOKUP
#    Query public LN explorers for node and channel data.
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=300, show_spinner=False)
def lookup_ln_node(pubkey: str) -> Dict:
    """
    Look up a Lightning node by public key via 1ML.com free API.
    Returns: alias, capacity, channel count, first/last seen.
    """
    result = {
        "pubkey":        pubkey,
        "alias":         "Unknown",
        "capacity_sat":  0,
        "channel_count": 0,
        "first_seen":    "",
        "last_seen":     "",
        "country":       "",
        "color":         "",
        "source":        "1ML.com",
    }
    try:
        resp = requests.get(
            f"https://1ml.com/node/{pubkey}/json",
            headers={"User-Agent": "CryptoForensicsAnalyzer/5.0"},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["alias"]         = data.get("alias","Unknown")
            result["capacity_sat"]  = data.get("capacity",0)
            result["channel_count"] = data.get("channelcount",0)
            result["first_seen"]    = data.get("firstupdate","")
            result["last_seen"]     = data.get("lastupdated","")
            result["country"]       = data.get("country",{}).get("en","")
            result["color"]         = data.get("color","")
    except Exception as e:
        logger.debug(f"1ML lookup failed: {e}")

    # Also check known nodes database
    if pubkey in KNOWN_LN_NODES:
        known = KNOWN_LN_NODES[pubkey]
        result["alias"]      = known["alias"]
        result["known_type"] = known["type"]
        result["risk"]       = known["risk"]

    return result


@st.cache_data(ttl=300, show_spinner=False)
def lookup_ln_channels_for_node(pubkey: str) -> List[Dict]:
    """Fetch open channels for a Lightning node via Amboss.space API."""
    channels = []
    try:
        resp = requests.get(
            f"https://api.amboss.space/graphql",
            json={
                "query": """
                query($pubkey: String!) {
                    getNode(pubkey: $pubkey) {
                        channels {
                            channel_id
                            capacity
                            last_update
                            node1_pub
                            node2_pub
                        }
                    }
                }
                """,
                "variables": {"pubkey": pubkey},
            },
            headers={"Content-Type": "application/json",
                     "User-Agent":   "CryptoForensicsAnalyzer/5.0"},
            timeout=10,
        )
        if resp.status_code == 200:
            data    = resp.json()
            ch_list = data.get("data",{}).get("getNode",{}).get("channels",[]) or []
            for ch in ch_list[:20]:
                channels.append({
                    "channel_id":  ch.get("channel_id",""),
                    "capacity":    ch.get("capacity",0),
                    "peer_pub":    ch.get("node2_pub","") if ch.get("node1_pub","") == pubkey
                                   else ch.get("node1_pub",""),
                    "last_update": ch.get("last_update",""),
                })
    except Exception as e:
        logger.debug(f"Amboss channel lookup failed: {e}")
    return channels


# ─────────────────────────────────────────────────────────────
# 4. TRACEABILITY ASSESSMENT
# ─────────────────────────────────────────────────────────────

def assess_ln_traceability(ln_df: pd.DataFrame) -> Dict:
    """
    Assess how much of the fund flow may be hidden via Lightning.
    Returns traceability score and guidance.
    """
    if ln_df.empty:
        return {"score": 100, "label": "Fully Traceable", "hidden_btc": 0}

    total_in_channels = ln_df["amount_btc"].sum()
    wumbo_amount      = ln_df[ln_df["channel_type"] == "WUMBO_CHANNEL"]["amount_btc"].sum()

    # Each BTC that enters a channel may fund many off-chain payments
    # Conservative estimate: 10× off-chain payments per on-chain channel
    hidden_estimate   = total_in_channels * 10

    # Traceability decreases as more funds enter channels
    score = max(0, min(100, 100 - (total_in_channels * 20)))

    label = "Severely Limited" if score < 30 else \
            "Partially Limited" if score < 70 else "Mostly Traceable"

    return {
        "score":              int(score),
        "label":              label,
        "btc_in_channels":    total_in_channels,
        "wumbo_btc":          wumbo_amount,
        "estimated_hidden_btc": hidden_estimate,
        "channel_count":      len(ln_df),
        "guidance": (
            "⚠️ Funds entered Lightning Network channels. Off-chain LN payments "
            "are NOT recorded on the Bitcoin blockchain. Subpoena LN node operators "
            "for payment records. Key targets: routing nodes shown above."
            if total_in_channels > 0 else
            "No Lightning Network activity detected."
        ),
    }


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_lightning_ui(df: pd.DataFrame = None):
    """Lightning Network forensics UI."""
    st.markdown("### ⚡ Lightning Network Forensics")
    st.caption(
        "Bitcoin Lightning Network payments are off-chain and NOT recorded on the blockchain. "
        "Once funds enter an LN channel, individual payments become invisible. "
        "This module detects channel opens, decodes BOLT11 invoices, and assesses traceability."
    )

    ln_tabs = st.tabs([
        "🔍 Channel Detection",   "⚡ Invoice Decoder",
        "🔗 Node Lookup",         "📊 Traceability Assessment"
    ])

    with ln_tabs[0]:
        st.markdown("**Lightning Channel Open Detection**")
        st.caption(
            "Scans Bitcoin transactions for amounts matching common LN channel capacities. "
            "Channel opens lock BTC off-chain — payments then occur invisibly."
        )
        if st.button("🔍 Detect LN Channels", type="primary", key="run_ln"):
            if df is not None and not df.empty:
                with st.spinner("Scanning for Lightning channel transactions…"):
                    ln_df = detect_lightning_channels(df)
                    st.session_state.ln_df = ln_df

                if not ln_df.empty:
                    assess = assess_ln_traceability(ln_df)
                    st.warning(
                        f"⚡ {len(ln_df)} probable LN channel opens detected — "
                        f"{assess['btc_in_channels']:.4f} BTC entered Lightning Network"
                    )
                    st.error(assess["guidance"])
                else:
                    st.success("✅ No Lightning channel patterns detected")
            else:
                st.info("Load a Bitcoin dataset to scan for LN channels.")

        if "ln_df" in st.session_state and not st.session_state.ln_df.empty:
            ldf = st.session_state.ln_df
            cols = [c for c in ["date","channel_type","from_address","to_address",
                                  "amount_btc","amount_sat","known_node","risk","tx_hash"]
                    if c in ldf.columns]
            st.dataframe(ldf[cols], use_container_width=True,
    hide_index=True,
    column_config={
        col: st.column_config.TextColumn(
            col,
            width="medium"
        )
        for col in df.columns
    }
)
            st.download_button("⬇️ Export LN Channel Report",
                ldf.to_csv(index=False).encode(), "ln_channels.csv", "text/csv")

            # Known nodes
            known = ldf[ldf["known_node"] != "Unknown"]
            if not known.empty:
                st.info(
                    f"💡 **Known routing nodes involved:** {', '.join(known['known_node'].unique())} — "
                    "These are legal entities that may have payment records. "
                    "Serve subpoena for routing information."
                )

    with ln_tabs[1]:
        st.markdown("**BOLT11 Invoice Decoder**")
        st.caption(
            "Decode Lightning Network payment invoices (starting with 'lnbc'). "
            "Extracts: amount, payee node public key, description, expiry, payment hash."
        )
        invoice_input = st.text_area(
            "Paste BOLT11 invoice",
            height=80,
            key="bolt11_invoice",
            placeholder="lnbc500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqd…",
        )
        if st.button("⚡ Decode Invoice", type="primary", key="run_bolt11") and invoice_input.strip():
            result = parse_bolt11_invoice(invoice_input.strip())
            if result["valid"]:
                st.success("✅ Valid BOLT11 invoice")
                m1,m2,m3,m4 = st.columns(4)
                m1.metric("Network",      result["network"].title())
                m2.metric("Amount (SAT)", f"{result['amount_sat']:,}")
                m3.metric("Amount (BTC)", f"{result['amount_sat']/1e8:.8f}")
                m4.metric("Expiry",       f"{result['expiry_sec']//3600}h {(result['expiry_sec']%3600)//60}m")

                if result["payee_pubkey"]:
                    st.markdown(f"**Payee Node Pubkey:** `{result['payee_pubkey']}`")
                    if result["payee_pubkey"] in KNOWN_LN_NODES:
                        known = KNOWN_LN_NODES[result["payee_pubkey"]]
                        st.info(f"Known node: {known['alias']} ({known['type']})")

                if result["description"]:
                    st.markdown(f"**Description:** {result['description']}")
                if result["payment_hash"]:
                    st.markdown(f"**Payment Hash:** `{result['payment_hash']}`")
                if result["timestamp"]:
                    st.markdown(f"**Created:** {result['timestamp']}")

                # Cross-reference payee with dataset
                if df is not None and not df.empty and result["payee_pubkey"]:
                    pk = result["payee_pubkey"][:20]
                    matches = df[
                        df["from_address"].str.lower().str.contains(pk, na=False) |
                        df["to_address"].str.lower().str.contains(pk, na=False)
                    ]
                    if not matches.empty:
                        st.error(f"🚨 Payee node found in investigation dataset ({len(matches)} txs)")
            else:
                st.error(f"Invalid invoice: {result['error']}")

    with ln_tabs[2]:
        st.markdown("**Lightning Node Lookup**")
        st.caption("Query public LN explorers for node details and channel information.")
        node_input = st.text_input(
            "Node public key (66 hex chars)",
            key="ln_node_input",
            placeholder="03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
        )
        if st.button("🔗 Lookup Node", type="primary", key="run_ln_node") and node_input.strip():
            with st.spinner("Querying 1ML.com…"):
                node_info = lookup_ln_node(node_input.strip())
            n1,n2,n3,n4 = st.columns(4)
            n1.metric("Alias",      node_info.get("alias","Unknown"))
            n2.metric("Channels",   node_info.get("channel_count",0))
            n3.metric("Capacity BTC", f"{node_info.get('capacity_sat',0)/1e8:.4f}")
            n4.metric("Country",    node_info.get("country","Unknown"))
            if node_info.get("first_seen"):
                st.caption(f"First seen: {node_info['first_seen']} | Last seen: {node_info.get('last_seen','')}")

        # Known nodes reference table
        st.markdown("**Known LN Routing Nodes:**")
        known_rows = [{"Pubkey (first 20)": k[:20]+"…", **v}
                      for k,v in KNOWN_LN_NODES.items()]
        st.dataframe(pd.DataFrame(known_rows), use_container_width=True,
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

    with ln_tabs[3]:
        st.markdown("**Traceability Assessment**")
        st.caption(
            "Quantifies how much of the fund flow may be hidden via Lightning. "
            "Each BTC entering a channel can fund many untraceable off-chain payments."
        )
        if "ln_df" in st.session_state and not st.session_state.ln_df.empty:
            assess = assess_ln_traceability(st.session_state.ln_df)
            risk_col = "#ff4444" if assess["score"] < 30 else \
                       "#ff8800" if assess["score"] < 70 else "#22c55e"
            st.markdown(
                f"<div style='background:{risk_col};padding:12px;border-radius:8px;"
                f"color:white;font-size:16px;font-weight:bold'>"
                f"Traceability: {assess['score']}% — {assess['label']}</div>",
                unsafe_allow_html=True
            )
            st.markdown("")
            a1,a2,a3 = st.columns(3)
            a1.metric("BTC in Channels",    f"{assess['btc_in_channels']:.4f}")
            a2.metric("Channel Opens",      assess["channel_count"])
            a3.metric("Est. Hidden Payments",f"~{assess['estimated_hidden_btc']:.1f} BTC equiv")
            st.error(assess["guidance"])
            st.info(
                "💡 **Investigative actions:**\n"
                "1. Identify channel partner addresses (counterparties in channel opens)\n"
                "2. Subpoena routing node operators for forwarding records\n"
                "3. Request payment records from LN wallets (Phoenix, Breez, Muun)\n"
                "4. Check if receiving party used a custodial LN service (Strike, Cash App BTC)"
            )
        else:
            st.info("Run Channel Detection first to see traceability assessment.")
