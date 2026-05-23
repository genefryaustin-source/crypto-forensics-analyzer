"""
forensics_ens.py  —  ENS Resolution & Address Reputation
Uses free public ENS APIs — no web3 package or RPC node required.
"""

import requests
import streamlit as st
import pandas as pd
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)

ENS_API      = "https://api.ensdata.net"
ENS_GRAPH    = "https://api.thegraph.com/subgraphs/name/ensdomains/ens"
LABELS_API   = "https://api.ethleaderboard.xyz/address"   # community label API


@st.cache_data(ttl=3600, show_spinner=False)
def resolve_address_to_ens(address: str) -> Optional[str]:
    """Reverse-resolve 0x address → ENS name via public API (no web3 needed)."""
    try:
        r = requests.get(f"{ENS_API}/{address.lower()}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            return data.get("ens") or data.get("name")
    except Exception:
        pass
    return None


@st.cache_data(ttl=3600, show_spinner=False)
def resolve_ens_to_address(ens_name: str) -> Optional[str]:
    """Forward-resolve ENS name → 0x address."""
    try:
        r = requests.get(f"{ENS_API}/{ens_name}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            return data.get("address")
    except Exception:
        pass
    return None


@st.cache_data(ttl=3600, show_spinner=False)
def get_ens_profile(ens_name_or_address: str) -> Dict:
    """Fetch ENS profile: avatar, Twitter, email, description."""
    profile = {}
    try:
        r = requests.get(f"{ENS_API}/{ens_name_or_address}", timeout=8)
        if r.status_code == 200:
            d = r.json()
            profile = {
                "ens":         d.get("ens"),
                "address":     d.get("address"),
                "avatar":      d.get("avatar"),
                "twitter":     d.get("twitter"),
                "github":      d.get("github"),
                "email":       d.get("email"),
                "description": d.get("description"),
                "url":         d.get("url"),
            }
    except Exception:
        pass
    return {k: v for k, v in profile.items() if v}


@st.cache_data(ttl=600, show_spinner=False)
def get_address_label(address: str) -> Optional[str]:
    """
    Look up community entity label for an address.
    Falls back to known label table for common entities.
    """
    KNOWN_LABELS = {
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045": "vitalik.eth",
        "0x28c6c06298d514db089934071355e5743bf21d60": "Binance Hot Wallet 14",
        "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance Hot Wallet 15",
        "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8": "Binance Cold Wallet",
        "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be": "Binance",
        "0xa910f92acdaf488fa6ef02174fb86208ad7722ba": "Kraken",
        "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0": "Kraken 2",
        "0x5041ed759dd4afc3a72b8192c143f72f4724081f": "OKX",
        "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b": "OKX 2",
        "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Coinbase",
        "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": "Coinbase 2",
        "0xa090e606e30bd747d4e6245a1517ebe430f0057e": "Coinbase 3",
        "0x7758e507850da48cd47df1fb5f875c23e3340c50": "Huobi",
        "0xaab2e55ff0e08e0c42aa0e13ef0f0ee48c8cd41f": "Huobi 2",
        "0x0d0707963952f2fba59dd06f2b425ace40b492fe": "Gate.io",
        "0xd793281182a0e3e023116004778f45c29fc14f19": "Tornado Cash",
    }
    normalized = address.lower()
    return KNOWN_LABELS.get(normalized)


def enrich_dataframe_with_ens(df: pd.DataFrame, max_lookups: int = 20) -> pd.DataFrame:
    """
    Add ENS labels to a transaction dataframe.
    Limits lookups to avoid rate limits — only enriches unique addresses.
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
    all_addrs = pd.concat([
        df["from_address"].drop_duplicates(),
        df["to_address"].drop_duplicates()
    ]).drop_duplicates().head(max_lookups)

    label_map = {}
    for addr in all_addrs:
        known = get_address_label(str(addr))
        if known:
            label_map[str(addr).lower()] = known
        else:
            ens = resolve_address_to_ens(str(addr))
            if ens:
                label_map[str(addr).lower()] = ens

    df["from_label"] = df["from_address"].str.lower().map(label_map).fillna("")
    df["to_label"]   = df["to_address"].str.lower().map(label_map).fillna("")
    return df


def render_ens_lookup():
    """Streamlit UI for ENS lookup panel."""
    st.markdown("### 🌐 ENS / Address Resolution")
    col1, col2 = st.columns(2)
    with col1:
        lookup_val = st.text_input("Address or ENS name", placeholder="0x… or vitalik.eth",
                                    key="ens_lookup_input")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        do_lookup = st.button("🔍 Resolve", key="ens_lookup_btn")

    if do_lookup and lookup_val.strip():
        val = lookup_val.strip()
        with st.spinner("Resolving…"):
            profile = get_ens_profile(val)
            if not profile:
                # Try direct label lookup for addresses
                if val.startswith("0x"):
                    label = get_address_label(val)
                    if label:
                        profile = {"address": val, "ens": label}

        if profile:
            p1, p2, p3 = st.columns(3)
            p1.metric("ENS Name",  profile.get("ens", "—"))
            p2.metric("Address",   (profile.get("address","")[:10]+"…") if profile.get("address") else "—")
            p3.metric("Twitter",   profile.get("twitter","—"))
            if profile.get("description"):
                st.caption(profile["description"])
        else:
            st.warning("No ENS record or label found for this address.")
