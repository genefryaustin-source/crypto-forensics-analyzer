"""
forensics_solana.py  —  Crypto Forensics Analyzer Pro v5.0
Solana blockchain support:
  • Transaction history via Solana JSON-RPC (no solana-py required)
  • SPL token transfer parsing
  • Jupiter aggregator swap analysis
  • Known Solana program fingerprinting
  • Solana address validation and risk scoring
"""

import requests
import pandas as pd
import numpy as np
import streamlit as st
import json
import time
import base64
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# SOLANA RPC ENDPOINTS  (public, no key required)
# ─────────────────────────────────────────────────────────────
SOLANA_RPC_ENDPOINTS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-mainnet.g.alchemy.com/v2/demo",
    "https://rpc.ankr.com/solana",
]

# SPL Token Program addresses
TOKEN_PROGRAM_ID      = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ASSOC_TOKEN_PROGRAM   = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bB"
SYSTEM_PROGRAM        = "11111111111111111111111111111111"

# Known Solana programs for fingerprinting
KNOWN_PROGRAMS = {
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4":  {"name":"Jupiter v6",          "category":"DEX_AGG",    "risk":"LOW"},
    "JUP4Fb2cqiRUcaTHdrPC8h2gNsA2ETXiPDD33WcGuJB":  {"name":"Jupiter v4",           "category":"DEX_AGG",    "risk":"LOW"},
    "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP": {"name":"Orca Whirlpool",       "category":"DEX",        "risk":"LOW"},
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc":  {"name":"Orca v2",              "category":"DEX",        "risk":"LOW"},
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8": {"name":"Raydium AMM",          "category":"DEX",        "risk":"LOW"},
    "27haf8L6oxUeXrHrgEgsexjSY5hbVUWEmvv9Nyxg8vQv": {"name":"Raydium CLMM",         "category":"DEX",        "risk":"LOW"},
    "MERLuDFBMmsHnsBPZw2sDQZHvXFMwp8EdjudcU2pgJh":  {"name":"Mercurial Finance",    "category":"DEX",        "risk":"LOW"},
    "TSWAPaqyCSx2KABk68Shruf4rp7CxcAi9UTjtKxiVV":   {"name":"Tensor NFT",           "category":"NFT_MARKET", "risk":"LOW"},
    "M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K":  {"name":"Magic Eden v2",        "category":"NFT_MARKET", "risk":"LOW"},
    "hausS13jsjafwWwGqZTUQRmWyvyxn9EQpqMwV1PBBmk":  {"name":"Hadeswap",             "category":"NFT_MARKET", "risk":"LOW"},
    "wormhole":                                       {"name":"Wormhole Bridge",      "category":"BRIDGE",     "risk":"MEDIUM"},
    "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth":  {"name":"Wormhole Token Bridge","category":"BRIDGE",     "risk":"MEDIUM"},
    "jtojtomepa8beriaJdf1sFnE1o7o5jG3tGfBZ3UL3s":   {"name":"Jito MEV",             "category":"MEV",        "risk":"MEDIUM"},
    "So11111111111111111111111111111111111111112":    {"name":"Wrapped SOL",          "category":"TOKEN",      "risk":"LOW"},
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": {"name":"USDC",                 "category":"STABLECOIN", "risk":"LOW"},
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB":  {"name":"USDT",                 "category":"STABLECOIN", "risk":"LOW"},
    "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So":  {"name":"mSOL (Marinade)",      "category":"STAKING",    "risk":"LOW"},
    "bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1":  {"name":"bSOL (BlazeStake)",    "category":"STAKING",    "risk":"LOW"},
}

# Known high-risk Solana addresses
SOLANA_HIGH_RISK = {
    "He3oBkqPFMbaBpuK5EL6yD9qTb7cUmDCyyuKVPGDVzFJ": "Known Solana Scammer",
    "AujeRTsZTrC5GrqRYwCDrX7QegAUXqxm4cRzF3mTm3fS": "Rug Pull Wallet",
}


# ─────────────────────────────────────────────────────────────
# SOLANA RPC HELPER
# ─────────────────────────────────────────────────────────────

def _solana_rpc(method: str, params: list, endpoint: str = None, timeout: int = 30) -> Any:
    """Make a Solana JSON-RPC call with automatic endpoint fallback."""
    endpoints = [endpoint] if endpoint else SOLANA_RPC_ENDPOINTS
    for ep in endpoints:
        try:
            resp = requests.post(ep, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data:
                    return data["result"]
                if "error" in data:
                    logger.warning(f"RPC error on {ep}: {data['error']}")
        except Exception as e:
            logger.warning(f"RPC failed on {ep}: {e}")
    return None


def validate_solana_address(address: str) -> bool:
    """Validate a Solana base58 address (32-44 chars, base58 chars only)."""
    BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return (32 <= len(address) <= 44 and
            all(c in BASE58_CHARS for c in address))


# ─────────────────────────────────────────────────────────────
# 1. FETCH SOLANA TRANSACTION HISTORY
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=300, show_spinner=False)
def get_solana_transactions(
    address: str,
    limit: int = 50,
    rpc_url: str = None,
) -> pd.DataFrame:
    """
    Fetch transaction history for a Solana address.
    Returns a DataFrame with parsed transfers.
    """
    if not validate_solana_address(address):
        logger.error(f"Invalid Solana address: {address}")
        return pd.DataFrame()

    # Get transaction signatures
    sigs_result = _solana_rpc(
        "getSignaturesForAddress",
        [address, {"limit": limit, "commitment": "finalized"}],
        endpoint=rpc_url,
    )
    if not sigs_result:
        return pd.DataFrame()

    rows = []
    for sig_info in sigs_result[:limit]:
        signature = sig_info["signature"]
        block_time = sig_info.get("blockTime")

        # Get full transaction
        tx_result = _solana_rpc(
            "getTransaction",
            [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
            endpoint=rpc_url,
        )
        if not tx_result:
            continue

        try:
            meta      = tx_result.get("meta", {})
            tx        = tx_result.get("transaction", {})
            message   = tx.get("message", {})
            accounts  = message.get("accountKeys", [])
            instructions = message.get("instructions", [])

            # Parse SOL transfers (native)
            pre_balances  = meta.get("preBalances", [])
            post_balances = meta.get("postBalances", [])
            for i, (pre, post) in enumerate(zip(pre_balances, post_balances)):
                diff = (post - pre) / 1e9  # lamports to SOL
                if abs(diff) > 0.000001 and i < len(accounts):
                    acc = accounts[i]
                    acc_key = acc["pubkey"] if isinstance(acc, dict) else str(acc)
                    if diff < 0 and acc_key != address:  # sender
                        rows.append({
                            "date":         datetime.fromtimestamp(block_time).strftime("%Y-%m-%d %H:%M") if block_time else "",
                            "from_address": acc_key,
                            "to_address":   address if diff > 0 else "",
                            "amount":       abs(diff),
                            "token":        "SOL",
                            "tx_hash":      signature,
                            "chain":        "solana",
                            "program":      SYSTEM_PROGRAM,
                        })

            # Parse SPL token transfers
            inner = meta.get("innerInstructions", [])
            post_token = meta.get("postTokenBalances", [])
            pre_token  = meta.get("preTokenBalances", [])

            for ix in instructions:
                if not isinstance(ix, dict):
                    continue
                program_id = ix.get("programId","")
                parsed     = ix.get("parsed", {})

                if isinstance(parsed, dict) and parsed.get("type") in (
                    "transfer","transferChecked","transferCheckedWithFee"
                ):
                    info = parsed.get("info", {})
                    rows.append({
                        "date":         datetime.fromtimestamp(block_time).strftime("%Y-%m-%d %H:%M") if block_time else "",
                        "from_address": info.get("source","") or info.get("multisigAuthority",""),
                        "to_address":   info.get("destination",""),
                        "amount":       float(info.get("amount", info.get("tokenAmount",{}).get("uiAmount", 0)) or 0),
                        "token":        info.get("mint","SPL")[:8] + "…",
                        "tx_hash":      signature,
                        "chain":        "solana",
                        "program":      program_id,
                        "program_name": KNOWN_PROGRAMS.get(program_id, {}).get("name","Unknown"),
                    })

        except Exception as e:
            logger.debug(f"TX parse error {signature}: {e}")
            continue

        time.sleep(0.05)  # Rate limit

    logger.info(f"✅ Solana: {len(rows)} transactions for {address}")
    return pd.DataFrame(rows) if rows else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 2. SOLANA ACCOUNT INFO
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=60, show_spinner=False)
def get_solana_account_info(address: str, rpc_url: str = None) -> Dict:
    """Fetch SOL balance and account type for a Solana address."""
    result = _solana_rpc(
        "getAccountInfo",
        [address, {"encoding": "jsonParsed", "commitment": "finalized"}],
        endpoint=rpc_url,
    )
    info = {"address": address, "sol_balance": 0, "account_type": "UNKNOWN",
            "executable": False, "owner": ""}

    if result and result.get("value"):
        val = result["value"]
        info["sol_balance"] = val.get("lamports", 0) / 1e9
        info["executable"]  = val.get("executable", False)
        info["owner"]       = val.get("owner","")
        info["account_type"] = (
            "PROGRAM" if info["executable"]
            else "TOKEN_ACCOUNT" if info["owner"] == TOKEN_PROGRAM_ID
            else "WALLET"
        )

    # Get SOL balance separately for reliability
    bal = _solana_rpc("getBalance", [address], endpoint=rpc_url)
    if bal is not None:
        info["sol_balance"] = bal / 1e9

    return info


# ─────────────────────────────────────────────────────────────
# 3. SPL TOKEN HOLDINGS
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=120, show_spinner=False)
def get_spl_token_holdings(address: str, rpc_url: str = None) -> pd.DataFrame:
    """Fetch all SPL token balances for a wallet address."""
    result = _solana_rpc(
        "getTokenAccountsByOwner",
        [address, {"programId": TOKEN_PROGRAM_ID},
         {"encoding": "jsonParsed"}],
        endpoint=rpc_url,
    )
    if not result:
        return pd.DataFrame()

    rows = []
    for acc in result.get("value", []):
        parsed = acc.get("account",{}).get("data",{}).get("parsed",{})
        info   = parsed.get("info",{})
        ta     = info.get("tokenAmount",{})
        mint   = info.get("mint","")
        bal    = float(ta.get("uiAmount") or 0)
        if bal > 0:
            rows.append({
                "token_account": acc.get("pubkey",""),
                "mint":          mint,
                "token_name":    KNOWN_PROGRAMS.get(mint,{}).get("name", mint[:8]+"…"),
                "balance":       bal,
                "decimals":      ta.get("decimals",0),
            })

    return pd.DataFrame(rows).sort_values("balance", ascending=False) if rows else pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# 4. PROGRAM FINGERPRINTING
# ─────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def fingerprint_solana_programs(df: pd.DataFrame) -> pd.DataFrame:
    """Add program labels and risk levels to Solana transactions."""
    if "program" not in df.columns:
        return df
    df = df.copy()

    def _label(prog):
        info = KNOWN_PROGRAMS.get(str(prog), {})
        return info.get("name", str(prog)[:12]+"…")

    def _risk(prog):
        info = KNOWN_PROGRAMS.get(str(prog), {})
        return info.get("risk", "LOW")

    def _category(prog):
        info = KNOWN_PROGRAMS.get(str(prog), {})
        return info.get("category", "UNKNOWN")

    df["program_name"]     = df["program"].apply(_label)
    df["program_risk"]     = df["program"].apply(_risk)
    df["program_category"] = df["program"].apply(_category)
    return df


# ─────────────────────────────────────────────────────────────
# 5. RISK SCORING (Solana-specific)
# ─────────────────────────────────────────────────────────────

def score_solana_address(address: str, df: pd.DataFrame) -> Dict:
    """Risk-score a Solana address using on-chain patterns."""
    score  = 0
    flags  = []

    if address in SOLANA_HIGH_RISK:
        score += 90
        flags.append(f"Known high-risk: {SOLANA_HIGH_RISK[address]}")

    addr_txs = df[(df["from_address"]==address)|(df["to_address"]==address)]

    if not addr_txs.empty:
        # High-risk program interactions
        if "program_risk" in addr_txs.columns:
            crit_progs = addr_txs[addr_txs["program_risk"]=="HIGH"]["program_name"].unique()
            if len(crit_progs):
                score += 35
                flags.append(f"High-risk programs: {', '.join(crit_progs)}")

        # Large volumes
        total_vol = addr_txs["amount"].sum()
        if total_vol > 100000:
            score += 20
            flags.append(f"High volume: {total_vol:,.0f}")

        # Many unique counterparties (mixer pattern)
        sent = addr_txs[addr_txs["from_address"]==address]["to_address"].nunique()
        if sent > 50:
            score += 25
            flags.append(f"High fan-out: {sent} unique recipients")

    level = "CRITICAL" if score>=85 else "HIGH" if score>=60 else "MEDIUM" if score>=35 else "LOW"
    return {"address":address, "risk_score":min(score,100), "risk_level":level, "flags":flags}


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_solana_ui():
    """Solana investigation UI."""
    st.markdown("### ◎ Solana Chain Analysis")
    st.caption(
        "Full Solana transaction tracing using the public JSON-RPC API — no API key required. "
        "Supports SOL transfers, SPL tokens, Jupiter swaps, and known program fingerprinting."
    )

    sol_tabs = st.tabs([
        "🔍 Address Lookup", "💰 Token Holdings",
        "📊 Program Analysis", "⚠️ Risk Score"
    ])

    with sol_tabs[0]:
        st.markdown("**Fetch Solana Transaction History**")
        col1, col2 = st.columns([3,1])
        sol_addr = col1.text_input("Solana address (base58)", key="sol_addr",
                                    placeholder="e.g. 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")
        sol_limit = col2.number_input("Max transactions", 10, 100, 50, key="sol_limit")
        custom_rpc = st.text_input("Custom RPC URL (optional, e.g. Alchemy/Helius)",
                                    key="sol_rpc", placeholder="https://your-rpc-endpoint.com")

        if st.button("◎ Fetch Transactions", type="primary", key="run_sol") and sol_addr.strip():
            if not validate_solana_address(sol_addr.strip()):
                st.error("Invalid Solana address format.")
            else:
                with st.spinner("Fetching from Solana RPC…"):
                    acct = get_solana_account_info(sol_addr.strip(), custom_rpc or None)
                    sol_df = get_solana_transactions(sol_addr.strip(), int(sol_limit), custom_rpc or None)

                # Account summary
                s1,s2,s3 = st.columns(3)
                s1.metric("SOL Balance",   f"◎ {acct['sol_balance']:,.4f}")
                s2.metric("Account Type",  acct["account_type"])
                s3.metric("Transactions",  len(sol_df))

                if not sol_df.empty:
                    sol_df = fingerprint_solana_programs(sol_df)
                    st.session_state.sol_df = sol_df

                    st.dataframe(sol_df.head(50), use_container_width=True,
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
                    st.download_button("⬇️ Export Solana Transactions",
                        sol_df.to_csv(index=False).encode(), "solana_txs.csv", "text/csv")

                    # Option to add to main dataset
                    if st.button("➕ Add to Investigation Dataset", key="add_sol"):
                        st.session_state.raw_df = pd.concat(
                            [st.session_state.get("raw_df", pd.DataFrame()), sol_df],
                            ignore_index=True
                        )
                        st.session_state.pop("processed_df", None)
                        st.success(f"✅ Added {len(sol_df)} Solana transactions to dataset")
                        st.rerun()
                else:
                    st.info("No transactions found.")

    with sol_tabs[1]:
        st.markdown("**SPL Token Portfolio**")
        th_addr = st.text_input("Wallet address", key="th_addr",
                                 placeholder="Solana wallet address")
        if st.button("💰 Fetch Token Holdings", type="primary", key="run_th") and th_addr.strip():
            with st.spinner("Fetching SPL token balances…"):
                holdings = get_spl_token_holdings(th_addr.strip())
            if not holdings.empty:
                st.metric("Tokens Held", len(holdings))
                st.dataframe(holdings, use_container_width=True,
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
                st.download_button("⬇️ Export Holdings",
                    holdings.to_csv(index=False).encode(), "sol_holdings.csv", "text/csv")
            else:
                st.info("No SPL token holdings found.")

    with sol_tabs[2]:
        st.markdown("**Program Interaction Analysis**")
        if "sol_df" in st.session_state:
            sdf = st.session_state.sol_df
            if "program_name" in sdf.columns:
                prog_summary = sdf.groupby(["program_name","program_category","program_risk"]).agg(
                    tx_count=("amount","size"),
                    total_volume=("amount","sum")
                ).reset_index().sort_values("total_volume", ascending=False)
                st.dataframe(prog_summary, use_container_width=True,
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

                high_risk = prog_summary[prog_summary["program_risk"].isin(["HIGH","CRITICAL"])]
                if not high_risk.empty:
                    st.warning(f"⚠️ {len(high_risk)} high-risk program interactions")
        else:
            st.info("Fetch transactions first in the Address Lookup tab.")

    with sol_tabs[3]:
        st.markdown("**Solana Address Risk Scoring**")
        rs_addr = st.text_input("Address to score", key="sol_rs",
                                 placeholder="Paste Solana address")
        if st.button("⚠️ Score Risk", type="primary", key="run_sol_rs") and rs_addr.strip():
            base_df = st.session_state.get("sol_df", pd.DataFrame())
            if base_df.empty:
                base_df = get_solana_transactions(rs_addr.strip(), 30)
                base_df = fingerprint_solana_programs(base_df)
            score = score_solana_address(rs_addr.strip(), base_df)

            risk_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(score["risk_level"],"⚪")
            st.markdown(f"## {risk_icon} {score['risk_level']} — {score['risk_score']}/100")
            for flag in score["flags"]:
                st.markdown(f"- {flag}")
            if not score["flags"]:
                st.success("✅ No risk indicators found")
