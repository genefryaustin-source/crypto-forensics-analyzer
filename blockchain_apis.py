"""
Blockchain API Integration Module
Supports Etherscan API v2 (2025+) unified across 60+ networks
Note: Polygon and all other chains now use Etherscan v2 unified API
"""

import requests
import pandas as pd
from datetime import datetime
import time
import streamlit as st
from typing import Dict, List, Optional, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# API ENDPOINTS - ETHERSCAN V2 UNIFIED API (2025+)
# ALL EVM chains now use https://api.etherscan.io/v2/api with chainId
# ─────────────────────────────────────────────────────────────
EXPLORER_APIS = {
    "ethereum": {
        "name": "Etherscan",
        "base_url": "https://api.etherscan.io/v2/api",
        "chainId": 1,
        "native_token": "ETH",
        "explorer_url": "https://etherscan.io",
        "api_key_param": "etherscan_key",
    },
    "bsc": {
        "name": "BscScan",
        "base_url": "https://api.etherscan.io/v2/api",  # UNIFIED - uses etherscan.io v2
        "chainId": 56,
        "native_token": "BNB",
        "explorer_url": "https://bscscan.com",
        "api_key_param": "etherscan_key",  # Uses same key as Etherscan!
    },
    "polygon": {
        "name": "PolygonScan",
        "base_url": "https://api.etherscan.io/v2/api",  # UNIFIED - uses etherscan.io v2
        "chainId": 137,
        "native_token": "MATIC",
        "explorer_url": "https://polygonscan.com",
        "api_key_param": "etherscan_key",  # Uses same key as Etherscan!
    },
    "avalanche": {
        "name": "Snowtrace",
        "base_url": "https://api.etherscan.io/v2/api",  # UNIFIED - uses etherscan.io v2
        "chainId": 43114,
        "native_token": "AVAX",
        "explorer_url": "https://snowtrace.io",
        "api_key_param": "etherscan_key",  # Uses same key as Etherscan!
    },
    "fantom": {
        "name": "FTMScan",
        "base_url": "https://api.etherscan.io/v2/api",  # UNIFIED - uses etherscan.io v2
        "chainId": 250,
        "native_token": "FTM",
        "explorer_url": "https://ftmscan.com",
        "api_key_param": "etherscan_key",  # Uses same key as Etherscan!
    },
    "arbitrum": {
        "name": "Arbiscan",
        "base_url": "https://api.etherscan.io/v2/api",  # UNIFIED - uses etherscan.io v2
        "chainId": 42161,
        "native_token": "ETH",
        "explorer_url": "https://arbiscan.io",
        "api_key_param": "etherscan_key",  # Uses same key as Etherscan!
    },
    "optimism": {
        "name": "Optimism",
        "base_url": "https://api.etherscan.io/v2/api",  # UNIFIED - uses etherscan.io v2
        "chainId": 10,
        "native_token": "ETH",
        "explorer_url": "https://optimistic.etherscan.io",
        "api_key_param": "etherscan_key",  # Uses same key as Etherscan!
    },
}

BITCOIN_APIS = {
    "blockchain": {
        "name": "Blockchain.com",
        "base_url": "https://blockchain.info",
        "supports": ["address", "tx"],
    },
    "mempool": {
        "name": "Mempool.space",
        "base_url": "https://mempool.space/api",
        "supports": ["address", "tx"],
    },
}


# ─────────────────────────────────────────────────────────────
# EVM CHAIN FUNCTIONS - ETHERSCAN V2 UNIFIED API
# ─────────────────────────────────────────────────────────────
def get_evm_transactions(address: str, chain: str, api_key: str, timeout: int = 30) -> pd.DataFrame:
    """
    Fetch transactions for an EVM address using Etherscan API v2 UNIFIED.
    2025+ All EVM chains (Ethereum, BSC, Polygon, Arbitrum, etc.) use the same unified endpoint.

    Supports: Ethereum, BSC, Polygon, Avalanche, Fantom, Arbitrum, Optimism
    """
    if chain not in EXPLORER_APIS:
        logger.error(f"Chain {chain} not supported")
        return pd.DataFrame()

    explorer = EXPLORER_APIS[chain]

    # Etherscan API v2 UNIFIED - all chains use same base URL with chainId
    params = {
        "module": "account",
        "action": "txlist",
        "address": address,
        "chainId": explorer["chainId"],
        "sort": "desc",
        "page": 1,
        "offset": 10000,
        "apikey": api_key,
    }

    try:
        logger.info(f"Fetching native transactions from {explorer['name']} (Chain {explorer['chainId']}) using Etherscan v2 API...")
        logger.info(f"API URL: {explorer['base_url']}")
        logger.info(f"Address: {address[:20]}...")

        response = requests.get(explorer["base_url"], params=params, timeout=timeout)

        logger.info(f"HTTP Status: {response.status_code}")

        if response.status_code != 200:
            logger.error(f"HTTP {response.status_code} from {explorer['name']}")
            logger.error(f"Response: {response.text[:500]}")
            return pd.DataFrame()

        data = response.json()

        logger.info(f"API Response Status: {data.get('status')}")
        logger.info(f"API Response Message: {data.get('message')}")

        # Check for API errors
        if data.get("status") != "1":
            logger.warning(f"API returned status {data.get('status')}: {data.get('message', 'No transactions found')}")
            logger.info(f"Full response: {data}")
            return pd.DataFrame()

        if not data.get("result"):
            logger.info(f"No transactions found on {explorer['name']} for {address}")
            return pd.DataFrame()

        rows = []
        for tx in data["result"]:
            try:
                rows.append({
                    "date": datetime.fromtimestamp(int(tx.get("timeStamp", 0))).strftime("%Y-%m-%d %H:%M"),
                    "from_address": tx.get("from", ""),
                    "to_address": tx.get("to", ""),
                    "amount": float(int(tx.get("value", 0)) / 1e18),
                    "token": explorer["native_token"],
                    "tx_hash": tx.get("hash", ""),
                    "chain": chain,
                    "gas_used": int(tx.get("gas", 0)),
                    "status": "success" if tx.get("isError", "0") == "0" else "failed",
                })
            except (ValueError, KeyError) as e:
                logger.debug(f"Skipping malformed transaction: {e}")
                continue

        logger.info(f"✅ Fetched {len(rows)} native transactions from {explorer['name']}")
        return pd.DataFrame(rows)

    except requests.exceptions.Timeout:
        logger.error(f"Timeout connecting to {explorer['name']}")
        return pd.DataFrame()
    except Exception as e:
        logger.error(f"Error fetching from {explorer['name']}: {e}")
        return pd.DataFrame()


def get_evm_token_transfers(address: str, chain: str, api_key: str, timeout: int = 30) -> pd.DataFrame:
    """
    Fetch ERC20/BEP20/etc token transfers for an address using Etherscan API v2 UNIFIED.
    """
    if chain not in EXPLORER_APIS:
        return pd.DataFrame()

    explorer = EXPLORER_APIS[chain]

    params = {
        "module": "account",
        "action": "tokentx",
        "address": address,
        "chainId": explorer["chainId"],
        "sort": "desc",
        "page": 1,
        "offset": 10000,
        "apikey": api_key,
    }

    try:
        logger.info(f"Fetching token transfers from {explorer['name']} (Chain {explorer['chainId']}) using Etherscan v2 API...")
        response = requests.get(explorer["base_url"], params=params, timeout=timeout)

        if response.status_code != 200:
            logger.warning(f"HTTP {response.status_code} from {explorer['name']}")
            return pd.DataFrame()

        data = response.json()

        if data.get("status") != "1" or not data.get("result"):
            logger.info(f"No token transfers found on {explorer['name']}")
            return pd.DataFrame()

        rows = []
        for tx in data["result"]:
            try:
                rows.append({
                    "date": datetime.fromtimestamp(int(tx.get("timeStamp", 0))).strftime("%Y-%m-%d %H:%M"),
                    "from_address": tx.get("from", ""),
                    "to_address": tx.get("to", ""),
                    "amount": float(int(tx.get("value", 0)) / 10 ** int(tx.get("tokenDecimal", 18))),
                    "token": tx.get("tokenSymbol", "UNKNOWN"),
                    "tx_hash": tx.get("hash", ""),
                    "chain": chain,
                    "contract": tx.get("contractAddress", ""),
                    "token_name": tx.get("tokenName", ""),
                })
            except (ValueError, KeyError):
                continue

        logger.info(f"✅ Fetched {len(rows)} token transfers from {explorer['name']}")
        return pd.DataFrame(rows)

    except Exception as e:
        logger.error(f"Error fetching token transfers from {explorer['name']}: {e}")
        return pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# BITCOIN FUNCTIONS
# ─────────────────────────────────────────────────────────────
def get_bitcoin_transactions_blockchain(address: str, timeout: int = 30) -> pd.DataFrame:
    """
    Fetch Bitcoin transactions using Blockchain.com API (free, no key).
    """
    url = f"https://blockchain.info/address/{address}?format=json"

    try:
        logger.info("Fetching Bitcoin transactions from Blockchain.com...")
        response = requests.get(url, timeout=timeout)

        if response.status_code != 200:
            logger.warning(f"HTTP {response.status_code} from Blockchain.com")
            return pd.DataFrame()

        data = response.json()
        rows = []

        # Process all transactions
        for tx in data.get("txs", []):
            tx_time = datetime.fromtimestamp(tx.get("time", 0)).strftime("%Y-%m-%d %H:%M")

            # Track inputs (where funds come FROM)
            for inp in tx.get("inputs", []):
                prev_addr = inp.get("prev_out", {}).get("addr", "Unknown")
                amount_sat = inp.get("prev_out", {}).get("value", 0)
                rows.append({
                    "date": tx_time,
                    "from_address": prev_addr,
                    "to_address": address,
                    "amount": amount_sat / 1e8,
                    "token": "BTC",
                    "tx_hash": tx.get("hash", ""),
                    "chain": "bitcoin",
                    "direction": "in",
                })

            # Track outputs (where funds go TO)
            for out in tx.get("out", []):
                out_addr = out.get("addr", "Unknown")
                amount_sat = out.get("value", 0)
                rows.append({
                    "date": tx_time,
                    "from_address": address,
                    "to_address": out_addr,
                    "amount": amount_sat / 1e8,
                    "token": "BTC",
                    "tx_hash": tx.get("hash", ""),
                    "chain": "bitcoin",
                    "direction": "out",
                })

        logger.info(f"✅ Fetched {len(rows)} Bitcoin transactions from Blockchain.com")
        return pd.DataFrame(rows)

    except Exception as e:
        logger.error(f"Error fetching Bitcoin transactions: {e}")
        return pd.DataFrame()


def get_bitcoin_transactions_mempool(address: str, timeout: int = 30) -> pd.DataFrame:
    """
    Fetch Bitcoin transactions using Mempool.space API (free, no key).
    """
    url = f"https://mempool.space/api/address/{address}"

    try:
        logger.info("Fetching Bitcoin transactions from Mempool.space...")
        response = requests.get(url, timeout=timeout)

        if response.status_code != 200:
            logger.warning(f"HTTP {response.status_code} from Mempool.space")
            return pd.DataFrame()

        data = response.json()
        rows = []

        # Process all transactions
        for tx in data.get("txs", []) + data.get("chain_txs", []):
            try:
                block_time = tx.get("status", {}).get("block_time", 0)
                if block_time:
                    tx_time = datetime.fromtimestamp(block_time).strftime("%Y-%m-%d %H:%M")
                else:
                    tx_time = datetime.now().strftime("%Y-%m-%d %H:%M")

                # Track inputs
                for inp in tx.get("vin", []):
                    prev_addr = inp.get("prevout", {}).get("scriptpubkey_address", "Unknown")
                    amount_sat = inp.get("prevout", {}).get("value", 0)
                    rows.append({
                        "date": tx_time,
                        "from_address": prev_addr,
                        "to_address": address,
                        "amount": amount_sat / 1e8,
                        "token": "BTC",
                        "tx_hash": tx.get("txid", ""),
                        "chain": "bitcoin",
                        "direction": "in",
                    })

                # Track outputs
                for out in tx.get("vout", []):
                    out_addr = out.get("scriptpubkey_address", "Unknown")
                    amount_sat = out.get("value", 0)
                    rows.append({
                        "date": tx_time,
                        "from_address": address,
                        "to_address": out_addr,
                        "amount": amount_sat / 1e8,
                        "token": "BTC",
                        "tx_hash": tx.get("txid", ""),
                        "chain": "bitcoin",
                        "direction": "out",
                    })
            except Exception as e:
                logger.debug(f"Skipping transaction: {e}")
                continue

        logger.info(f"✅ Fetched {len(rows)} Bitcoin transactions from Mempool.space")
        return pd.DataFrame(rows)

    except Exception as e:
        logger.error(f"Error fetching Bitcoin transactions from Mempool: {e}")
        return pd.DataFrame()


# ─────────────────────────────────────────────────────────────
# TRON SUPPORT  (TronScan public API — no key required)
# ─────────────────────────────────────────────────────────────
TRONSCAN_BASE = "https://apilist.tronscanapi.com/api"


def get_tron_native_transactions(address: str, limit: int = 50, timeout: int = 30) -> pd.DataFrame:
    """Fetch native TRX transactions for a TRON address via TronScan."""
    url = f"{TRONSCAN_BASE}/transaction"
    params = {
        "address": address,
        "limit": limit,
        "sort": "-timestamp",
        "count": "true",
        "filterTokenValue": 0,
    }
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        logger.info(f"TronScan native TX HTTP {resp.status_code}")
        if resp.status_code != 200:
            logger.warning(f"TronScan returned {resp.status_code}: {resp.text[:200]}")
            return pd.DataFrame()

        data = resp.json()
        rows = []
        for tx in data.get("data", []):
            try:
                ts = tx.get("timestamp", 0) / 1000
                contract = tx.get("contractData", {})
                amount_sun = int(contract.get("amount", 0))
                rows.append({
                    "date":         datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M"),
                    "from_address": contract.get("owner_address", tx.get("ownerAddress", "")),
                    "to_address":   contract.get("to_address",    tx.get("toAddress", "")),
                    "amount":       amount_sun / 1_000_000,   # SUN → TRX
                    "token":        "TRX",
                    "tx_hash":      tx.get("hash", ""),
                    "chain":        "tron",
                    "status":       "success" if tx.get("contractRet") == "SUCCESS" else "failed",
                })
            except Exception as e:
                logger.debug(f"Skipping TRX tx: {e}")
                continue

        logger.info(f"✅ Fetched {len(rows)} native TRX transactions")
        return pd.DataFrame(rows)

    except Exception as e:
        logger.error(f"Error fetching native TRX transactions: {e}")
        return pd.DataFrame()


def get_tron_trc20_transfers(address: str, limit: int = 50, timeout: int = 30) -> pd.DataFrame:
    """Fetch TRC20 token transfers (USDT, USDC, etc.) for a TRON address."""
    url = f"{TRONSCAN_BASE}/token_trc20/transfers"
    params = {
        "relatedAddress": address,
        "limit": limit,
        "start": 0,
        "sort": "-timestamp",
        "count": "true",
        "filterTokenValue": 0,
    }
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        logger.info(f"TronScan TRC20 HTTP {resp.status_code}")
        if resp.status_code != 200:
            logger.warning(f"TronScan TRC20 returned {resp.status_code}: {resp.text[:200]}")
            return pd.DataFrame()

        data = resp.json()
        rows = []
        for tx in data.get("token_transfers", []):
            try:
                decimals = int(tx.get("tokenInfo", {}).get("tokenDecimal", 6))
                raw_amt  = int(tx.get("quant", 0))
                symbol   = tx.get("tokenInfo", {}).get("tokenAbbr", "TRC20")
                ts       = tx.get("block_ts", 0) / 1000
                rows.append({
                    "date":         datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M"),
                    "from_address": tx.get("from_address", ""),
                    "to_address":   tx.get("to_address", ""),
                    "amount":       raw_amt / (10 ** decimals),
                    "token":        symbol,
                    "tx_hash":      tx.get("transaction_id", ""),
                    "chain":        "tron",
                    "status":       "success",
                })
            except Exception as e:
                logger.debug(f"Skipping TRC20 tx: {e}")
                continue

        logger.info(f"✅ Fetched {len(rows)} TRC20 transfers")
        return pd.DataFrame(rows)

    except Exception as e:
        logger.error(f"Error fetching TRC20 transfers: {e}")
        return pd.DataFrame()


def get_tron_account_info(address: str, timeout: int = 15) -> dict:
    """Fetch account summary (balance, bandwidth, energy) from TronScan."""
    url = f"{TRONSCAN_BASE}/accountv2"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, params={"address": address}, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.error(f"TronScan account info error: {e}")
    return {}

# ─────────────────────────────────────────────────────────────
# UNIFIED ADDRESS LOOKUP
# ─────────────────────────────────────────────────────────────
def lookup_address(address: str, chain: str, include_tokens: bool = True, rate_limit_delay: float = 0.1, api_key: str = "") -> Dict:
    """
    Comprehensive address lookup across all available APIs.
    Returns both native and token transfers.

    Args:
        address: Blockchain address to lookup
        chain: Chain name (ethereum, bsc, polygon, avalanche, fantom, arbitrum, optimism, bitcoin)
        include_tokens: Whether to fetch token transfers
        rate_limit_delay: Delay between API calls
        api_key: Etherscan API key (used for ALL EVM chains in 2025+)

    Returns:
        Dict with transaction data and metadata
    """
    results = {
        "success": False,
        "chain": chain,
        "address": address,
        "native_txs": pd.DataFrame(),
        "token_txs": pd.DataFrame(),
        "total_txs": 0,
        "sources": [],
        "errors": [],
    }

    try:
        if chain == "bitcoin":
            # Try multiple Bitcoin APIs (no key needed)
            logger.info("Trying Blockchain.com for Bitcoin address...")
            results["native_txs"] = get_bitcoin_transactions_blockchain(address)

            if results["native_txs"].empty:
                logger.info("Blockchain.com failed, trying Mempool.space...")
                time.sleep(rate_limit_delay)
                results["native_txs"] = get_bitcoin_transactions_mempool(address)

            if not results["native_txs"].empty:
                results["sources"].append("Bitcoin: Blockchain.com/Mempool.space")
                results["success"] = True
            else:
                results["errors"].append("No Bitcoin transactions found")

        elif chain == "tron":
            # TRON — TronScan public API, no API key required
            logger.info("Fetching native TRX transactions from TronScan...")
            results["native_txs"] = get_tron_native_transactions(address)
            time.sleep(rate_limit_delay)

            logger.info("Fetching TRC20 token transfers from TronScan...")
            results["token_txs"] = get_tron_trc20_transfers(address)

            if not results["native_txs"].empty or not results["token_txs"].empty:
                results["sources"].append("TronScan (native TRX + TRC20 tokens)")
                results["success"] = True
            else:
                results["errors"].append("No TRON transactions found — check address format (must start with T)")

        else:
            # EVM chains - use Etherscan API key (unified for all chains in 2025+)
            if not api_key:
                results["errors"].append(f"No API key provided for {chain}")
                logger.error(f"No API key provided for {chain}")
                return results

            logger.info(f"🔑 Using Etherscan API key for {chain}: {api_key[:10]}...")

            # Get native transactions
            results["native_txs"] = get_evm_transactions(address, chain, api_key)
            time.sleep(rate_limit_delay)

            if not results["native_txs"].empty:
                results["sources"].append(f"{EXPLORER_APIS[chain]['name']} (Native)")
                results["success"] = True
            else:
                logger.warning(f"No native transactions found on {chain}")

            # Get token transfers if requested
            if include_tokens:
                logger.info(f"Fetching token transfers for {chain}...")
                token_df = get_evm_token_transfers(address, chain, api_key)
                time.sleep(rate_limit_delay)
                if not token_df.empty:
                    results["token_txs"] = token_df
                    results["sources"].append(f"{EXPLORER_APIS[chain]['name']} (Tokens)")
                    results["success"] = True

        # Combine results
        all_txs = pd.concat([results["native_txs"], results["token_txs"]], ignore_index=True)
        results["total_txs"] = len(all_txs)

        logger.info(f"✅ Lookup complete: {results['total_txs']} transactions found")

    except Exception as e:
        logger.error(f"Error in lookup_address: {e}")
        results["errors"].append(str(e))

    return results


# ─────────────────────────────────────────────────────────────
# ADDRESS VALIDATION
# ─────────────────────────────────────────────────────────────
def validate_address(address: str, chain: str) -> Tuple[bool, str]:
    """
    Validate address format for the given chain.
    """
    address = address.strip()

    if chain == "bitcoin":
        if address.startswith(("1", "3", "bc1")) and len(address) >= 26:
            return True, "Valid Bitcoin address"
        return False, "Invalid Bitcoin address format"

    elif chain in ["ethereum", "bsc", "polygon", "avalanche", "fantom", "arbitrum", "optimism"]:
        if address.startswith("0x") and len(address) == 42:
            try:
                int(address, 16)
                return True, "Valid EVM address"
            except ValueError:
                return False, "Invalid EVM address (not valid hex)"
        return False, "Invalid EVM address format"

    elif chain == "tron":
        if address.startswith("T") and len(address) == 34:
            return True, "Valid TRON address"
        return False, "Invalid TRON address (must start with T and be 34 characters)"

    return False, "Unknown chain"


def get_chain_from_address(address: str) -> Optional[str]:
    """
    Attempt to determine chain from address format.
    """
    address = address.strip()

    if address.startswith("0x") and len(address) == 42:
        return "ethereum"
    elif address.startswith(("1", "3", "bc1")):
        return "bitcoin"
    elif address.startswith("T") and len(address) == 34:
        return "tron"

    return None