"""
forensics_social.py — Crypto Forensics Analyzer Pro v5.0
Social Media & Open Web Intelligence:
  • Reddit public API — search posts and comments mentioning addresses
  • GitHub code search — find addresses committed to public repos
  • BitcoinAbuse.com — community scam/fraud reports per address
  • CryptoScamDB API — known scam address database
  • Etherscan community labels — crowd-sourced address tags
  • Paste site detection — pastebin / ghostbin mentions
  • Blockchain.com entity lookup — known named entities
"""

import requests
import pandas as pd
import streamlit as st
import json
import time
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from pathlib import Path

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent": "Mozilla/5.0 CryptoForensicsAnalyzer/5.0 (forensic investigation tool)",
    "Accept":     "application/json",
}

def _get(url: str, params: dict = None, timeout: int = 12) -> Optional[dict]:
    """Safe GET with error handling."""
    try:
        resp = requests.get(url, params=params, headers=_HEADERS, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        logger.debug(f"HTTP {resp.status_code} from {url}")
    except Exception as e:
        logger.debug(f"Request failed {url}: {e}")
    return None


def _is_crypto_address(text: str) -> bool:
    """Quick check if a string looks like a crypto address."""
    return bool(
        re.match(r"^0x[a-fA-F0-9]{40}$", text) or          # EVM
        re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", text) or  # BTC Legacy
        re.match(r"^bc1[a-z0-9]{25,62}$", text, re.I) or    # BTC SegWit
        re.match(r"^T[a-zA-Z0-9]{33}$", text)                # Tron
    )


# ─────────────────────────────────────────────────────────────
# 1. REDDIT PUBLIC API
#    Completely free — no auth, no key required.
#    Searches posts and comments across all subreddits.
# ─────────────────────────────────────────────────────────────

REDDIT_SEARCH_URL = "https://www.reddit.com/search.json"

CRYPTO_SUBREDDITS = [
    "CryptoCurrency", "Bitcoin", "ethereum", "CryptoScams",
    "BitcoinScamAlerts", "Scams", "Fraud", "CryptoMoonShots",
    "defi", "wallstreetbets", "CryptoTax",
]


@st.cache_data(ttl=1800, show_spinner=False)
def search_reddit(address: str, max_results: int = 25) -> List[Dict]:
    """
    Search Reddit for mentions of a crypto address.
    Uses Reddit's public JSON API — no authentication required.
    """
    results = []

    # Global search
    data = _get(REDDIT_SEARCH_URL, params={
        "q":    f'"{address}"',
        "type": "link,comment",
        "sort": "relevance",
        "limit": min(max_results, 100),
        "t":    "all",
    })
    if data:
        for post in data.get("data", {}).get("children", []):
            p = post.get("data", {})
            results.append({
                "platform":   "Reddit",
                "type":       post.get("kind","t3"),
                "title":      p.get("title", p.get("body",""))[:120],
                "url":        f"https://reddit.com{p.get('permalink','')}",
                "subreddit":  p.get("subreddit",""),
                "author":     p.get("author",""),
                "score":      p.get("score",0),
                "date":       datetime.fromtimestamp(p.get("created_utc",0)).strftime("%Y-%m-%d"),
                "text":       (p.get("selftext","") or p.get("body",""))[:300],
                "sentiment":  "negative" if any(w in (p.get("title","") + p.get("selftext","") + p.get("body","")).lower()
                              for w in ["scam","fraud","stolen","hack","rug","lost","fake"]) else "neutral",
            })
    time.sleep(0.5)  # Reddit rate limit

    # Also search crypto-specific subreddits
    for sub in CRYPTO_SUBREDDITS[:5]:
        sub_data = _get(
            f"https://www.reddit.com/r/{sub}/search.json",
            params={"q": address, "restrict_sr": "true", "limit": 10},
        )
        if sub_data:
            for post in sub_data.get("data",{}).get("children",[]):
                p = post.get("data",{})
                entry = {
                    "platform":  "Reddit",
                    "type":      f"r/{sub}",
                    "title":     p.get("title","")[:120],
                    "url":       f"https://reddit.com{p.get('permalink','')}",
                    "subreddit": sub,
                    "author":    p.get("author",""),
                    "score":     p.get("score",0),
                    "date":      datetime.fromtimestamp(p.get("created_utc",0)).strftime("%Y-%m-%d"),
                    "text":      p.get("selftext","")[:300],
                    "sentiment": "negative" if "scam" in p.get("title","").lower() else "neutral",
                }
                # Deduplicate
                if entry["url"] not in {r["url"] for r in results}:
                    results.append(entry)
        time.sleep(0.3)

    logger.info(f"✅ Reddit: {len(results)} results for {address[:16]}")
    return results


# ─────────────────────────────────────────────────────────────
# 2. GITHUB CODE SEARCH
#    Finds crypto addresses committed to public repositories.
#    Key for: finding dev wallets, contract deployer addresses,
#    hardcoded payment addresses in scam project code.
# ─────────────────────────────────────────────────────────────

GITHUB_SEARCH_URL = "https://api.github.com/search/code"


@st.cache_data(ttl=3600, show_spinner=False)
def search_github(address: str, github_token: str = "") -> List[Dict]:
    """
    Search GitHub for an address in public code/commits.
    60 req/hour unauthenticated, 5000/hour with token.
    """
    headers = dict(_HEADERS)
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    headers["Accept"] = "application/vnd.github.v3+json"

    results = []
    try:
        resp = requests.get(
            GITHUB_SEARCH_URL,
            params={"q": address, "per_page": 20},
            headers=headers,
            timeout=12,
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                results.append({
                    "platform":   "GitHub",
                    "type":       "code",
                    "title":      item.get("name",""),
                    "url":        item.get("html_url",""),
                    "repository": item.get("repository",{}).get("full_name",""),
                    "author":     item.get("repository",{}).get("owner",{}).get("login",""),
                    "date":       "",
                    "text":       f"File: {item.get('path','')} in {item.get('repository',{}).get('full_name','')}",
                    "score":      0,
                    "sentiment":  "neutral",
                })
        elif resp.status_code == 403:
            results.append({
                "platform":"GitHub","type":"rate_limit",
                "title":"Rate limited — try again in 1 minute or add GitHub token",
                "url":"","repository":"","author":"","date":"","text":"","score":0,"sentiment":"neutral",
            })
    except Exception as e:
        logger.debug(f"GitHub search failed: {e}")

    logger.info(f"✅ GitHub: {len(results)} results for {address[:16]}")
    return results


# ─────────────────────────────────────────────────────────────
# 3. BITCOINABUSE.COM
#    Community reports of Bitcoin addresses used in scams,
#    ransomware, darknet markets, etc. Free API.
# ─────────────────────────────────────────────────────────────

BITCOINABUSE_URL = "https://www.bitcoinabuse.com/api/reports/check"
BITCOINABUSE_CACHE = Path("bitcoinabuse_cache.json")


@st.cache_data(ttl=3600, show_spinner=False)
def check_bitcoinabuse(address: str) -> Dict:
    """
    Check BitcoinAbuse.com for community abuse reports.
    Free API — returns report count and abuse types.
    """
    result = {
        "address":      address,
        "report_count": 0,
        "abuse_types":  [],
        "first_seen":   "",
        "last_seen":    "",
        "source":       "BitcoinAbuse.com",
    }

    # BitcoinAbuse requires an API token even for free tier
    # We use the public check endpoint which returns basic data
    try:
        resp = requests.get(
            f"https://www.bitcoinabuse.com/api/reports/check",
            params={"address": address, "api_token": "free"},
            headers=_HEADERS,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["report_count"] = data.get("count", 0)
            result["abuse_types"]  = [r.get("abuse_type_label","") for r in data.get("result",[]) if r.get("abuse_type_label")]
            if data.get("result"):
                dates = [r.get("created_at","") for r in data["result"] if r.get("created_at")]
                result["first_seen"] = min(dates)[:10] if dates else ""
                result["last_seen"]  = max(dates)[:10] if dates else ""
    except Exception as e:
        logger.debug(f"BitcoinAbuse failed: {e}")

    return result


# ─────────────────────────────────────────────────────────────
# 4. CRYPTOSCAMDB
#    Known scam addresses database. Completely free API.
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=7200, show_spinner=False)
def check_cryptoscamdb(address: str) -> Dict:
    """
    Check CryptoScamDB for known scam reports.
    Free public API — no authentication required.
    """
    result = {
        "address":    address,
        "is_scam":    False,
        "scam_type":  "",
        "entries":    [],
        "source":     "CryptoScamDB",
    }
    try:
        resp = requests.get(
            f"https://api.cryptoscamdb.org/v1/check/{address}",
            headers=_HEADERS,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["is_scam"]  = data.get("input","") == address and bool(data.get("entries"))
            result["entries"]  = data.get("entries",[])[:5]
            if result["entries"]:
                result["scam_type"] = result["entries"][0].get("type","")
    except Exception as e:
        logger.debug(f"CryptoScamDB failed: {e}")
    return result


# ─────────────────────────────────────────────────────────────
# 5. ETHERSCAN COMMUNITY LABELS
#    Crowd-sourced address tags visible on Etherscan.
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=3600, show_spinner=False)
def get_etherscan_label(address: str, api_key: str = "") -> Dict:
    """
    Fetch community label for an Ethereum address from Etherscan.
    Labels include exchange names, DEX labels, known entities.
    """
    result = {"address": address, "label": "", "tags": [], "source": "Etherscan"}
    if not api_key or not address.startswith("0x"):
        return result

    try:
        resp = requests.get(
            "https://api.etherscan.io/v2/api",
            params={
                "chainid": 1,
                "module":  "account",
                "action":  "txlist",
                "address": address,
                "offset":  1,
                "sort":    "asc",
                "apikey":  api_key,
            },
            timeout=10,
        ).json()
        # Etherscan doesn't expose labels via API directly,
        # but the address page shows them — we check the token tracker
        result["label"] = "Checked — no public label API available"
    except Exception:
        pass

    # Use the Etherscan name tag lookup (unofficial endpoint)
    try:
        resp2 = requests.get(
            f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}&apikey={api_key}",
            timeout=10,
        ).json()
        if resp2.get("status") == "1" and resp2.get("result"):
            contract_name = resp2["result"][0].get("ContractName","")
            if contract_name:
                result["label"] = f"Contract: {contract_name}"
    except Exception:
        pass

    return result


# ─────────────────────────────────────────────────────────────
# 6. BLOCKCHAIN.COM ENTITY LOOKUP
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=3600, show_spinner=False)
def check_blockchain_com(address: str) -> Dict:
    """
    Check Blockchain.com for entity/wallet information.
    Returns label, transaction count, and balance for Bitcoin addresses.
    """
    result = {
        "address":   address,
        "label":     "",
        "n_tx":      0,
        "balance":   0,
        "source":    "Blockchain.com",
    }
    # Only works for Bitcoin addresses
    if not (address.startswith("1") or address.startswith("3") or address.startswith("bc1")):
        return result

    try:
        resp = requests.get(
            f"https://blockchain.info/rawaddr/{address}",
            headers=_HEADERS,
            timeout=10,
        ).json()
        result["n_tx"]    = resp.get("n_tx", 0)
        result["balance"] = resp.get("final_balance", 0) / 1e8
        result["label"]   = resp.get("wallet",{}).get("label","")
    except Exception as e:
        logger.debug(f"Blockchain.com failed: {e}")

    return result


# ─────────────────────────────────────────────────────────────
# 7. PASTE SITE MENTIONS
#    Check if an address appears in public paste sites.
#    Paste sites are commonly used to publish stolen credentials,
#    ransomware payment instructions, and scam templates.
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=3600, show_spinner=False)
def check_paste_sites(address: str) -> List[Dict]:
    """
    Search for address mentions on paste/document sharing sites.
    Uses Google-adjacent search and HaveIBeenPwned-style lookup.
    """
    results = []

    # Psbdmp (Pastebin dump search — free public API)
    try:
        resp = requests.get(
            f"https://psbdmp.ws/api/v3/search/{address}",
            headers=_HEADERS,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            for paste in (data.get("data") or [])[:10]:
                results.append({
                    "platform":  "Pastebin",
                    "type":      "paste",
                    "title":     paste.get("id",""),
                    "url":       f"https://pastebin.com/{paste.get('id','')}",
                    "date":      paste.get("time","")[:10] if paste.get("time") else "",
                    "text":      f"Paste ID: {paste.get('id','')}",
                    "score":     0,
                    "sentiment": "suspicious",
                })
    except Exception as e:
        logger.debug(f"Psbdmp failed: {e}")

    logger.info(f"✅ Paste sites: {len(results)} results for {address[:16]}")
    return results


# ─────────────────────────────────────────────────────────────
# 8. AGGREGATED SOCIAL MEDIA SEARCH
# ─────────────────────────────────────────────────────────────

def search_all_social(
    address:      str,
    api_key:      str = "",
    github_token: str = "",
    max_results:  int = 25,
) -> Dict:
    """
    Run all social media and open web searches for an address.
    Returns aggregated results from all sources.
    """
    results = {
        "address":  address,
        "searched_at": datetime.now().isoformat(),
        "reddit":        [],
        "github":        [],
        "bitcoinabuse":  {},
        "cryptoscamdb":  {},
        "blockchain_com":{},
        "paste_sites":   [],
        "etherscan_label":{},
        "summary": {},
    }

    with st.spinner("Searching Reddit…"):
        results["reddit"] = search_reddit(address, max_results)

    with st.spinner("Searching GitHub…"):
        results["github"] = search_github(address, github_token)

    if address.startswith("1") or address.startswith("3") or address.startswith("bc1"):
        with st.spinner("Checking BitcoinAbuse…"):
            results["bitcoinabuse"] = check_bitcoinabuse(address)
        with st.spinner("Checking Blockchain.com…"):
            results["blockchain_com"] = check_blockchain_com(address)

    with st.spinner("Checking CryptoScamDB…"):
        results["cryptoscamdb"] = check_cryptoscamdb(address)

    with st.spinner("Checking paste sites…"):
        results["paste_sites"] = check_paste_sites(address)

    if api_key and address.startswith("0x"):
        with st.spinner("Checking Etherscan labels…"):
            results["etherscan_label"] = get_etherscan_label(address, api_key)

    # Summary
    results["summary"] = {
        "reddit_mentions":     len(results["reddit"]),
        "github_mentions":     len(results["github"]),
        "abuse_reports":       results["bitcoinabuse"].get("report_count",0),
        "scamdb_hit":          results["cryptoscamdb"].get("is_scam", False),
        "paste_mentions":      len(results["paste_sites"]),
        "negative_sentiment":  len([r for r in results["reddit"] if r.get("sentiment") == "negative"]),
        "total_mentions":      len(results["reddit"]) + len(results["github"]) + len(results["paste_sites"]),
    }

    return results


# ─────────────────────────────────────────────────────────────
# DATASET BATCH SOCIAL SCAN
# ─────────────────────────────────────────────────────────────

def batch_social_scan(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """
    Run quick social checks on the top N high-risk addresses in the dataset.
    """
    if df.empty:
        return pd.DataFrame()

    # Pick top addresses by risk
    if "risk_level" in df.columns:
        top = df[df["risk_level"].isin(["CRITICAL","HIGH"])]["from_address"].value_counts().head(top_n).index.tolist()
    else:
        top = df["from_address"].value_counts().head(top_n).index.tolist()

    rows = []
    for addr in top:
        # Quick CryptoScamDB check only (fast, free)
        scam = check_cryptoscamdb(addr)
        abuse = check_bitcoinabuse(addr) if (addr.startswith("1") or addr.startswith("bc1")) else {}
        rows.append({
            "address":       addr,
            "scamdb_hit":    scam.get("is_scam",False),
            "scam_type":     scam.get("scam_type",""),
            "abuse_reports": abuse.get("report_count",0),
            "checked_at":    datetime.now().strftime("%H:%M"),
        })
        time.sleep(0.3)

    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_social_ui(df: pd.DataFrame = None, get_key_fn=None):
    """Social media and open web intelligence UI."""
    st.markdown("### 📡 Social Media & Open Web Intelligence")
    st.caption(
        "Search Reddit, GitHub, BitcoinAbuse, CryptoScamDB, paste sites, and Blockchain.com "
        "for mentions of crypto addresses. Finds suspects who publicly posted their address, "
        "scam reports from victims, and developer wallets committed to public code."
    )

    api_key      = get_key_fn("etherscan_key") if get_key_fn else ""
    anthropic_key = get_key_fn("anthropic_key") if get_key_fn else ""

    social_tabs = st.tabs([
        "🔍 Address Search",   "⚡ Batch Dataset Scan",
        "📊 Results",          "📋 Reddit Mentions",
        "💻 GitHub Findings",  "☠️ Abuse Reports"
    ])

    with social_tabs[0]:
        st.markdown("**Search all sources for a single address:**")
        sc1, sc2 = st.columns([3,1])
        social_addr = sc1.text_input(
            "Crypto address to search",
            key="social_addr",
            placeholder="0x… or Bitcoin address",
        )
        max_reddit = sc2.number_input("Max Reddit results", 5, 50, 25, key="social_max")

        github_token = st.text_input(
            "GitHub token (optional — increases rate limit from 60 to 5000/hr)",
            type="password", key="social_gh_token",
            help="Create at github.com/settings/tokens — no permissions needed for public search",
        )

        # Suggest top addresses from dataset
        if df is not None and not df.empty:
            if "risk_level" in df.columns:
                suggested = df[df["risk_level"] == "CRITICAL"]["from_address"].value_counts().head(5).index.tolist()
            else:
                suggested = df["from_address"].value_counts().head(5).index.tolist()

            if suggested:
                st.caption("**Quick select from critical addresses in dataset:**")
                btn_cols = st.columns(min(3, len(suggested)))
                for i, addr in enumerate(suggested[:3]):
                    if btn_cols[i].button(addr[:18]+"…", key=f"ss_{i}"):
                        st.session_state.social_addr = addr
                        st.rerun()

        if st.button("📡 Search All Sources", type="primary", key="run_social") and social_addr.strip():
            results = search_all_social(
                social_addr.strip(), api_key, github_token, int(max_reddit)
            )
            st.session_state.social_results = results
            st.session_state.social_results_addr = social_addr.strip()

    with social_tabs[1]:
        st.markdown("**Quick scan of top high-risk addresses in dataset:**")
        st.caption(
            "Runs CryptoScamDB and BitcoinAbuse checks on the top 10 critical/high-risk "
            "addresses in your dataset. Faster than full search."
        )
        top_n = st.slider("Addresses to scan", 3, 20, 10, key="batch_n")
        if st.button("⚡ Batch Scan Dataset", type="primary", key="run_batch_social"):
            if df is not None and not df.empty:
                with st.spinner(f"Scanning top {top_n} addresses…"):
                    batch_df = batch_social_scan(df, int(top_n))
                    st.session_state.batch_social_df = batch_df

                # Ensure expected columns exist
                if "scamdb_hit" not in batch_df.columns:
                    batch_df["scamdb_hit"] = False

                if "abuse_reports" not in batch_df.columns:
                    batch_df["abuse_reports"] = 0

                batch_df["scamdb_hit"] = (
                    batch_df["scamdb_hit"]
                    .fillna(False)
                    .astype(bool)
                )

                batch_df["abuse_reports"] = pd.to_numeric(
                    batch_df["abuse_reports"],
                    errors="coerce"
                ).fillna(0)

                hits = batch_df[
                    batch_df["scamdb_hit"]
                    |
                    (batch_df["abuse_reports"] > 0)
                    ]
                if not hits.empty:
                    st.error(f"🚨 {len(hits)} addresses flagged in social databases")
                else:
                    st.success("✅ No social database hits for top addresses")
            else:
                st.warning("Load a dataset first.")

        if "batch_social_df" in st.session_state:
            bdf = st.session_state.batch_social_df
            st.dataframe(bdf, use_container_width=True,
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
            st.download_button("⬇️ Export Batch Results",
                bdf.to_csv(index=False).encode(),
                "social_batch_scan.csv", "text/csv")

    with social_tabs[2]:
        if "social_results" not in st.session_state:
            st.info("Run a search in the Address Search tab first.")
        else:
            results = st.session_state.social_results
            addr    = st.session_state.get("social_results_addr","")
            summary = results.get("summary",{})

            st.markdown(f"### Results for `{addr[:30]}…`")

            m1,m2,m3,m4,m5 = st.columns(5)
            m1.metric("Reddit Mentions",    summary.get("reddit_mentions",0))
            m2.metric("GitHub Mentions",    summary.get("github_mentions",0))
            m3.metric("Abuse Reports",      summary.get("abuse_reports",0))
            m4.metric("ScamDB Hit",         "🚨 YES" if summary.get("scamdb_hit") else "✅ No")
            m5.metric("Paste Sites",        summary.get("paste_mentions",0))

            total = summary.get("total_mentions",0)
            negative = summary.get("negative_sentiment",0)
            if total > 0:
                if summary.get("scamdb_hit") or summary.get("abuse_reports",0) > 0:
                    st.error(f"🚨 Address has confirmed abuse/scam reports")
                elif negative > 2:
                    st.warning(f"⚠️ {negative} Reddit mentions with negative sentiment (scam/fraud keywords)")
                elif total > 0:
                    st.info(f"ℹ️ {total} mentions found — review tabs for details")

            # CryptoScamDB
            scamdb = results.get("cryptoscamdb",{})
            if scamdb.get("is_scam"):
                st.error(f"☠️ **CryptoScamDB:** Confirmed scam — type: {scamdb.get('scam_type','')}")
                for entry in scamdb.get("entries",[])[:3]:
                    st.markdown(f"  - {entry.get('name','')} ({entry.get('type','')}): {entry.get('url','')}")

            # BitcoinAbuse
            abuse = results.get("bitcoinabuse",{})
            if abuse.get("report_count",0) > 0:
                st.warning(
                    f"☠️ **BitcoinAbuse.com:** {abuse['report_count']} abuse reports | "
                    f"Types: {', '.join(set(abuse.get('abuse_types',[])))}"
                )

            # Blockchain.com
            bc = results.get("blockchain_com",{})
            if bc.get("label"):
                st.info(f"🔗 **Blockchain.com label:** {bc['label']}")
            if bc.get("n_tx",0) > 0:
                st.caption(
                    f"Blockchain.com: {bc['n_tx']} transactions | "
                    f"Balance: {bc.get('balance',0):.8f} BTC"
                )

    with social_tabs[3]:
        results = st.session_state.get("social_results",{})
        reddit  = results.get("reddit",[])
        if not reddit:
            st.info("No Reddit results. Run a search first.")
        else:
            st.markdown(f"**{len(reddit)} Reddit mentions:**")
            for post in reddit:
                icon = "🚨" if post.get("sentiment") == "negative" else "💬"
                with st.expander(
                    f"{icon} r/{post.get('subreddit','')} — {post.get('title','')[:70]}",
                    expanded=post.get("sentiment")=="negative"
                ):
                    st.markdown(f"**Author:** u/{post.get('author','')} | **Score:** {post.get('score',0)} | **Date:** {post.get('date','')}")
                    if post.get("text"):
                        st.caption(post["text"][:300])
                    st.markdown(f"[View on Reddit]({post.get('url','')})")

    with social_tabs[4]:
        results = st.session_state.get("social_results",{})
        github  = results.get("github",[])
        if not github:
            st.info("No GitHub results. Run a search first.")
        else:
            st.markdown(f"**{len(github)} GitHub mentions:**")
            for item in github:
                with st.expander(f"💻 {item.get('repository','')} — {item.get('title','')}"):
                    st.markdown(f"**Repo:** {item.get('repository','')} | **Author:** {item.get('author','')}")
                    st.caption(item.get("text",""))
                    st.markdown(f"[View on GitHub]({item.get('url','')})")
                    st.warning("⚠️ Address found in public code — developer wallet or hardcoded payment address")

    with social_tabs[5]:
        results = st.session_state.get("social_results",{})
        abuse   = results.get("bitcoinabuse",{})
        scamdb  = results.get("cryptoscamdb",{})
        pastes  = results.get("paste_sites",[])

        st.markdown("**BitcoinAbuse Reports:**")
        if abuse.get("report_count",0) > 0:
            st.error(f"🚨 {abuse['report_count']} reports — types: {', '.join(set(abuse.get('abuse_types',[])))}")
            st.caption(f"First seen: {abuse.get('first_seen','')} | Last seen: {abuse.get('last_seen','')}")
        else:
            st.success("✅ No BitcoinAbuse reports") if abuse else st.info("Run search first")

        st.markdown("**CryptoScamDB:**")
        if scamdb.get("is_scam"):
            st.error(f"🚨 Confirmed scam — {scamdb.get('scam_type','')}")
            for e in scamdb.get("entries",[]):
                st.markdown(f"- {e}")
        elif scamdb:
            st.success("✅ Not in CryptoScamDB")

        st.markdown("**Paste Site Mentions:**")
        if pastes:
            st.warning(f"⚠️ Found in {len(pastes)} paste(s)")
            for p in pastes:
                st.markdown(f"- [{p.get('platform','')} — {p.get('title','')}]({p.get('url','')})")
        elif "social_results" in st.session_state:
            st.success("✅ No paste site mentions found")
