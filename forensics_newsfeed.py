"""
forensics_newsfeed.py — Crypto Forensics Analyzer Pro v5.0
Crypto Crime News Intelligence Feed:
  • Aggregates free RSS feeds (CoinDesk, Krebs, CoinTelegraph, CISA, FBI)
  • Extracts crypto addresses mentioned in news articles
  • Cross-references extracted addresses with investigation dataset
  • Categorizes by crime type (hack, ransomware, scam, sanctions, etc.)
  • Real-time alerts when investigation addresses appear in news
"""

import re
import requests
import pandas as pd
import streamlit as st
import xml.etree.ElementTree as ET
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from pathlib import Path

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# NEWS FEED SOURCES
# ─────────────────────────────────────────────────────────────

NEWS_FEEDS = {
    "CoinDesk": {
        "url":      "https://www.coindesk.com/arc/outboundfeeds/rss/",
        "category": "general",
        "focus":    ["hack","scam","fraud","arrest","seized","stolen","laundering"],
        "icon":     "📰",
    },
    "CoinTelegraph": {
        "url":      "https://cointelegraph.com/rss",
        "category": "general",
        "focus":    ["hack","exploit","scam","fraud","police","interpol","sanction"],
        "icon":     "📰",
    },
    "Krebs on Security": {
        "url":      "https://krebsonsecurity.com/feed/",
        "category": "security",
        "focus":    ["bitcoin","crypto","ransomware","payment","wallet"],
        "icon":     "🔐",
    },
    "CISA Advisories": {
        "url":      "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "category": "government",
        "focus":    ["crypto","bitcoin","ransomware","virtual currency"],
        "icon":     "🏛️",
    },
    "The Block": {
        "url":      "https://www.theblock.co/rss.xml",
        "category": "general",
        "focus":    ["hack","exploit","arrest","seized","fraud"],
        "icon":     "📰",
    },
    "Decrypt": {
        "url":      "https://decrypt.co/feed",
        "category": "general",
        "focus":    ["scam","hack","fraud","stolen","laundering","arrest"],
        "icon":     "📰",
    },
    "Bleeping Computer": {
        "url":      "https://www.bleepingcomputer.com/feed/",
        "category": "security",
        "focus":    ["ransomware","crypto","bitcoin","payment","wallet"],
        "icon":     "🔐",
    },
}

CRIME_KEYWORDS = {
    "Hack/Exploit":       ["hack","exploit","breach","stolen","drained","compromised","reentrancy","flash loan"],
    "Ransomware":         ["ransomware","ransom","lockbit","blackcat","alphv","revil","conti","hive","akira"],
    "Fraud/Scam":         ["fraud","scam","ponzi","rug pull","exit scam","pig butchering","romance scam"],
    "Sanctions":          ["sanction","ofac","sdn","blacklist","designated","lazarus","dprk","north korea"],
    "Money Laundering":   ["launder","laundering","money mule","mixing","tumbling","obfuscat"],
    "Law Enforcement":    ["arrest","seized","indicted","charged","convicted","doj","fbi","europol","interpol"],
    "Darknet":            ["darknet","dark web","silk road","hydra","dream market","alphabay"],
    "NFT/DeFi Fraud":     ["nft","defi","rug","pump.dump","wash trading","fake","counterfeit"],
}

# Crypto address regex patterns
ADDRESS_PATTERNS = {
    "EVM":     re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "BTC_Legacy": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "BTC_SegWit": re.compile(r"\bbc1[a-z0-9]{25,62}\b", re.IGNORECASE),
    "Tron":    re.compile(r"\bT[a-zA-Z0-9]{33}\b"),
    "TxHash":  re.compile(r"\b0x[a-fA-F0-9]{64}\b"),
}


# ─────────────────────────────────────────────────────────────
# RSS FEED FETCHER
# ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=900, show_spinner=False)   # Cache 15 minutes
def fetch_rss_feed(source_name: str, feed_url: str, max_items: int = 20) -> List[Dict]:
    """
    Fetch and parse an RSS/Atom feed.
    Returns list of article dicts with extracted addresses.
    """
    articles = []
    try:
        resp = requests.get(
            feed_url,
            headers={"User-Agent": "CryptoForensicsAnalyzer/5.0 (forensic research)"},
            timeout=12,
        )
        if resp.status_code != 200:
            return []

        root = ET.fromstring(resp.content)
        ns   = {"atom": "http://www.w3.org/2005/Atom"}

        # Handle both RSS and Atom formats
        items = (root.findall(".//item") or          # RSS
                 root.findall(".//atom:entry", ns))   # Atom

        for item in items[:max_items]:
            def _text(tag):
                el = item.find(tag) or item.find(f"atom:{tag}", ns)
                return el.text if el is not None and el.text else ""

            title    = _text("title")
            link     = _text("link")
            pubdate  = _text("pubDate") or _text("published") or _text("updated")
            summary  = _text("description") or _text("summary") or _text("content")

            # Clean HTML from summary
            clean = re.sub(r"<[^>]+>", " ", summary or "")
            full_text = f"{title} {clean}"

            # Categorize
            categories = []
            full_lower = full_text.lower()
            for cat, keywords in CRIME_KEYWORDS.items():
                if any(kw in full_lower for kw in keywords):
                    categories.append(cat)

            # Only include if crypto/crime related
            if not categories and not any(
                w in full_lower for w in ["crypto","bitcoin","blockchain","ethereum","defi","nft"]
            ):
                continue

            # Extract addresses
            addresses = extract_addresses_from_text(full_text)

            # Parse date
            article_date = ""
            try:
                from email.utils import parsedate_to_datetime
                article_date = parsedate_to_datetime(pubdate).strftime("%Y-%m-%d") if pubdate else ""
            except Exception:
                article_date = pubdate[:10] if len(pubdate) >= 10 else ""

            articles.append({
                "source":     source_name,
                "title":      title[:120],
                "url":        link,
                "date":       article_date,
                "summary":    clean[:300],
                "categories": categories,
                "addresses":  addresses,
                "has_addresses": bool(addresses),
                "severity":   "HIGH" if "Hack/Exploit" in categories or "Ransomware" in categories
                              else "MEDIUM" if "Sanctions" in categories or "Law Enforcement" in categories
                              else "LOW",
            })

    except Exception as e:
        logger.warning(f"RSS fetch failed for {source_name}: {e}")

    return articles


def extract_addresses_from_text(text: str) -> Dict[str, List[str]]:
    """Extract all crypto addresses from article text."""
    found = {}
    for chain, pattern in ADDRESS_PATTERNS.items():
        matches = list(set(pattern.findall(text)))
        # Filter out obviously wrong matches (too common words etc.)
        if chain == "BTC_Legacy":
            matches = [m for m in matches if len(m) >= 26 and len(m) <= 35]
        if matches:
            found[chain] = matches[:10]   # Cap per chain
    return found


def fetch_all_feeds(max_per_feed: int = 15) -> List[Dict]:
    """Fetch all configured news feeds and merge results."""
    all_articles = []
    for name, config in NEWS_FEEDS.items():
        with st.spinner(f"Fetching {name}…"):
            articles = fetch_rss_feed(name, config["url"], max_per_feed)
        all_articles.extend(articles)
        time.sleep(0.3)

    # Sort by date
    all_articles.sort(key=lambda x: x.get("date",""), reverse=True)
    return all_articles


# ─────────────────────────────────────────────────────────────
# CROSS-REFERENCE WITH INVESTIGATION DATASET
# ─────────────────────────────────────────────────────────────

def cross_reference_news_with_dataset(
    articles:  List[Dict],
    df:        pd.DataFrame,
) -> List[Dict]:
    """
    Flag any news articles that mention addresses from the investigation dataset.
    This is the highest-value feature: knowing your suspect appeared in the news.
    """
    if df.empty:
        return articles

    dataset_addrs = set(
        df["from_address"].str.lower().tolist() +
        df["to_address"].str.lower().tolist()
    )
    # Also add tx hashes
    if "tx_hash" in df.columns:
        dataset_addrs.update(df["tx_hash"].str.lower().tolist())

    enriched = []
    for article in articles:
        matched_addrs = []
        for chain, addrs in article.get("addresses",{}).items():
            for addr in addrs:
                if addr.lower() in dataset_addrs:
                    matched_addrs.append({"chain": chain, "address": addr})

        enriched.append({
            **article,
            "dataset_matches": matched_addrs,
            "in_investigation": bool(matched_addrs),
        })

    return enriched


def search_articles_for_address(
    address: str,
    articles: List[Dict],
) -> List[Dict]:
    """Find all articles mentioning a specific address."""
    addr_lower = address.lower()
    matches = []
    for art in articles:
        for chain, addrs in art.get("addresses",{}).items():
            if any(a.lower() == addr_lower for a in addrs):
                matches.append(art)
                break
    return matches


# ─────────────────────────────────────────────────────────────
# CRIME TREND ANALYSIS
# ─────────────────────────────────────────────────────────────

def analyze_crime_trends(articles: List[Dict]) -> Dict:
    """Summarize crime types and trends from news articles."""
    from collections import Counter

    all_cats = []
    for art in articles:
        all_cats.extend(art.get("categories",[]))

    cat_counts  = Counter(all_cats)
    sources     = Counter(art["source"] for art in articles)
    has_addrs   = sum(1 for art in articles if art.get("has_addresses"))
    investigation_hits = sum(1 for art in articles if art.get("in_investigation"))

    return {
        "total_articles":       len(articles),
        "articles_with_addrs":  has_addrs,
        "investigation_hits":   investigation_hits,
        "crime_categories":     dict(cat_counts.most_common()),
        "sources":              dict(sources),
        "top_crime_type":       cat_counts.most_common(1)[0][0] if cat_counts else "None",
        "addresses_found":      sum(
            sum(len(v) for v in art.get("addresses",{}).values())
            for art in articles
        ),
    }


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────────────────────

def render_newsfeed_ui(df: pd.DataFrame = None):
    """Crypto crime news intelligence feed UI."""
    st.markdown("### 📰 Crypto Crime Intelligence Feed")
    st.caption(
        "Aggregates crypto crime news from CoinDesk, CoinTelegraph, Krebs on Security, "
        "CISA, Decrypt, and Bleeping Computer. Extracts addresses from articles and "
        "cross-references with your investigation dataset."
    )

    feed_tabs = st.tabs([
        "📡 Live Feed",          "🚨 Investigation Alerts",
        "🔍 Address Search",     "📊 Crime Trends",
        "🔗 Feed Sources"
    ])

    with feed_tabs[0]:
        fc1, fc2, fc3 = st.columns(3)
        max_per = fc1.slider("Articles per source", 5, 25, 10, key="news_max")
        filter_cat = fc2.multiselect(
            "Filter by crime type",
            options=list(CRIME_KEYWORDS.keys()),
            default=[],
            key="news_cat",
        )
        severity_filter = fc3.selectbox("Min severity", ["LOW","MEDIUM","HIGH"], index=0, key="news_sev")

        if st.button("📡 Fetch Latest News", type="primary", key="run_news"):
            with st.spinner("Fetching from all sources…"):
                articles = fetch_all_feeds(int(max_per))
                if df is not None and not df.empty:
                    articles = cross_reference_news_with_dataset(articles, df)
                st.session_state.news_articles = articles

            inv_hits = sum(1 for a in articles if a.get("in_investigation"))
            if inv_hits > 0:
                st.error(f"🚨 {inv_hits} articles mention addresses from your investigation dataset!")
            st.success(f"✅ Fetched {len(articles)} articles from {len(NEWS_FEEDS)} sources")

        articles = st.session_state.get("news_articles", [])
        if not articles:
            st.info("Click 'Fetch Latest News' to load the feed.")
        else:
            # Apply filters
            filtered = articles
            SEVERITY_ORDER = ["LOW","MEDIUM","HIGH"]
            min_sev_idx = SEVERITY_ORDER.index(severity_filter)
            filtered = [a for a in filtered
                        if SEVERITY_ORDER.index(a.get("severity","LOW")) >= min_sev_idx]
            if filter_cat:
                filtered = [a for a in filtered
                            if any(c in a.get("categories",[]) for c in filter_cat)]

            st.markdown(f"**{len(filtered)} articles** (filtered from {len(articles)} total)")
            for art in filtered[:30]:
                sev_icon = {"HIGH":"🔴","MEDIUM":"🟠","LOW":"🟢"}.get(art.get("severity","LOW"),"⚪")
                inv_flag = "🚨 **IN DATASET**" if art.get("in_investigation") else ""
                cats     = " · ".join(art.get("categories",[]))

                with st.expander(
                    f"{sev_icon} {art['source']} — {art['title'][:70]} {inv_flag}",
                    expanded=art.get("in_investigation", False)
                ):
                    st.markdown(f"**Date:** {art.get('date','')} | **Categories:** {cats or 'General'}")
                    if art.get("summary"):
                        st.caption(art["summary"])
                    if art.get("addresses"):
                        addr_count = sum(len(v) for v in art["addresses"].values())
                        st.markdown(f"**{addr_count} crypto addresses extracted:**")
                        for chain, addrs in art["addresses"].items():
                            for addr in addrs[:3]:
                                is_match = art.get("in_investigation") and any(
                                    m["address"].lower() == addr.lower()
                                    for m in art.get("dataset_matches",[])
                                )
                                prefix = "🚨 " if is_match else ""
                                st.code(f"{prefix}{chain}: {addr}")
                    st.markdown(f"[Read full article]({art.get('url','')})")

    with feed_tabs[1]:
        st.markdown("**🚨 Investigation Alerts**")
        st.caption("Articles mentioning addresses that appear in your investigation dataset.")
        articles = st.session_state.get("news_articles", [])
        inv_articles = [a for a in articles if a.get("in_investigation")]

        if not articles:
            st.info("Fetch news first using the Live Feed tab.")
        elif not inv_articles:
            st.success("✅ No news articles mention addresses from your investigation dataset.")
        else:
            st.error(f"🚨 {len(inv_articles)} articles reference addresses in your investigation!")
            for art in inv_articles:
                with st.expander(f"🔴 {art['title'][:80]}", expanded=True):
                    st.markdown(f"**Source:** {art['source']} | **Date:** {art['date']}")
                    for match in art.get("dataset_matches",[]):
                        st.error(f"Address in dataset: `{match['address']}` ({match['chain']})")
                    st.caption(art.get("summary",""))
                    st.markdown(f"[Read article]({art.get('url','')})")

    with feed_tabs[2]:
        st.markdown("**Search News for Specific Address**")
        search_addr = st.text_input("Address to search in news", key="news_search_addr",
                                     placeholder="0x… or Bitcoin address")
        articles = st.session_state.get("news_articles",[])
        if st.button("🔍 Search", key="run_news_search") and search_addr.strip():
            if not articles:
                st.warning("Fetch news first.")
            else:
                matches = search_articles_for_address(search_addr.strip(), articles)
                if matches:
                    st.warning(f"⚠️ Address found in {len(matches)} news articles!")
                    for art in matches:
                        with st.expander(f"📰 {art['title'][:70]}"):
                            st.markdown(f"**Source:** {art['source']} | **Date:** {art['date']}")
                            st.caption(art.get("summary",""))
                            st.markdown(f"[Read article]({art.get('url','')})")
                else:
                    st.success("✅ Address not found in any fetched articles.")

    with feed_tabs[3]:
        st.markdown("**Crime Trend Analysis**")
        articles = st.session_state.get("news_articles",[])
        if not articles:
            st.info("Fetch news first.")
        else:
            trends = analyze_crime_trends(articles)
            m1,m2,m3,m4 = st.columns(4)
            m1.metric("Total Articles",    trends["total_articles"])
            m2.metric("With Addresses",    trends["articles_with_addrs"])
            m3.metric("Dataset Hits",      trends["investigation_hits"])
            m4.metric("Top Crime Type",    trends["top_crime_type"])

            if trends["crime_categories"]:
                st.markdown("**Crime Category Distribution:**")
                cat_df = pd.DataFrame([
                    {"Category": k, "Articles": v}
                    for k,v in trends["crime_categories"].items()
                ]).sort_values("Articles", ascending=False)

                import plotly.express as px
                fig = px.bar(cat_df, x="Category", y="Articles",
                             color="Articles", color_continuous_scale="Reds",
                             height=300)
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", showlegend=False)
                st.plotly_chart(fig, use_container_width=True)

    with feed_tabs[4]:
        st.markdown("**Configured Feed Sources**")
        source_rows = [
            {
                "Source":   name,
                "Category": cfg["category"].title(),
                "Focus":    ", ".join(cfg["focus"][:4]),
                "URL":      cfg["url"][:60] + "…",
            }
            for name, cfg in NEWS_FEEDS.items()
        ]
        st.dataframe(pd.DataFrame(source_rows), use_container_width=True,
    hide_index=True,
    column_config={
        col: st.column_config.TextColumn(
            col,
            width="medium"
        )
        for col in df.columns
    }
)
        st.info(
            "💡 All feeds are free public RSS/Atom — no API keys required. "
            "Cache refreshes every 15 minutes. "
            "To add a custom feed, edit NEWS_FEEDS in forensics_newsfeed.py."
        )
