"""
forensics_global_sanctions.py — Crypto Forensics Analyzer Pro v5.0

Global sanctions and financial-crime wallet screening.

Adds multi-jurisdiction screening beyond OFAC:
- OFAC / U.S. Treasury
- European Union consolidated financial sanctions data
- UK Sanctions List / OFSI-era data sources when available
- United Nations Security Council consolidated sanctions list
- OpenSanctions address/entity search

Design goals:
- Safe for Streamlit Cloud
- No required API keys
- Graceful degradation if a public source is unavailable
- Does not mutate unrelated app state
- Normalized output dataframe for UI, reporting, and compliance workflows
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote_plus

import pandas as pd
import requests
import streamlit as st

logger = logging.getLogger(__name__)

CACHE_PATH = Path("global_sanctions_cache.json")
LOOKUP_CACHE_PATH = Path("global_sanctions_lookup_cache.json")
CACHE_TTL_HOURS = 24

# These are public endpoints/search pages. Some providers change URLs; failures are
# deliberately non-fatal so the OSINT panel can keep working.
GLOBAL_SANCTIONS_SOURCES: Dict[str, Dict[str, str]] = {
    "OFAC_ADVANCED": {
        "label": "OFAC SDN Advanced XML",
        "jurisdiction": "US",
        "authority": "U.S. Treasury OFAC",
        "url": "https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml",
        "risk_level": "CRITICAL",
    },
    "EU_CONSOLIDATED": {
        "label": "EU Consolidated Financial Sanctions",
        "jurisdiction": "EU",
        "authority": "European Union",
        "url": "https://webgate.ec.europa.eu/europeaid/fsd/fsf/public/files/xmlFullSanctionsList/content?token=dG9rZW4tMjAxNw",
        "risk_level": "CRITICAL",
    },
    "UN_CONSOLIDATED": {
        "label": "UN Security Council Consolidated List",
        "jurisdiction": "UN",
        "authority": "United Nations Security Council",
        "url": "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
        "risk_level": "HIGH",
    },
    # UK now uses the UK Sanctions List as the current list. This endpoint may
    # change; OpenSanctions is also used as a resilient aggregator for UK-linked data.
    "UK_SANCTIONS_LIST": {
        "label": "UK Sanctions List",
        "jurisdiction": "UK",
        "authority": "UK FCDO / HMT",
        "url": "https://assets.publishing.service.gov.uk/media/681ca8e99c45845ea8cbf11c/UK_Sanctions_List.ods",
        "risk_level": "CRITICAL",
    },
}

CRYPTO_ADDRESS_PATTERN = re.compile(
    r"(0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{20,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,40}|T[A-Za-z0-9]{25,40})"
)


def _now_ts() -> float:
    return time.time()


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, data: Any) -> None:
    try:
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    except Exception as exc:
        logger.warning("Unable to write sanctions cache %s: %s", path, exc)


def normalize_address(value: Any) -> str:
    return str(value or "").strip().lower()


def extract_unique_addresses(df: pd.DataFrame) -> List[str]:
    if df is None or not isinstance(df, pd.DataFrame) or df.empty:
        return []

    addresses: Set[str] = set()
    for col in ["from_address", "to_address", "address", "wallet", "counterparty"]:
        if col in df.columns:
            for v in df[col].dropna().astype(str).tolist():
                s = v.strip()
                if s and s.lower() not in {"unknown", "nan", "none", "null"}:
                    addresses.add(s)

    return sorted(addresses)


def _extract_context(text: str, needle: str, radius: int = 180) -> str:
    if not text or not needle:
        return ""
    lower = text.lower()
    idx = lower.find(needle.lower())
    if idx < 0:
        return ""
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    return re.sub(r"\s+", " ", text[start:end]).strip()


@st.cache_data(ttl=CACHE_TTL_HOURS * 3600, show_spinner=False)
def fetch_global_source_text(source_key: str) -> Dict[str, Any]:
    meta = GLOBAL_SANCTIONS_SOURCES.get(source_key)
    if not meta:
        return {"ok": False, "error": f"Unknown source {source_key}"}

    try:
        resp = requests.get(meta["url"], timeout=45)
        ok = 200 <= resp.status_code < 300
        content_type = resp.headers.get("content-type", "")

        # ODS/binary files are not useful for direct substring scan in this light engine.
        # We keep status metadata but skip raw binary payload storage.
        is_binary = "spreadsheet" in content_type or meta["url"].lower().endswith(".ods")
        text = "" if is_binary else resp.text

        return {
            "ok": ok,
            "status_code": resp.status_code,
            "source_key": source_key,
            "label": meta["label"],
            "jurisdiction": meta["jurisdiction"],
            "authority": meta["authority"],
            "risk_level": meta["risk_level"],
            "url": meta["url"],
            "content_type": content_type,
            "text": text,
            "fetched_at": datetime.utcnow().isoformat(),
            "note": "Binary source skipped for direct text scan" if is_binary else "",
        }
    except Exception as exc:
        return {
            "ok": False,
            "source_key": source_key,
            "label": meta["label"],
            "jurisdiction": meta["jurisdiction"],
            "authority": meta["authority"],
            "risk_level": meta["risk_level"],
            "url": meta["url"],
            "error": str(exc),
            "fetched_at": datetime.utcnow().isoformat(),
        }


def fetch_all_global_sources(force_refresh: bool = False) -> Dict[str, Any]:
    if force_refresh:
        fetch_global_source_text.clear()

    sources = {}
    for key in GLOBAL_SANCTIONS_SOURCES:
        sources[key] = fetch_global_source_text(key)

    payload = {
        "cached_at": datetime.utcnow().isoformat(),
        "sources": sources,
    }
    _write_json(CACHE_PATH, payload)
    return payload


def _load_lookup_cache() -> Dict[str, Any]:
    cache = _read_json(LOOKUP_CACHE_PATH, {})
    if not isinstance(cache, dict):
        return {}
    return cache


def _save_lookup_cache(cache: Dict[str, Any]) -> None:
    _write_json(LOOKUP_CACHE_PATH, cache)


def query_opensanctions_address(address: str) -> List[Dict[str, Any]]:
    """Best-effort OpenSanctions public search for a single crypto address."""
    addr = normalize_address(address)
    if not addr:
        return []

    cache = _load_lookup_cache()
    cached = cache.get(addr)
    if cached and _now_ts() - cached.get("ts", 0) < CACHE_TTL_HOURS * 3600:
        return cached.get("matches", [])

    matches: List[Dict[str, Any]] = []
    try:
        # OpenSanctions search endpoint may rate-limit or change; failure is non-fatal.
        url = f"https://api.opensanctions.org/search/default?limit=5&q={quote_plus(addr)}"
        resp = requests.get(url, timeout=20)
        if 200 <= resp.status_code < 300:
            data = resp.json()
            for result in data.get("results", []):
                ent = result.get("entity", result)
                props = ent.get("properties", {}) if isinstance(ent, dict) else {}
                caption = ent.get("caption") or ent.get("name") or "OpenSanctions entity"
                datasets = ent.get("datasets") or result.get("datasets") or []
                matches.append({
                    "address": addr,
                    "source": "OpenSanctions",
                    "jurisdiction": "GLOBAL",
                    "authority": "OpenSanctions",
                    "entity_name": caption,
                    "program": ", ".join(datasets[:5]) if isinstance(datasets, list) else str(datasets),
                    "risk_level": "HIGH",
                    "match_type": "OpenSanctions search",
                    "confidence": 80,
                    "details": json.dumps(props)[:500] if props else "",
                })
    except Exception as exc:
        logger.info("OpenSanctions lookup failed for %s: %s", addr, exc)

    cache[addr] = {"ts": _now_ts(), "matches": matches}
    _save_lookup_cache(cache)
    return matches


def screen_addresses_global(
    addresses: Iterable[str],
    include_opensanctions_api: bool = False,
    max_opensanctions_queries: int = 100,
    force_refresh: bool = False,
) -> pd.DataFrame:
    addresses_norm = [normalize_address(a) for a in addresses if normalize_address(a)]
    addresses_norm = sorted(set(addresses_norm))

    source_payload = fetch_all_global_sources(force_refresh=force_refresh)
    rows: List[Dict[str, Any]] = []

    for source_key, source in source_payload.get("sources", {}).items():
        text = str(source.get("text", ""))
        if not source.get("ok") or not text:
            continue
        lower_text = text.lower()
        for addr in addresses_norm:
            if addr in lower_text:
                rows.append({
                    "address": addr,
                    "source": source.get("label", source_key),
                    "jurisdiction": source.get("jurisdiction", ""),
                    "authority": source.get("authority", ""),
                    "entity_name": "",
                    "program": "",
                    "risk_level": source.get("risk_level", "HIGH"),
                    "match_type": "Direct crypto address match",
                    "confidence": 95 if source.get("jurisdiction") in {"US", "EU", "UK"} else 85,
                    "details": _extract_context(text, addr),
                })

    if include_opensanctions_api:
        for addr in addresses_norm[:max_opensanctions_queries]:
            rows.extend(query_opensanctions_address(addr))

    if not rows:
        return pd.DataFrame(columns=[
            "address", "source", "jurisdiction", "authority", "entity_name",
            "program", "risk_level", "match_type", "confidence", "details",
        ])

    out = pd.DataFrame(rows).drop_duplicates(
        subset=["address", "source", "jurisdiction", "match_type"],
        keep="first",
    )
    return out.sort_values(["risk_level", "source", "address"], ascending=[True, True, True])


def apply_global_sanctions_to_transactions(df: pd.DataFrame, matches: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in ["from_address", "to_address"]:
        if col not in out.columns:
            out[col] = ""
        out[col] = out[col].fillna("").astype(str).str.strip()

    out["global_sanctions_hit"] = False
    out["global_sanctions_sources"] = ""
    out["global_sanctions_jurisdictions"] = ""
    out["global_sanctions_risk"] = ""

    if matches is None or matches.empty:
        return out

    match_map: Dict[str, Dict[str, Set[str]]] = {}
    for _, row in matches.iterrows():
        addr = normalize_address(row.get("address", ""))
        if not addr:
            continue
        bucket = match_map.setdefault(addr, {"sources": set(), "jurisdictions": set(), "risk": set()})
        bucket["sources"].add(str(row.get("source", "")))
        bucket["jurisdictions"].add(str(row.get("jurisdiction", "")))
        bucket["risk"].add(str(row.get("risk_level", "HIGH")))

    from_l = out["from_address"].astype(str).str.lower()
    to_l = out["to_address"].astype(str).str.lower()
    hit_mask = from_l.isin(match_map.keys()) | to_l.isin(match_map.keys())
    out["global_sanctions_hit"] = hit_mask

    def _joined_for_row(row, key: str) -> str:
        vals: Set[str] = set()
        for addr in [normalize_address(row.get("from_address")), normalize_address(row.get("to_address"))]:
            vals.update(match_map.get(addr, {}).get(key, set()))
        return ", ".join(sorted(v for v in vals if v))

    if hit_mask.any():
        out.loc[hit_mask, "global_sanctions_sources"] = out[hit_mask].apply(lambda r: _joined_for_row(r, "sources"), axis=1)
        out.loc[hit_mask, "global_sanctions_jurisdictions"] = out[hit_mask].apply(lambda r: _joined_for_row(r, "jurisdictions"), axis=1)
        out.loc[hit_mask, "global_sanctions_risk"] = out[hit_mask].apply(lambda r: _joined_for_row(r, "risk"), axis=1)

    return out


def render_global_sanctions_ui(df: pd.DataFrame) -> None:
    st.markdown("### 🌍 Global Sanctions & Financial Crime Screening")
    st.caption(
        "Screens wallet addresses against U.S. OFAC, EU, UK, UN, and OpenSanctions-style global watchlist intelligence. "
        "Public sources change over time, so unavailable feeds are skipped safely."
    )

    with st.expander("Sources covered", expanded=False):
        st.markdown(
            "- **OFAC / U.S. Treasury** — SDN advanced sanctions data\n"
            "- **EU Consolidated Financial Sanctions** — EU asset-freeze screening\n"
            "- **UK Sanctions List / OFSI transition** — UK sanctions screening when source is reachable\n"
            "- **UN Security Council Consolidated List** — terrorism/proliferation/global sanctions\n"
            "- **OpenSanctions** — optional address/entity search aggregator"
        )

    addresses = extract_unique_addresses(df)
    c1, c2, c3 = st.columns(3)
    c1.metric("Unique addresses", f"{len(addresses):,}")
    include_open = c2.checkbox("OpenSanctions API search", value=False, help="Optional best-effort per-address search. Use with a limited batch size.")
    max_open = c3.number_input("Max OpenSanctions lookups", min_value=10, max_value=1000, value=100, step=10)

    force_refresh = st.checkbox("Force refresh public-source cache", value=False)

    if st.button("🌍 Run Global Sanctions Screening", type="primary", use_container_width=True, key="run_global_sanctions"):
        with st.spinner("Screening global sanctions and watchlist sources…"):
            matches = screen_addresses_global(
                addresses,
                include_opensanctions_api=include_open,
                max_opensanctions_queries=int(max_open),
                force_refresh=force_refresh,
            )
            screened = apply_global_sanctions_to_transactions(df, matches)
            st.session_state.global_sanctions_matches = matches
            st.session_state.global_sanctions_df = screened

        if matches.empty:
            st.success("✅ No global sanctions/watchlist address matches found.")
        else:
            st.error(f"🚨 {len(matches):,} global sanctions/watchlist address matches detected.")

    matches = st.session_state.get("global_sanctions_matches")
    screened = st.session_state.get("global_sanctions_df")

    if isinstance(matches, pd.DataFrame):
        if matches.empty:
            st.success("No global sanctions/watchlist matches in current dataset.")
        else:
            s1, s2, s3 = st.columns(3)
            s1.metric("Matches", len(matches))
            s2.metric("Jurisdictions", matches["jurisdiction"].nunique() if "jurisdiction" in matches else 0)
            s3.metric("Sources", matches["source"].nunique() if "source" in matches else 0)

            show = [c for c in [
                "address", "source", "jurisdiction", "authority", "entity_name",
                "program", "risk_level", "match_type", "confidence", "details",
            ] if c in matches.columns]
            st.dataframe(matches[show], use_container_width=True, hide_index=True)
            st.download_button(
                "⬇️ Export Global Sanctions Matches CSV",
                matches[show].to_csv(index=False).encode(),
                "global_sanctions_matches.csv",
                "text/csv",
            )

    if isinstance(screened, pd.DataFrame) and "global_sanctions_hit" in screened.columns:
        hits = screened[screened["global_sanctions_hit"] == True]
        if not hits.empty:
            st.markdown("**Transactions touching matched addresses**")
            show_tx = [c for c in [
                "date", "from_address", "to_address", "amount", "token", "risk_level",
                "global_sanctions_sources", "global_sanctions_jurisdictions", "global_sanctions_risk",
            ] if c in hits.columns]
            st.dataframe(hits[show_tx].head(500), use_container_width=True, hide_index=True)
