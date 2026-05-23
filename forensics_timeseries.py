"""
forensics_timeseries.py  —  Time-Series ML Anomaly Detection
Module-level functions (not instance methods) so @st.cache_data works correctly.
"""

import pandas as pd
import numpy as np
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


@st.cache_data(show_spinner=False)
def detect_adaptive_laundering(df: pd.DataFrame, windows: List[int] = None) -> List[Dict]:
    """
    Detect addresses slowly increasing transaction size/frequency over time.
    'Ramping' pattern: start small to avoid detection, escalate once trusted.
    """
    if windows is None:
        windows = [7, 14, 30]

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
    df = df.dropna(subset=["date"]).sort_values("date")

    findings = []

    for addr in df["from_address"].unique():
        addr_txs = df[df["from_address"] == addr].copy().sort_values("date")
        if len(addr_txs) < 10:
            continue

        for window_days in windows:
            freq = f"{window_days}D"
            addr_txs["period"] = addr_txs["date"].dt.to_period(freq)
            by_period = addr_txs.groupby("period").agg(
                volume=("amount", "sum"),
                avg_size=("amount", "mean"),
                count=("amount", "size"),
                tokens=("token", "nunique"),
            ).reset_index()

            if len(by_period) < 3:
                continue

            y = by_period["volume"].values
            X = np.arange(len(y))
            slope = float(np.polyfit(X, y, 1)[0])
            recent = float(y[-1])
            hist_mean = float(np.mean(y[:-1]))

            if slope > hist_mean * 0.1 and recent > hist_mean * 2 and hist_mean > 0:
                severity = min(100, int(
                    (recent / hist_mean) * 20 +
                    (slope / max(hist_mean, 1)) * 10 + 20
                ))
                findings.append({
                    "address":           addr,
                    "type":              "RAMPING_ATTACK",
                    "window_days":       window_days,
                    "slope":             round(slope, 2),
                    "recent_volume":     round(recent, 2),
                    "historical_mean":   round(hist_mean, 2),
                    "multiplier":        round(recent / max(hist_mean, 0.001), 1),
                    "severity":          severity,
                    "description":       f"Volume {round(recent/max(hist_mean,1),1)}× baseline over {window_days}d window",
                    "period_data":       by_period[["volume","count"]].to_dict("records"),
                })

    logger.info(f"✅ Ramping detection: {len(findings)} findings")
    return sorted(findings, key=lambda x: x["severity"], reverse=True)


@st.cache_data(show_spinner=False)
def detect_cyclical_patterns(df: pd.DataFrame) -> List[Dict]:
    """
    Detect addresses with suspiciously regular transaction timing.
    Bots and automated systems transact at precise intervals.
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
    df = df.dropna(subset=["date"])

    patterns = []

    for addr in df["from_address"].unique():
        addr_txs = df[df["from_address"] == addr].sort_values("date")
        if len(addr_txs) < 6:
            continue

        # Hour-of-day concentration
        hours = addr_txs["date"].dt.hour.value_counts()
        if len(hours) > 0 and hours.max() > hours.mean() * 3:
            peak = hours.idxmax()
            patterns.append({
                "address":       addr,
                "type":          "HOURLY_CYCLICAL",
                "peak_hour":     int(peak),
                "concentration": float(hours.max() / hours.sum()),
                "tx_count":      len(addr_txs),
                "severity":      min(100, int(hours.max() / max(hours.mean(), 1) * 10)),
                "description":   f"Sends {hours.max()} tx at hour {peak:02d}:00 UTC",
            })

        # Inter-transaction interval regularity
        if len(addr_txs) >= 8:
            gaps = addr_txs["date"].diff().dt.total_seconds().dropna()
            cv   = float(gaps.std() / max(gaps.mean(), 1))   # Coefficient of variation
            if cv < 0.15 and gaps.mean() < 3600:             # Very regular, under 1hr intervals
                patterns.append({
                    "address":       addr,
                    "type":          "BOT_REGULARITY",
                    "avg_interval_s": round(float(gaps.mean()), 1),
                    "cv":            round(cv, 3),
                    "tx_count":      len(addr_txs),
                    "severity":      min(100, int((1 - cv) * 80)),
                    "description":   f"Transactions every {gaps.mean()/60:.1f} min with {cv:.0%} variance — likely bot",
                })

    logger.info(f"✅ Cyclical patterns: {len(patterns)} found")
    return sorted(patterns, key=lambda x: x["severity"], reverse=True)


@st.cache_data(show_spinner=False)
def detect_dormant_reactivation(df: pd.DataFrame, dormant_days: int = 180) -> List[Dict]:
    """
    Find addresses that were dormant for >N days then suddenly active.
    Common in: seized-wallet reuse, long-term money hiding, exit scams.
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
    df = df.dropna(subset=["date"])

    findings = []
    for addr in df["from_address"].unique():
        addr_txs = df[df["from_address"] == addr].sort_values("date")
        if len(addr_txs) < 2:
            continue

        gaps = addr_txs["date"].diff().dt.days.dropna()
        big_gap_idx = gaps[gaps >= dormant_days]

        for idx in big_gap_idx.index:
            gap_days = float(gaps[idx])
            pre_vol  = addr_txs.loc[:idx-1, "amount"].sum()
            post_vol = addr_txs.loc[idx:, "amount"].sum()
            findings.append({
                "address":        addr,
                "type":           "DORMANT_REACTIVATION",
                "gap_days":       int(gap_days),
                "reactivation_date": str(addr_txs.loc[idx, "date"])[:10],
                "volume_before":  round(pre_vol, 2),
                "volume_after":   round(post_vol, 2),
                "volume_ratio":   round(post_vol / max(pre_vol, 0.001), 2),
                "severity":       min(100, int(gap_days / 10 + (post_vol > pre_vol * 5) * 30)),
                "description":    f"Dormant {int(gap_days)} days, reactivated with ${post_vol:,.0f} outflow",
            })

    logger.info(f"✅ Dormant reactivation: {len(findings)} found")
    return sorted(findings, key=lambda x: x["severity"], reverse=True)


def plot_address_timeline(df: pd.DataFrame, address: str) -> go.Figure:
    """Plot transaction volume over time for a single address."""
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
    addr_lower = address.lower()
    mask = (df["from_address"].str.lower() == addr_lower) | (df["to_address"].str.lower() == addr_lower)
    addr_df = df[mask].dropna(subset=["date"]).sort_values("date")

    if addr_df.empty:
        return None

    addr_df["direction"] = addr_df["from_address"].str.lower().apply(
        lambda x: "Outbound" if x == addr_lower else "Inbound"
    )
    fig = px.scatter(addr_df, x="date", y="amount", color="direction",
                     size="amount", size_max=30,
                     color_discrete_map={"Outbound": "#ff4444", "Inbound": "#22c55e"},
                     title=f"Transaction Timeline: {address[:20]}…",
                     hover_data=["token", "tx_hash"])
    fig.update_layout(height=380, paper_bgcolor="rgba(0,0,0,0)")
    return fig
