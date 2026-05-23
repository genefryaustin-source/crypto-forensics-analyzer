"""
forensics_alerts.py  —  Mobile & Push Alert System + Live Monitoring
Push channels: ntfy.sh (free, no account) · Pushover · Email (SMTP)
Monitoring: polling-based address watchlist via block explorer APIs
"""

import requests
import streamlit as st
import pandas as pd
import time
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# PUSH ALERT CHANNELS
# ─────────────────────────────────────────────────────────────

def send_ntfy_alert(
    topic: str,
    title: str,
    message: str,
    priority: str = "high",   # min / low / default / high / urgent
    tags: List[str] = None,
) -> bool:
    """
    Send push notification via ntfy.sh — completely free, no account needed.
    Install the ntfy app: https://ntfy.sh/app
    Subscribe to your topic in the app, then receive alerts here.
    """
    try:
        resp = requests.post(
            f"https://ntfy.sh/{topic}",
            data=message.encode("utf-8"),
            headers={
                "Title":    title,
                "Priority": priority,
                "Tags":     ",".join(tags or ["warning", "rotating_light"]),
            },
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"ntfy alert failed: {e}")
        return False


def send_pushover_alert(
    api_token: str,
    user_key: str,
    title: str,
    message: str,
    priority: int = 1,    # -2 to 2, 1 = high priority
    sound: str = "siren",
) -> bool:
    """
    Send push via Pushover (https://pushover.net) — $5 one-time app purchase.
    Excellent for iOS/Android with custom sounds and priorities.
    """
    try:
        resp = requests.post(
            "https://api.pushover.net/1/messages.json",
            json={
                "token":   api_token,
                "user":    user_key,
                "title":   title,
                "message": message,
                "priority": priority,
                "sound":   sound,
            },
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"Pushover alert failed: {e}")
        return False


def send_email_alert(
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    recipient: str,
    subject: str,
    body: str,
    use_tls: bool = True,
) -> bool:
    """Send alert email via SMTP (Gmail, Outlook, etc.)."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = username
        msg["To"]      = recipient
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if use_tls:
                server.starttls()
            server.login(username, password)
            server.sendmail(username, recipient, msg.as_string())
        return True
    except Exception as e:
        logger.error(f"Email alert failed: {e}")
        return False


def format_alert_message(findings: Dict, case_id: str = "") -> tuple:
    """Format a standardized alert title and body from findings."""
    crit    = findings.get("critical_count", 0)
    high    = findings.get("high_count", 0)
    vol     = findings.get("total_volume", 0)
    addr    = findings.get("flagged_address", "")

    if crit > 0:
        priority = "urgent"
        emoji    = "🔴"
    elif high > 0:
        priority = "high"
        emoji    = "🟠"
    else:
        priority = "default"
        emoji    = "🟡"

    title = f"{emoji} Forensics Alert{' — ' + case_id if case_id else ''}"
    body  = (
        f"CRITICAL flags: {crit}  HIGH flags: {high}\n"
        f"Volume: ${vol:,.2f}\n"
        f"Address: {addr[:30] if addr else 'multiple'}\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}"
    )
    return title, body, priority


# ─────────────────────────────────────────────────────────────
# ADDRESS WATCHLIST MONITOR  (polling-based, no WebSocket needed)
# ─────────────────────────────────────────────────────────────

WATCHLIST_FILE = "watchlist.json"

def load_watchlist() -> List[Dict]:
    try:
        return json.loads(open(WATCHLIST_FILE).read())
    except Exception:
        return []

def save_watchlist(wl: List[Dict]):
    open(WATCHLIST_FILE, "w").write(json.dumps(wl, indent=2))

def check_address_for_new_txs(
    address: str,
    chain: str,
    api_key: str,
    since_timestamp: int,
) -> List[Dict]:
    """Poll Etherscan/BscScan for new transactions since last check."""
    base = {
        "ethereum": "https://api.etherscan.io/v2/api",
        "bsc":      "https://api.etherscan.io/v2/api",
        "polygon":  "https://api.etherscan.io/v2/api",
    }.get(chain, "https://api.etherscan.io/v2/api")

    chain_ids = {"ethereum": 1, "bsc": 56, "polygon": 137, "avalanche": 43114}
    chain_id  = chain_ids.get(chain, 1)

    new_txs = []
    try:
        resp = requests.get(base, params={
            "chainid":  chain_id,
            "module":   "account",
            "action":   "txlist",
            "address":  address,
            "sort":     "desc",
            "offset":   20,
            "apikey":   api_key,
        }, timeout=15).json()

        if resp.get("status") == "1":
            for tx in resp.get("result", []):
                ts = int(tx.get("timeStamp", 0))
                if ts > since_timestamp:
                    new_txs.append({
                        "hash":       tx["hash"],
                        "from":       tx["from"],
                        "to":         tx.get("to",""),
                        "value_eth":  int(tx.get("value","0")) / 1e18,
                        "timestamp":  ts,
                        "date":       datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M"),
                    })
    except Exception as e:
        logger.warning(f"Watchlist poll error for {address}: {e}")

    return new_txs


def render_alerts_ui(get_key_fn=None):
    """Full alerts & monitoring UI."""
    st.markdown("### 🔔 Alerts & Live Monitoring")

    al_tab1, al_tab2, al_tab3 = st.tabs(["📱 Push Config", "👁️ Watchlist", "🔴 Live Monitor"])

    with al_tab1:
        st.markdown("**Configure push notification channels**")
        st.caption("ntfy.sh is free and requires no account — just install the app and subscribe to your topic.")

        with st.expander("📱 ntfy.sh (Free — Recommended)", expanded=True):
            ntfy_topic = st.text_input("Your ntfy topic (any unique string)",
                                        placeholder="my-forensics-alerts-xyz",
                                        key="ntfy_topic")
            st.markdown(f"📲 Subscribe in the ntfy app: `ntfy.sh/{ntfy_topic or 'your-topic'}`")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🧪 Test ntfy Alert") and ntfy_topic:
                    ok = send_ntfy_alert(ntfy_topic, "🧪 Test Alert",
                        "Crypto Forensics Analyzer is connected!", "default", ["white_check_mark"])
                    st.success("✅ Alert sent!") if ok else st.error("❌ Failed — check topic name")
            with col2:
                st.markdown("[📥 Get ntfy app](https://ntfy.sh/app)")

        with st.expander("📳 Pushover"):
            po_token = st.text_input("API Token", type="password", key="po_token")
            po_user  = st.text_input("User Key",  type="password", key="po_user")
            if st.button("🧪 Test Pushover") and po_token and po_user:
                ok = send_pushover_alert(po_token, po_user, "🧪 Test",
                    "Crypto Forensics connected!", 1, "siren")
                st.success("✅ Sent!") if ok else st.error("❌ Failed")

        with st.expander("📧 Email (SMTP)"):
            em_host = st.text_input("SMTP Host", value="smtp.gmail.com", key="em_host")
            em_port = st.number_input("Port", value=587, key="em_port")
            em_user = st.text_input("Username (your email)", key="em_user")
            em_pass = st.text_input("Password / App Password", type="password", key="em_pass")
            em_to   = st.text_input("Recipient email", key="em_to")
            if st.button("🧪 Test Email") and all([em_host, em_user, em_pass, em_to]):
                ok = send_email_alert(em_host, int(em_port), em_user, em_pass, em_to,
                    "🧪 Forensics Test", "Crypto Forensics Analyzer email alerts active.")
                st.success("✅ Email sent!") if ok else st.error("❌ Failed — check credentials")

        # Risk threshold for alerts
        st.markdown("**Alert Thresholds**")
        t1, t2 = st.columns(2)
        min_risk_score = t1.slider("Min risk score to alert", 0, 100, 75, key="alert_threshold")
        min_vol_alert  = t2.number_input("Min transaction value ($)", 0.0, step=1000.0, key="alert_min_vol")
        st.caption(f"Alerts will fire for transactions with risk score ≥ {min_risk_score} and value ≥ ${min_vol_alert:,.0f}")

    with al_tab2:
        st.markdown("**Address Watchlist — monitor specific addresses for new activity**")
        wl = load_watchlist()

        # Add to watchlist
        wl1, wl2, wl3 = st.columns([3,2,1])
        new_addr  = wl1.text_input("Address to watch", key="wl_addr")
        new_chain = wl2.selectbox("Chain", ["ethereum","bsc","polygon","tron","bitcoin"], key="wl_chain")
        new_label = wl1.text_input("Label / note", key="wl_label", placeholder="e.g. Suspect wallet #1")
        if wl3.button("➕ Add", key="add_wl") and new_addr.strip():
            wl.append({
                "address":    new_addr.strip(),
                "chain":      new_chain,
                "label":      new_label,
                "added":      str(datetime.now())[:19],
                "last_check": int(datetime.now().timestamp()),
            })
            save_watchlist(wl)
            st.success("Added to watchlist")
            st.rerun()

        if wl:
            wl_df = pd.DataFrame(wl)
            st.dataframe(wl_df[["address","chain","label","added"]],
                         width='stretch', hide_index=True)
            if st.button("🗑️ Clear Watchlist", key="clear_wl"):
                save_watchlist([])
                st.rerun()
        else:
            st.info("No addresses on watchlist yet.")

    with al_tab3:
        st.markdown("**Live polling monitor** — checks watchlist addresses every N seconds")
        wl = load_watchlist()

        if not wl:
            st.warning("Add addresses to the watchlist first.")
        else:
            poll_sec = st.slider("Poll interval (seconds)", 15, 300, 60, key="poll_interval")
            api_key  = (get_key_fn("etherscan_key") if get_key_fn else "") or ""
            ntfy_t   = st.session_state.get("ntfy_topic","")

            st.markdown(f"Monitoring **{len(wl)}** address(es) · Poll every **{poll_sec}s**")

            if not api_key:
                st.warning("⚠️ No Etherscan API key — add it in API Key Management.")

            if st.button("▶ Start Monitoring", type="primary", key="start_monitor",
                         disabled=not bool(api_key)):
                monitor_box = st.empty()
                alert_log   = st.empty()
                log_entries = []
                stop_btn    = st.button("⏹ Stop", key="stop_monitor")

                for cycle in range(1, 1000):
                    if stop_btn:
                        break
                    results = []
                    for item in wl:
                        new_txs = check_address_for_new_txs(
                            item["address"], item["chain"],
                            api_key, item.get("last_check", 0)
                        )
                        if new_txs:
                            item["last_check"] = int(datetime.now().timestamp())
                            for tx in new_txs:
                                entry = {
                                    "time":    datetime.now().strftime("%H:%M:%S"),
                                    "label":   item.get("label", item["address"][:16]),
                                    "hash":    tx["hash"][:20]+"…",
                                    "value":   f"{tx['value_eth']:.4f}",
                                    "from":    tx["from"][:16]+"…",
                                }
                                log_entries.insert(0, entry)
                                if ntfy_t:
                                    send_ntfy_alert(ntfy_t,
                                        f"🔴 New TX: {item.get('label','')}",
                                        f"Hash: {tx['hash'][:20]}\nValue: {tx['value_eth']:.4f} ETH",
                                        "high", ["rotating_light"])

                    save_watchlist(wl)
                    monitor_box.markdown(
                        f"**Cycle {cycle}** · {datetime.now().strftime('%H:%M:%S')} · "
                        f"Next check in {poll_sec}s"
                    )
                    if log_entries:
                        alert_log.dataframe(pd.DataFrame(log_entries[:20]),
                                            width='stretch', hide_index=True)
                    time.sleep(poll_sec)
