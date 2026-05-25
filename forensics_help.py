"""
forensics_help.py — Crypto Forensics Analyzer Pro v5.0
Interactive Help & Documentation:
  Full step-by-step guide rendered as an in-app help page.
  Also exports render_sidebar_help() for the mini sidebar widget.
"""

import streamlit as st
from datetime import datetime


# ─────────────────────────────────────────────────────────────
# SIDEBAR MINI HELP — shown at the bottom of every page
# ─────────────────────────────────────────────────────────────

def render_sidebar_help():
    """
    Compact help widget shown at the bottom of the sidebar.
    Quick-access links to the most important guidance.
    """
    with st.sidebar.expander("❓ Quick Help", expanded=False):
        st.markdown("""
**New here? Start with:**
1. ⚙️ **Settings** → add your API keys
2. Upload a **CSV file** or click **Load Sample Data**
3. Go to **📊 Overview** to see your data
4. Run **🔴 OFAC Screening** in OSINT Intelligence
5. Run **🧩 Pattern Intel** to find suspicious patterns

**CSV must have these columns:**
`date, from_address, to_address, amount, token`

**Full help:** [📖 Help & Guide](#) in the nav

**Support:** Check the ⚙️ Settings page for API key status
""")


# ─────────────────────────────────────────────────────────────
# FULL HELP PAGE
# ─────────────────────────────────────────────────────────────

def render_help_ui():
    """Full help and documentation page."""

    st.markdown("""
<style>
.help-hero {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 32px;
    margin-bottom: 24px;
    text-align: center;
}
.help-step {
    background: #1e293b;
    border-left: 4px solid #3b82f6;
    border-radius: 0 8px 8px 0;
    padding: 16px 20px;
    margin: 8px 0;
}
.help-step-critical {
    border-left-color: #ef4444;
}
.help-step-success {
    border-left-color: #22c55e;
}
.help-step-warning {
    border-left-color: #f59e0b;
}
.feature-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 16px;
    margin: 6px 0;
}
.kbd {
    background: #334155;
    border: 1px solid #475569;
    border-radius: 4px;
    padding: 2px 6px;
    font-family: monospace;
    font-size: 12px;
}
</style>

<div class="help-hero">
    <h1 style="margin:0;font-size:28px;font-weight:800;color:white">
        🔍 Crypto Forensics Analyzer Pro
    </h1>
    <p style="margin:8px 0 0;color:#94a3b8;font-size:16px">
        v5.0 · Complete Help & Investigation Guide
    </p>
</div>
""", unsafe_allow_html=True)

    help_tabs = st.tabs([
        "🚀 Getting Started",
        "📂 Loading Data",
        "🔍 Investigation Workflow",
        "🗂️ All Features",
        "🔑 API Keys",
        "⚠️ Troubleshooting",
        "📋 Quick Reference",
    ])

    # ══════════════════════════════════════════════════════════
    # TAB 1 — GETTING STARTED
    # ══════════════════════════════════════════════════════════
    with help_tabs[0]:
        st.markdown("## 🚀 Getting Started")

        st.info(
            "**Crypto Forensics Analyzer Pro** is a blockchain investigation platform "
            "that combines on-chain data, threat intelligence, compliance tools, and AI "
            "into a single investigative workflow. No coding required."
        )

        st.markdown("### What this tool does")
        col1, col2, col3 = st.columns(3)
        col1.success(
            "**🔍 Investigate**\n\n"
            "Trace funds across Bitcoin, Ethereum, BSC, Polygon, Tron, and Solana. "
            "Follow the money through mixers, bridges, and exchanges."
        )
        col2.warning(
            "**⚠️ Detect**\n\n"
            "Automatically flag OFAC sanctions hits, ransomware addresses, "
            "structuring, pig butchering, DPRK patterns, and 30+ other indicators."
        )
        col3.error(
            "**📋 Report**\n\n"
            "Generate FinCEN SARs, INTERPOL Purple Notices, Maltego exports, "
            "i2 ANB charts, Cellebrite CSVs, and full PDF investigation reports."
        )

        st.markdown("---")
        st.markdown("### First-time setup checklist")

        st.markdown("""
<div class="help-step help-step-critical">
<strong>Step 1 — Add API keys to secrets.toml</strong><br>
Go to <strong>⚙️ Settings</strong> in the sidebar, or create <code>.streamlit/secrets.toml</code> in your app folder.<br>
At minimum add your <strong>Etherscan key</strong> (free) for on-chain data.
</div>

<div class="help-step">
<strong>Step 2 — Load sample data to explore the interface</strong><br>
Click <strong>Load Sample Data (BSC/DeFi)</strong> or <strong>Load Sample Data (Bitcoin)</strong>
in the sidebar. This lets you explore every feature without needing your own data.
</div>

<div class="help-step">
<strong>Step 3 — Understand the navigation</strong><br>
The left sidebar has groups (Analysis, Intelligence, OSINT, etc.).<br>
Each group contains pages. Click any button to navigate to that page.
</div>

<div class="help-step help-step-success">
<strong>Step 4 — Run your first investigation</strong><br>
Load your CSV → 📊 Overview → 🔴 OFAC Screening → 🧩 Pattern Intel → 👤 Suspect Profile
</div>
""", unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("### Interface overview")
        st.image(
            "https://placehold.co/800x300/0f172a/3b82f6?text=Sidebar+Navigation+|+Main+Content+Area+|+Tabs",
            caption="Layout: Sidebar navigation on left, main content on right with tabbed sub-pages",
        )
        st.markdown("""
- **Sidebar** — Navigation groups and buttons. Also shows data status (transactions loaded, risk counts)
- **Main area** — Page content. Most pages have multiple sub-tabs
- **Session state** — Analysis results are kept in memory while the app runs. Changing pages does NOT lose your results
- **Streamlit rerun** — If the app seems stuck, press **R** to rerun, or use the hamburger menu → Rerun
""")

    # ══════════════════════════════════════════════════════════
    # TAB 2 — LOADING DATA
    # ══════════════════════════════════════════════════════════
    with help_tabs[1]:
        st.markdown("## 📂 Loading Data")

        st.markdown("### Option A — Upload a CSV file")
        st.markdown(
            "Use the **Upload Transaction CSV** button in the sidebar. "
            "The file must have these columns:"
        )

        required_df_data = {
            "Column":      ["date", "from_address", "to_address", "amount", "token"],
            "Required":    ["✅ Yes", "✅ Yes", "✅ Yes", "✅ Yes", "✅ Yes"],
            "Format":      [
                "YYYY-MM-DD or datetime string",
                "Any crypto address format",
                "Any crypto address format",
                "Numeric (USD value or token amount)",
                "Token symbol e.g. ETH, USDT, BTC",
            ],
            "Example":     [
                "2024-01-15",
                "0x1234…abcd",
                "0x5678…ef01",
                "9500.00",
                "USDT",
            ],
        }
        import pandas as pd
        st.dataframe(pd.DataFrame(required_df_data), width='stretch', hide_index=True)

        st.markdown("**Optional columns** (add these to unlock more features):")
        optional_df_data = {
            "Column":   ["tx_hash", "chain", "gas_price", "block_number", "risk_level"],
            "Unlocks":  [
                "Transaction deep-dive, Boltzmann analysis",
                "Multi-chain filtering and Sankey flow",
                "Infrastructure clustering fingerprint",
                "Timing analysis and MEV detection",
                "Pre-scored data (CRITICAL/HIGH/MEDIUM/LOW)",
            ],
        }
        st.dataframe(pd.DataFrame(optional_df_data), width='stretch', hide_index=True)

        st.markdown("---")
        st.markdown("### Option B — Load from blockchain API")
        st.markdown("""
Use the **On-chain** section in the sidebar to fetch live data directly from blockchains.
You need API keys configured in ⚙️ Settings first.

- **Etherscan** → Ethereum, BSC, Polygon transactions
- **Blockchain.com / BlockCypher** → Bitcoin transactions
- **TronScan** → Tron TRC-20 transactions
- **Solana RPC** → SPL token transactions
""")

        st.markdown("---")
        st.markdown("### Option C — Sample data (no setup needed)")
        st.markdown("""
Click either sample data button in the sidebar to load pre-built demonstration datasets:
- **BSC/DeFi sample** — DEX swaps, token transfers, DeFi interactions with embedded risk patterns
- **Bitcoin sample** — BTC transactions with structuring and mixer patterns
        
These are safe to explore and demonstrate every feature without real data.
""")

        st.markdown("---")
        st.markdown("### CSV example")
        example_csv = """date,from_address,to_address,amount,token,chain,tx_hash
2024-01-15 14:32:11,0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b,0x7f367cc41522ce07553e823bf3be79a889debe1b,9500.00,USDT,ethereum,0xabc123...
2024-01-15 14:45:00,0x7f367cc41522ce07553e823bf3be79a889debe1b,0x910cbd523d972eb0a6f4cae4618ad62622b39dbf,9450.00,USDT,ethereum,0xdef456...
2024-01-15 15:01:33,0x910cbd523d972eb0a6f4cae4618ad62622b39dbf,0x1a1zp1ep5qgefi2dmpTftl5slmv7divfna,9400.00,BTC,bitcoin,0xghi789..."""
        st.code(example_csv, language="csv")

    # ══════════════════════════════════════════════════════════
    # TAB 3 — INVESTIGATION WORKFLOW
    # ══════════════════════════════════════════════════════════
    with help_tabs[2]:
        st.markdown("## 🔍 Step-by-Step Investigation Workflow")

        st.markdown(
            "Follow these steps in order for a complete investigation. "
            "Each step builds on the last. Results from earlier steps automatically feed into later ones."
        )

        steps = [
            {
                "num": "01",
                "icon": "📂",
                "title": "Load your transaction data",
                "page": "Sidebar → Upload CSV or Load Sample Data",
                "what": "Get your data into the tool. The sidebar will show transaction count and risk summary once loaded.",
                "tips": [
                    "Make sure date, from_address, to_address, amount, token columns exist",
                    "The tool handles up to 100,000+ transactions — larger files may be slower",
                    "Save your CSV with UTF-8 encoding to avoid character errors",
                ],
                "color": "#3b82f6",
            },
            {
                "num": "02",
                "icon": "📊",
                "title": "Review the Overview",
                "page": "Analysis → Overview",
                "what": "Get the big picture. See transaction volume, risk distribution, top addresses, and chain breakdown before diving deeper.",
                "tips": [
                    "Check the CRITICAL and HIGH risk counts at the top — these are your priority addresses",
                    "The timeline chart shows when suspicious activity peaked",
                    "Use the address table to identify which addresses appear most frequently",
                ],
                "color": "#3b82f6",
            },
            {
                "num": "03",
                "icon": "🔴",
                "title": "Run OFAC + Ransomware screening",
                "page": "OSINT → OSINT Intelligence → OFAC Screening tab, then Ransomwhere tab",
                "what": "Check every address against the US Treasury sanctions list and three ransomware databases. These are mandatory for any compliance-related investigation.",
                "tips": [
                    "OFAC hit = immediate mandatory reporting obligation under 31 CFR Part 501",
                    "Ransomware screening covers Ransomwhere.co, Abuse.ch ThreatFox, and CISA advisories simultaneously",
                    "Results are saved in session state — the SAR auto-generator will include them automatically",
                ],
                "color": "#ef4444",
            },
            {
                "num": "04",
                "icon": "🧩",
                "title": "Detect patterns",
                "page": "Intelligence → Pattern Intel",
                "what": "Run all 8 pattern detectors: structuring, velocity, circular flows, mixer behavior, peeling chains, cross-chain movement, stablecoin analysis, and behavioral anomalies.",
                "tips": [
                    "Click 'Run All Pattern Analysis' to run everything at once",
                    "Structuring = transactions kept deliberately below $10,000 reporting thresholds",
                    "Peeling chains = ransomware cashout signature — funds passed through many small hops",
                    "Pattern results feed automatically into the auto-SAR generator",
                ],
                "color": "#8b5cf6",
            },
            {
                "num": "05",
                "icon": "🔗",
                "title": "Trace fund flows",
                "page": "Intelligence → Multi-hop Tracer",
                "what": "Follow money forward or backward through multiple hops. Essential for finding where funds originated or where they ended up.",
                "tips": [
                    "Use 'Both Directions' to trace simultaneously forward and backward",
                    "Increase hop depth to 5+ for complex laundering chains",
                    "Look for exchange endpoints — these are your subpoena targets",
                    "The Sankey Flow chart (Analysis → Sankey Flow) visualizes the entire path",
                ],
                "color": "#3b82f6",
            },
            {
                "num": "06",
                "icon": "🏷️",
                "title": "Screen addresses with intelligence sources",
                "page": "Address Intel → Address Intelligence",
                "what": "Run the 5-source intel screen covering GoPlus (30M+ addresses), USDC/USDT frozen lists, Hop Protocol sanctions, and CryptoScamDB.",
                "tips": [
                    "USDC/USDT frozen = Circle or Tether has blacklisted the address at the contract level",
                    "GoPlus covers Ethereum, BSC, Polygon, Avalanche, Arbitrum, Optimism, Tron, Solana",
                    "Check the Exchange Endpoints tab — exchange-linked addresses are your KYC leads",
                ],
                "color": "#f59e0b",
            },
            {
                "num": "07",
                "icon": "🎯",
                "title": "Run threat intelligence",
                "page": "Market Intel → Threat Intel",
                "what": "Detect pig butchering scams, DPRK/Lazarus Group signatures, P2P exchange usage, and crypto ATM activity.",
                "tips": [
                    "DPRK hit = national security matter requiring immediate LE escalation",
                    "Pig butchering = victim makes escalating payments over weeks — look for 1.5× or more escalation ratio",
                    "Crypto ATM transactions: operators must be subpoenaed — US FinCEN requires ID for >$900",
                ],
                "color": "#ef4444",
            },
            {
                "num": "08",
                "icon": "👤",
                "title": "Build suspect profiles",
                "page": "Profiles → Suspect Profile",
                "what": "Enter any address to generate a 360° profile that aggregates all intelligence gathered in steps 3–7 into one view with legal process recommendations.",
                "tips": [
                    "The profile only shows results from analyses already run — do steps 3–7 first",
                    "The Legal Actions tab shows IMMEDIATE / HIGH / MEDIUM priority actions with specific legal authorities",
                    "Export the profile as JSON for inclusion in case files",
                ],
                "color": "#22c55e",
            },
            {
                "num": "09",
                "icon": "📋",
                "title": "Document off-chain evidence",
                "page": "Regulatory → Case Dashboard",
                "what": "Create a case record and attach off-chain payment evidence (Zelle, PayPal, CashApp, Venmo, wire transfers). Upload screenshots as evidence. Search CFPB and BBB for fraud complaints.",
                "tips": [
                    "Every off-chain payment gets a full record: sender, receiver, amount, platform, screenshot",
                    "Evidence files are stored as base64 inside the case JSON — they travel with the case",
                    "CFPB complaint search is free and covers all major payment platforms",
                    "The Cross-Case Entity Linking button finds the same account appearing in multiple cases",
                ],
                "color": "#0891b2",
            },
            {
                "num": "10",
                "icon": "📄",
                "title": "Generate reports and file",
                "page": "Reports → PDF Report / Export & SIEM / Maltego Export\nCompliance → SAR / CTR Filing",
                "what": "Generate the SAR narrative (auto or manual), export to Maltego/i2/Cellebrite, create the full PDF investigation report, and export an INTERPOL Purple Notice if needed.",
                "tips": [
                    "Use 🤖 Auto-Generate SAR to create a complete FinCEN narrative in one click — no manual typing",
                    "The PDF report has 27 sections and embeds screenshots from your evidence files",
                    "Maltego CSV imports directly into Maltego for further enrichment",
                    "INTERPOL Purple Notice goes via your NCB (National Central Bureau) on I-24/7",
                ],
                "color": "#22c55e",
            },
        ]

        for step in steps:
            with st.expander(
                f"**Step {step['num']}** {step['icon']} — {step['title']}",
                expanded=step["num"] in ("01","02","03")
            ):
                st.markdown(
                    f"<div style='border-left:4px solid {step['color']};padding-left:12px'>",
                    unsafe_allow_html=True
                )
                st.markdown(f"**Navigate to:** `{step['page']}`")
                st.markdown(f"**What it does:** {step['what']}")
                if step["tips"]:
                    st.markdown("**💡 Tips:**")
                    for tip in step["tips"]:
                        st.markdown(f"- {tip}")
                st.markdown("</div>", unsafe_allow_html=True)

    # ══════════════════════════════════════════════════════════
    # TAB 4 — ALL FEATURES
    # ══════════════════════════════════════════════════════════
    with help_tabs[3]:
        st.markdown("## 🗂️ Complete Feature Reference")
        st.caption("Every page and what it does — organized by sidebar group.")

        feature_groups = {
            "📊 Analysis": {
                "color": "#3b82f6",
                "pages": {
                    "Overview":           "Transaction summary, risk distribution, timeline chart, top addresses by volume and risk",
                    "Transactions":       "Full sortable/filterable transaction table with risk scoring and amount analysis",
                    "Sankey Flow":        "Interactive fund flow diagram showing money movement between addresses visually",
                    "Timeline":           "Chronological view of all investigation events — transactions, case notes, SAR filings, LE referrals",
                },
            },
            "🔍 Intelligence": {
                "color": "#8b5cf6",
                "pages": {
                    "Multi-hop Tracer":   "Follow funds forward/backward through up to 10 hops across multiple blockchains",
                    "Pattern Intel":      "8 detection algorithms: structuring, velocity, circular flows, mixer behavior, peeling chains, cross-chain, stablecoin, anomalies",
                    "Velocity":           "Time-to-forward analysis — how quickly addresses forward received funds (fast = layering)",
                    "Network Graph":      "Interactive Plotly network graph of address relationships with community detection",
                    "Infrastructure":     "Behavioral clustering — groups addresses by operational hours, gas price, timing patterns to identify same operators",
                },
            },
            "📡 SOCMINT": {
                "color": "#0891b2",
                "pages": {
                    "Social Media Intel": "Reddit, GitHub, BitcoinAbuse, CryptoScamDB, paste site search for any address. Batch scan top-risk addresses from dataset.",
                },
            },
            "🤖 AI & ML": {
                "color": "#7c3aed",
                "pages": {
                    "Claude AI":          "AI-assisted transaction analysis, pattern explanation, and narrative generation using Claude Sonnet",
                    "Time Series ML":     "ML anomaly detection on transaction time series — ramping, cyclical bots, dormant reactivation",
                },
            },
            "⚖️ Compliance": {
                "color": "#be185d",
                "pages": {
                    "SAR / CTR Filing":   "Generate FinCEN SAR narrative (auto or manual), SAR XML for BSA E-Filing, SAR PDF, and CTR data for $10K+ transactions",
                    "EIP-712 Signing":    "Sign and verify EIP-712 structured data messages — generates forensic hash certificates",
                    "ZK Proofs":          "Zero-knowledge proof generation for proving knowledge without revealing private data",
                },
            },
            "🌐 On-chain": {
                "color": "#059669",
                "pages": {
                    "ENS Resolution":     "Resolve Ethereum Name Service (ENS) names to addresses and vice versa",
                    "Alerts & Monitoring":"Set up watchlists for addresses with push notifications via ntfy.sh, Pushover, or email",
                },
            },
            "🔎 OSINT": {
                "color": "#dc2626",
                "pages": {
                    "OSINT Intelligence": "9 tabs: OFAC SDN, Ransomware (3 sources), USD valuation, Contract intel, DeFi protocols, Dust attacks, Flash loans, Evidence log, Entity databases (DefiLlama + CryptoScamDB)",
                },
            },
            "🏷️ Address Intel": {
                "color": "#f59e0b",
                "pages": {
                    "Address Intelligence":"6 tabs: Co-spending clusters, Address classifier, Exchange endpoints, Darknet intel (5-source screen), Change address detection, Reputation score aggregator",
                },
            },
            "⚔️ Market Intel": {
                "color": "#dc2626",
                "pages": {
                    "MEV & Market Manipulation": "MEV/sandwich attacks, rug pull detection, honeypot checker, coordinated dumps, NFT pump-and-dump",
                    "Threat Intel":         "Boltzmann entropy, pig butchering detection, DPRK/Lazarus Group signatures",
                    "P2P & ATMs":           "P2P exchange detection (LocalBitcoins, Paxful, Bisq), Crypto ATM operator matching and structuring patterns",
                },
            },
            "👤 Profiles": {
                "color": "#22c55e",
                "pages": {
                    "Suspect Profile":    "360° intelligence aggregator — pulls from every analysis module into one profile with legal action recommendations",
                    "Seed Phrase":        "BIP39/BIP44 wallet derivation from seized seed phrase. Derives addresses across BTC/ETH/BSC/Tron/Polygon. Checks balances and cross-references dataset",
                    "Investigation Timeline": "Visual Plotly timeline of all case events filterable by type and date range",
                    "QR Scanner":         "Upload photos to extract crypto addresses from QR codes. Cross-references with dataset",
                    "Investigation Agent":"AI chat interface backed by Claude — answers investigation questions in plain English, writes SAR narratives, explains findings",
                },
            },
            "📋 Regulatory": {
                "color": "#0891b2",
                "pages": {
                    "FATF Travel Rule":   "Identify transactions requiring VASP-to-VASP data sharing (≥$1,000). Generate IVMS101 packages",
                    "L2 Chains":          "Layer 2 chain analysis — Arbitrum, Optimism, Base, zkSync transaction support",
                    "Multi-sig":          "Multi-signature wallet analysis and threshold detection",
                    "Privacy Coins":      "Monero/Zcash ingress/egress tracking and privacy coin interaction detection",
                    "Case Dashboard":     "Full case management: status, off-chain payments, evidence files, notes. Includes cross-case entity linking and CFPB/BBB fraud search",
                    "MiCA Compliance":    "EU Markets in Crypto-Assets compliance: Travel Rule (€1,000), EDD (€15,000), CASP registration tracker, NCA contacts",
                },
            },
            "◎ Solana": {
                "color": "#9945ff",
                "pages": {
                    "Solana Analysis":    "Solana transaction history, SPL token holdings, program fingerprinting, on-chain risk screening",
                },
            },
            "🔬 Deep Analytics": {
                "color": "#6366f1",
                "pages": {
                    "Tornado Linking":    "Statistical deposit-withdrawal linking for Tornado Cash (and other mixers) using timing/amount correlation",
                    "GNN Clustering":     "Graph Neural Network address clustering — finds wallets controlled by the same entity",
                    "Mempool Monitor":    "Real-time mempool monitoring for pending transactions involving tracked addresses",
                    "Atomic Swaps":       "Cross-chain atomic swap and DEX detection — identifies untraced cross-chain movements",
                    "Lightning Network":  "Bitcoin LN channel detection, BOLT11 invoice decoder, node lookup, traceability assessment",
                },
            },
            "📰 Crime Intel": {
                "color": "#dc2626",
                "pages": {
                    "Crypto Crime News":  "Live RSS aggregation from 7 sources. Extracts addresses from articles. Alerts when your investigation addresses appear in news",
                    "Stablecoin Depeg":   "6 historical depeg events database. Detects exploitation during USDC/USDT/DAI/UST depeg windows. Flash loan attack correlation",
                },
            },
            "🔌 API": {
                "color": "#475569",
                "pages": {
                    "REST API":           "FastAPI server with 41 HTTP endpoints. Run separately on port 8001. Swagger UI at /docs. API key authentication, webhooks, async jobs",
                },
            },
            "📤 Reports": {
                "color": "#22c55e",
                "pages": {
                    "PDF Report":         "27-section investigation report with embedded screenshots, all analysis results, and SAR narrative",
                    "Export & SIEM":      "Maltego CSV, i2 ANB XML, Cellebrite CSV, SIEM/CEF events, INTERPOL Purple Notice XML, raw JSON/CSV",
                    "Maltego Export":     "Dedicated Maltego/i2/Cellebrite export hub with format-specific guidance",
                    "Case Notes":         "Global case notes and evidence audit log across the investigation",
                },
            },
        }

        for group, info in feature_groups.items():
            with st.expander(f"**{group}**", expanded=False):
                for page, desc in info["pages"].items():
                    st.markdown(
                        f"<div style='border-left:3px solid {info['color']};"
                        f"padding:8px 12px;margin:4px 0;background:#1e293b;border-radius:0 6px 6px 0'>"
                        f"<strong>{page}</strong><br>"
                        f"<span style='color:#94a3b8;font-size:13px'>{desc}</span></div>",
                        unsafe_allow_html=True,
                    )

    # ══════════════════════════════════════════════════════════
    # TAB 5 — API KEYS
    # ══════════════════════════════════════════════════════════
    with help_tabs[4]:
        st.markdown("## 🔑 API Keys Setup")

        st.markdown(
            "Most features work with **no API keys**. Keys unlock on-chain data fetching "
            "and some screening sources. Add keys to `.streamlit/secrets.toml` in your app folder "
            "or via the ⚙️ Configuration page."
        )

        st.code("""# .streamlit/secrets.toml
# Add keys at the TOP LEVEL — no [section] headers

anthropic_key    = "sk-ant-..."      # Claude AI features
etherscan_key    = "..."             # Ethereum on-chain data
bscscan_key      = "..."             # BSC on-chain data
polygonscan_key  = "..."             # Polygon on-chain data
bitquery_key     = "..."             # Multi-chain GraphQL queries
breadcrumbs_key  = "..."             # Breadcrumbs.io entity labels
tron_key         = "..."             # TronScan API
""", language="toml")

        keys_data = {
            "Key":              ["anthropic_key", "etherscan_key", "bscscan_key", "polygonscan_key", "bitquery_key", "breadcrumbs_key", "tron_key"],
            "Used for":         [
                "Claude AI analysis, Investigation Agent, Auto-SAR",
                "Ethereum on-chain fetch, USDC/USDT blacklist, live balances, seed phrase balance check",
                "BSC/BNB Chain transaction history",
                "Polygon (MATIC) transaction history",
                "Multi-chain GraphQL queries",
                "Exchange/entity label enrichment",
                "Tron TRC-20 transaction history",
            ],
            "Free tier":        ["~$5 free credit", "100K req/day", "100K req/day", "100K req/day", "10K req/day", "Limited free", "5K req/day"],
            "Get it at":        [
                "console.anthropic.com",
                "etherscan.io/apis",
                "bscscan.com/apis",
                "polygonscan.com/apis",
                "bitquery.io",
                "breadcrumbs.app",
                "tronscan.org/api",
            ],
            "Required?":        ["⚠️ For Claude AI only", "✅ Recommended", "Optional", "Optional", "Optional", "Optional", "Optional"],
        }
        st.dataframe(pd.DataFrame(keys_data), width='stretch', hide_index=True)

        st.markdown("---")
        st.markdown("### Features that work with NO API keys")
        st.success("""
✅ OFAC SDN screening (downloads directly from US Treasury)
✅ Ransomwhere.co ransomware database
✅ Abuse.ch ThreatFox ransomware database  
✅ CISA advisory ransomware addresses
✅ GoPlus Security address screening (30M+ addresses)
✅ Hop Protocol sanctions list
✅ CryptoScamDB community blacklist
✅ DefiLlama DeFi hacks database
✅ BitcoinAbuse community reports
✅ Reddit, GitHub, paste site OSINT search
✅ CoinGecko live stablecoin prices
✅ Lightning Network node lookup (1ML.com)
✅ All pattern detection algorithms
✅ All clustering algorithms (sklearn built-in)
✅ Crypto crime news feed (7 RSS sources)
✅ All SAR/CTR/compliance generation
✅ All export formats (Maltego, i2, Cellebrite, INTERPOL)
✅ Seed phrase address derivation (pure Python — no API)
✅ Boltzmann entropy analysis (pure math)
""")

        st.markdown("### Streamlit Cloud deployment")
        st.markdown("""
On Streamlit Cloud, add secrets via the app dashboard:
1. Go to your app on **share.streamlit.io**
2. Click **⋮ → Settings → Secrets**
3. Paste your `secrets.toml` content exactly as shown above
4. Click **Save** — the app restarts automatically
""")

    # ══════════════════════════════════════════════════════════
    # TAB 6 — TROUBLESHOOTING
    # ══════════════════════════════════════════════════════════
    with help_tabs[5]:
        st.markdown("## ⚠️ Troubleshooting")

        issues = [
            {
                "problem": "❌ `ButtonMixin.button() got unexpected keyword argument 'width'`",
                "cause":   "An old version of a module file is still deployed alongside the updated CryptoAnalyzerApp.py",
                "fix":     "Replace ALL module files at the same time. Do not mix old and new file versions. Run `streamlit cache clear` then restart.",
            },
            {
                "problem": "❌ `UnicodeDecodeError: 'charmap' codec can't decode...`",
                "cause":   "Windows encoding issue when running Python scripts",
                "fix":     "Always open files with `encoding='utf-8'` parameter. All provided scripts already do this.",
            },
            {
                "problem": "⚠️ Charts or tables not updating after I change pages",
                "cause":   "Streamlit caches some results in session_state — this is intentional",
                "fix":     "Press **R** to rerun, or use the hamburger menu → Rerun. Results from previous runs are preserved.",
            },
            {
                "problem": "⚠️ OFAC screening returns 0 results unexpectedly",
                "cause":   "OFAC SDN list failed to download (network issue or rate limit)",
                "fix":     "Try again — the list is cached for 24 hours once downloaded successfully. Check your internet connection.",
            },
            {
                "problem": "⚠️ Pattern detection finds nothing suspicious",
                "cause":   "Either the data is genuinely clean, or the dataset is too small (<10 transactions)",
                "fix":     "Load sample data to confirm the detectors are working. Structuring requires transactions across a date range with similar amounts.",
            },
            {
                "problem": "❌ `ModuleNotFoundError: No module named 'forensics_...'`",
                "cause":   "A new module file was not added to the app folder",
                "fix":     "Copy ALL .py files to your app folder. Each Tier adds new module files that must be present.",
            },
            {
                "problem": "⚠️ QR scanner says 'QR detection requires pyzbar'",
                "cause":   "pyzbar system library not installed",
                "fix":     "Add `libzbar0` to `packages.txt` (Streamlit Cloud) or run `apt install libzbar0` (Linux) or `brew install zbar` (Mac).",
            },
            {
                "problem": "❌ FastAPI / REST API not starting",
                "cause":   "fastapi or uvicorn not installed, or port 8001 already in use",
                "fix":     "Run `pip install fastapi uvicorn[standard]`. Try `--port 8002` if 8001 is taken. The API runs as a SEPARATE process from Streamlit.",
            },
            {
                "problem": "⚠️ Seed phrase derivation gives wrong ETH addresses",
                "cause":   "pycryptodome not installed — falling back to sha3 approximation",
                "fix":     "Run `pip install pycryptodome`. The ETH addresses shown without it are approximate — install pycryptodome for accurate keccak256.",
            },
            {
                "problem": "⚠️ Infrastructure clustering returns 'sklearn not installed'",
                "cause":   "scikit-learn package missing",
                "fix":     "Run `pip install scikit-learn>=1.4.0`",
            },
            {
                "problem": "⚠️ App is very slow on large datasets",
                "cause":   "15,000+ transactions can take time for some algorithms",
                "fix":     "Use the vectorized risk scorer (it handles 15K rows in 0.04s). Filter to a specific date range or address before running slower analyses like GNN clustering.",
            },
            {
                "problem": "⚠️ Streamlit Cloud shows old version after file update",
                "cause":   "Streamlit Cloud caches the app — needs a full reboot",
                "fix":     "Go to your app on share.streamlit.io → ⋮ → Reboot app (not just Rerun).",
            },
        ]

        for issue in issues:
            with st.expander(issue["problem"], expanded=False):
                st.markdown(f"**Cause:** {issue['cause']}")
                st.success(f"**Fix:** {issue['fix']}")

    # ══════════════════════════════════════════════════════════
    # TAB 7 — QUICK REFERENCE
    # ══════════════════════════════════════════════════════════
    with help_tabs[6]:
        st.markdown("## 📋 Quick Reference")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Risk Levels")
            st.markdown("""
| Level | Score | What it means |
|---|---|---|
| 🔴 CRITICAL | 85–100 | OFAC/sanctions hit, ransomware, DPRK — immediate action |
| 🟠 HIGH | 60–84 | Strong laundering indicators — escalate |
| 🟡 MEDIUM | 35–59 | Suspicious patterns — investigate further |
| 🟢 LOW | 0–34 | No significant indicators |
""")

            st.markdown("### Reporting Deadlines")
            st.markdown("""
| Report | Deadline | Threshold |
|---|---|---|
| SAR | 30 days from detection | Any suspicious activity |
| SAR (no suspect) | 60 days | Any suspicious activity |
| CTR | 15 days | Single tx ≥ $10,000 |
| OFAC hit | Immediate | Any SDN match |
| MiCA STR (EU) | 24 hours | Any suspicious tx |
""")

            st.markdown("### Common FATF Typologies")
            typologies = [
                ("#1", "Bulk cash smuggling"),
                ("#3", "Structuring / Smurfing"),
                ("#8", "Use of mixing services"),
                ("#14", "Shell companies and nominees"),
                ("#22", "Virtual currency — rapid layering"),
                ("#28", "Ransomware payment channels"),
            ]
            for code, desc in typologies:
                st.markdown(f"- **FATF {code}:** {desc}")

        with col2:
            st.markdown("### Legal Process Reference")
            st.markdown("""
| Action | Authority | Target |
|---|---|---|
| Exchange subpoena | 18 USC 2703 | KYC identity of account holder |
| SAR filing | 31 USC 5318(g) | FinCEN BSA E-Filing |
| Asset freeze | Court order | Wallet with active balance |
| OFAC report | 31 CFR 501 | Sanctions compliance |
| LN node subpoena | 18 USC 2703 | Routing/payment records |
| ATM operator subpoena | FinCEN MSB rules | Customer ID + tx records |
| P2P platform | 18 USC 2703 | Trade partner payment info |
""")

            st.markdown("### Keyboard Shortcuts")
            st.markdown("""
| Key | Action |
|---|---|
| `R` | Rerun the app |
| `W` | Open settings |
| `F` | Search in page |
| `Ctrl+K` | Open command bar (Streamlit) |
""")

            st.markdown("### Address Formats")
            st.markdown("""
| Chain | Format | Example start |
|---|---|---|
| Ethereum/EVM | `0x` + 40 hex chars | `0x1234...` |
| Bitcoin Legacy | Base58, 26–35 chars | `1`, `3` |
| Bitcoin SegWit | bech32 | `bc1q...` |
| Tron | Base58, 34 chars | `T...` |
| Solana | Base58, 32–44 chars | `...` (any) |
""")

        st.markdown("---")
        st.markdown("### Supported Chains")
        chains_data = {
            "Chain":    ["Ethereum", "BSC / BNB Chain", "Polygon", "Arbitrum", "Optimism", "Base", "Tron", "Bitcoin", "Solana"],
            "Token IDs":["ETH, ERC-20", "BNB, BEP-20", "MATIC, ERC-20", "ETH, ERC-20", "ETH, ERC-20", "ETH, ERC-20", "TRX, TRC-20", "BTC", "SOL, SPL"],
            "API Key":  ["etherscan_key", "bscscan_key", "polygonscan_key", "etherscan_key", "etherscan_key", "etherscan_key", "tron_key", "None needed", "None needed"],
        }
        st.dataframe(pd.DataFrame(chains_data), width='stretch', hide_index=True)

        st.markdown("---")
        st.markdown("### Module File Reference")
        st.caption("Every .py file and what it contains. All files must be in the same folder as CryptoAnalyzerApp.py.")
        files_data = {
            "File": [
                "CryptoAnalyzerApp.py", "blockchain_apis.py", "hop_tracer.py",
                "forensics_intel.py", "forensics_patterns.py", "forensics_osint.py",
                "forensics_compliance.py", "forensics_compliance2.py", "forensics_export.py",
                "forensics_address_intel.py", "forensics_advanced.py", "forensics_mev.py",
                "forensics_solana.py", "forensics_advanced2.py", "forensics_api.py",
                "forensics_timeseries.py", "forensics_fullreport.py", "forensics_profile.py",
                "forensics_timeline.py", "forensics_scams.py", "forensics_seedphrase.py",
                "forensics_social.py", "forensics_netinfra.py", "forensics_lightning.py",
                "forensics_stablecoin.py", "forensics_newsfeed.py", "forensics_help.py",
                "forensics_alerts.py", "forensics_crypto.py", "forensics_ens.py", "forensics_zkp.py",
            ],
            "Contains": [
                "Main app, navigation, page routing (2,541 lines)",
                "EVM/Bitcoin/Tron on-chain data fetching",
                "Multi-hop forward/backward fund tracer",
                "Structuring, velocity, network graph, wallet profiler, peeling chains",
                "DBSCAN clustering, circular flows, mixer detection, behavioral anomalies",
                "OFAC SDN, 3-source ransomware, USD valuation, contracts, DeFi, dust, flash loans",
                "SAR/CTR filing, FinCEN XML, PDF, auto-SAR from session",
                "FATF Travel Rule, L2 chains, multi-sig, privacy coins, case dashboard, off-chain payments, MiCA",
                "JSON/CSV/PDF/SIEM + Maltego/i2/Cellebrite + INTERPOL Purple Notice",
                "Co-spending clusters, address classifier, exchange endpoints, 5-source darknet screen",
                "NFT wash trading, airdrop farming, geolocation, save/restore, portfolio",
                "MEV/sandwich, rug pulls, honeypots, coordinated dumps, NFT pump-and-dump",
                "Solana RPC, SPL tokens, program fingerprinting",
                "Tornado Cash linking, GNN clustering, mempool monitor, atomic swaps",
                "FastAPI REST API, 41 endpoints, API key auth, webhooks, background jobs",
                "Ramping, cyclical/bot, dormant reactivation time series ML",
                "27-section PDF report with embedded images",
                "360° suspect profile aggregating all modules",
                "Investigation timeline, QR scanner, AI investigation agent",
                "Boltzmann entropy, pig butchering, DPRK/Lazarus, P2P exchanges, crypto ATMs",
                "BIP39/BIP44 seed phrase derivation — pure Python",
                "Reddit, GitHub, BitcoinAbuse, CryptoScamDB, paste site SOCMINT",
                "64-dim behavioral infrastructure clustering",
                "Lightning Network channel detection, BOLT11 invoice parser",
                "Stablecoin depeg event database, exploitation detection, flash loan correlation",
                "RSS crime news aggregator, address extraction, dataset cross-reference",
                "This help file",
                "ntfy.sh/Pushover/email push alerts, address watchlist",
                "EIP-712 structured data signing",
                "ENS name resolution",
                "Zero-knowledge proof generation",
            ],
        }
        st.dataframe(pd.DataFrame(files_data), width='stretch', hide_index=True)

        st.markdown("---")
        st.caption(
            f"Crypto Forensics Analyzer Pro v5.0 · "
            f"Help last updated: {datetime.now().strftime('%B %Y')} · "
            "For authorized investigative use only"
        )
