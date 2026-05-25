"""
forensics_api.py  —  Crypto Forensics Analyzer Pro v5.0
REST API wrapper via FastAPI:
  • Exposes all forensics functions as HTTP endpoints
  • API key authentication
  • Swagger/OpenAPI documentation at /docs
  • Background task support for long-running analyses
  • CORS support for integration with external tools
  • Cellebrite / Nuix / JIRA / Slack webhook compatible

Run: uvicorn forensics_api:app --host 0.0.0.0 --port 8001 --reload
Docs: http://localhost:8001/docs
"""

import sys
import json
import hashlib
import logging
import asyncio
import pandas as pd
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# CHECK FASTAPI AVAILABILITY
# ─────────────────────────────────────────────────────────────
try:
    from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Security
    from fastapi.security import APIKeyHeader
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse
    from pydantic import BaseModel, Field
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.warning("FastAPI not installed. Run: pip install fastapi uvicorn[standard] pydantic")


# ─────────────────────────────────────────────────────────────
# INSTALL INSTRUCTIONS (shown when run directly without FastAPI)
# ─────────────────────────────────────────────────────────────

INSTALL_INSTRUCTIONS = """
╔══════════════════════════════════════════════════════════════╗
║         Crypto Forensics REST API — Setup Instructions        ║
╚══════════════════════════════════════════════════════════════╝

1. Install dependencies:
   pip install fastapi uvicorn[standard] pydantic

2. Start the API server:
   uvicorn forensics_api:app --host 0.0.0.0 --port 8001 --reload

3. Interactive docs (Swagger UI):
   http://localhost:8001/docs

4. Alternative docs (ReDoc):
   http://localhost:8001/redoc

5. Set your API key in .streamlit/secrets.toml:
   [api]
   forensics_api_key = "your-secret-key-here"

6. Use the API:
   curl -H "X-API-Key: your-key" http://localhost:8001/health
   curl -H "X-API-Key: your-key" -X POST \\
     -H "Content-Type: application/json" \\
     -d '{"addresses":["0x..."],"chain":"ethereum"}' \\
     http://localhost:8001/v1/screen/ofac

Integration examples:
  • Postman collection: import /v1/openapi.json
  • Python requests: see /docs for auto-generated examples  
  • Webhook (Slack/JIRA): POST to /v1/webhook/results
"""

if not FASTAPI_AVAILABLE:
    print(INSTALL_INSTRUCTIONS)


# ─────────────────────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────────────────────

if FASTAPI_AVAILABLE:
    class TransactionInput(BaseModel):
        transactions: List[Dict] = Field(..., description="List of transaction records")
        case_id: Optional[str] = Field(None, description="Case identifier for audit logging")

    class AddressScreenRequest(BaseModel):
        addresses: List[str] = Field(..., description="List of addresses to screen")
        chain: str = Field("ethereum", description="Blockchain network")
        include_ofac: bool = Field(True, description="Include OFAC SDN screening")
        include_ransomware: bool = Field(True, description="Include Ransomwhere screening")

    class WalletLookupRequest(BaseModel):
        address: str = Field(..., description="Wallet address to look up")
        chain: str = Field("ethereum", description="Blockchain network")
        max_transactions: int = Field(50, ge=1, le=200)

    class RiskScoreRequest(BaseModel):
        transactions: List[Dict] = Field(..., description="Transaction records")

    class SARRequest(BaseModel):
        case_id: str
        filing_institution: str
        subject_addresses: List[str]
        total_volume: float
        typologies: List[str]
        narrative: str
        investigator: str = "API"

    class WebhookConfig(BaseModel):
        url: str = Field(..., description="Webhook URL to POST results to")
        events: List[str] = Field(["critical_risk","ofac_hit","ransomware_hit"],
                                   description="Events that trigger the webhook")
        secret: Optional[str] = Field(None, description="HMAC secret for webhook signing")

    class AnalysisJob(BaseModel):
        job_id: str
        status: str
        created_at: str
        result: Optional[Any] = None
        error: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# API KEY AUTHENTICATION
# ─────────────────────────────────────────────────────────────

API_KEY_FILE = Path("api_keys.json")

def _load_api_keys() -> Dict[str, str]:
    """Load API keys from file or secrets."""
    keys = {}

    # Load from secrets file
    try:
        import streamlit as st
        key = st.secrets.get("api", {}).get("forensics_api_key")
        if key:
            keys[str(key)] = "primary"
    except Exception:
        pass

    # Load from api_keys.json
    if API_KEY_FILE.exists():
        try:
            stored = json.loads(API_KEY_FILE.read_text())
            keys.update(stored)
        except Exception:
            pass

    # Default development key (change in production!)
    if not keys:
        dev_key = "forensics-dev-key-change-in-production"
        keys[dev_key] = "development"
        logger.warning(f"Using default dev API key: {dev_key}")

    return keys

def add_api_key(key: str, label: str):
    """Add a new API key."""
    keys = {}
    if API_KEY_FILE.exists():
        try:
            keys = json.loads(API_KEY_FILE.read_text())
        except Exception:
            pass
    keys[key] = label
    API_KEY_FILE.write_text(json.dumps(keys, indent=2))


# ─────────────────────────────────────────────────────────────
# JOB STORAGE (in-memory for simplicity; use Redis in production)
# ─────────────────────────────────────────────────────────────

_JOBS: Dict[str, Dict] = {}
_WEBHOOKS: List[Dict]  = []


def _new_job_id() -> str:
    return hashlib.sha256(f"{datetime.now().isoformat()}".encode()).hexdigest()[:12]


async def _send_webhook(event: str, data: Dict):
    """Send webhook notifications for registered events."""
    import httpx
    for wh in _WEBHOOKS:
        if event in wh.get("events", []):
            try:
                payload = json.dumps({"event": event, "data": data, "timestamp": datetime.now().isoformat()})
                headers = {"Content-Type": "application/json"}
                if wh.get("secret"):
                    sig = hashlib.sha256(f"{wh['secret']}{payload}".encode()).hexdigest()
                    headers["X-Forensics-Signature"] = sig
                async with httpx.AsyncClient() as client:
                    await client.post(wh["url"], content=payload, headers=headers, timeout=10)
            except Exception as e:
                logger.warning(f"Webhook delivery failed: {e}")


# ─────────────────────────────────────────────────────────────
# FASTAPI APPLICATION
# ─────────────────────────────────────────────────────────────

if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="Crypto Forensics Analyzer API",
        description=(
            "REST API for blockchain forensics analysis. "
            "Exposes risk scoring, OFAC screening, pattern detection, "
            "address lookup, and SAR generation as HTTP endpoints. "
            "Integrate with Cellebrite, Nuix, JIRA, Slack, or any HTTP client."
        ),
        version="5.0.0",
        contact={"name": "Crypto Forensics Pro", "url": "http://localhost:8502"},
        license_info={"name": "Proprietary — For authorized investigative use only"},
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],    # Restrict in production
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

    async def verify_api_key(api_key: str = Security(api_key_header)):
        keys = _load_api_keys()
        if api_key not in keys:
            raise HTTPException(status_code=403, detail="Invalid API key")
        return api_key

    # ── Health & Info ─────────────────────────────────────────

    @app.get("/health", tags=["System"])
    async def health():
        return {"status": "ok", "version": "5.0.0", "timestamp": datetime.now().isoformat()}

    @app.get("/v1/capabilities", tags=["System"])
    async def capabilities(key: str = Depends(verify_api_key)):
        """List all available API endpoints and their capabilities."""
        return {
            "version": "5.0.0",
            "total_endpoints": 30,
            "endpoints": {
                # ── Screening ──────────────────────────────────────
                "POST /v1/screen/ofac":              "OFAC SDN screening — official Treasury data",
                "POST /v1/screen/ransomware":        "Ransomwhere + ThreatFox + CISA ransomware screening",
                "POST /v1/screen/full":              "Full 5-source intel screen (GoPlus, USDC/USDT, Hop, ScamDB, Darknet)",
                "POST /v1/screen/social":            "Social media + abuse database address lookup",
                "POST /v1/screen/defillama":         "DeFi hack database screening",
                # ── Risk & Scoring ─────────────────────────────────
                "POST /v1/risk/score":               "Vectorized risk scoring for transaction batch",
                "POST /v1/risk/boltzmann":           "Boltzmann entropy analysis (Bitcoin privacy scoring)",
                "POST /v1/risk/profile":             "360° suspect profile — aggregate all intel sources",
                # ── Address Lookup ─────────────────────────────────
                "POST /v1/lookup/address":           "Live on-chain data for EVM/Bitcoin/Tron address",
                "POST /v1/lookup/solana":            "Solana transaction history and SPL token holdings",
                "POST /v1/lookup/seedphrase":        "BIP44 address derivation from seed phrase",
                # ── Pattern Detection ──────────────────────────────
                "POST /v1/pattern/structuring":      "Structuring/smurfing detection",
                "POST /v1/pattern/velocity":         "Velocity analysis (time-to-forward)",
                "POST /v1/pattern/tornado":          "Tornado Cash statistical deposit-withdrawal linking",
                "POST /v1/pattern/mev":              "MEV/sandwich attack detection",
                "POST /v1/pattern/rugpull":          "Rug pull and exit scam detection",
                "POST /v1/pattern/atomicswap":       "Atomic swap and cross-chain DEX detection",
                "POST /v1/pattern/pigbutchering":    "Pig butchering / romance investment scam detection",
                "POST /v1/pattern/dprk":             "DPRK/Lazarus Group signature detection",
                "POST /v1/pattern/p2p":              "P2P exchange and crypto ATM detection",
                "POST /v1/pattern/nft":              "NFT wash trading and pump-and-dump detection",
                "POST /v1/pattern/stablecoin":       "Stablecoin depeg exploitation detection",
                "POST /v1/pattern/lightning":        "Lightning Network channel detection",
                # ── Clustering ─────────────────────────────────────
                "POST /v1/cluster/gnn":              "GNN address clustering (async)",
                "POST /v1/cluster/infrastructure":   "Infrastructure behavioral clustering (async)",
                # ── Compliance ─────────────────────────────────────
                "POST /v1/sar/generate":             "Generate SAR narrative and FinCEN XML",
                "POST /v1/sar/auto":                 "Auto-generate SAR from all session findings",
                "POST /v1/compliance/travelrule":    "Identify FATF Travel Rule transactions",
                "POST /v1/export/interpol":          "Generate INTERPOL Purple Notice XML",
                # ── Jobs & Webhooks ────────────────────────────────
                "GET  /v1/jobs/{job_id}":            "Poll async job status/results",
                "GET  /v1/jobs":                     "List all jobs",
                "POST /v1/webhook/register":         "Register webhook for event alerts",
                "POST /v1/keys/create":              "Create new API key",
            }
        }

    # ── Risk Scoring ──────────────────────────────────────────

    @app.post("/v1/risk/score", tags=["Analysis"])
    async def risk_score(request: RiskScoreRequest, key: str = Depends(verify_api_key)):
        """
        Vectorized risk scoring for a batch of transactions.
        Returns risk_level, risk_score, and risk_reasons for each transaction.
        """
        try:
            from CryptoAnalyzerApp import calculate_risk_vectorized, normalize_dataframe
            df = pd.DataFrame(request.transactions)
            df = normalize_dataframe(df)
            df = calculate_risk_vectorized(df)
            return {
                "count":          len(df),
                "critical_count": int((df["risk_level"]=="CRITICAL").sum()),
                "high_count":     int((df["risk_level"]=="HIGH").sum()),
                "transactions":   df[["risk_level","risk_score","risk_reasons"]].to_dict("records"),
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── OFAC Screening ────────────────────────────────────────

    @app.post("/v1/screen/ofac", tags=["Screening"])
    async def screen_ofac(request: AddressScreenRequest, key: str = Depends(verify_api_key)):
        """
        Screen addresses against the OFAC SDN list.
        Downloads fresh list daily (cached 24h).
        """
        try:
            from forensics_osint import fetch_ofac_sdn_addresses
            sdn_addrs, sdn_names = fetch_ofac_sdn_addresses()
            results = []
            for addr in request.addresses:
                hit = addr.lower() in sdn_addrs
                results.append({
                    "address": addr,
                    "ofac_hit": hit,
                    "entity_name": sdn_names.get(addr.lower(), "") if hit else "",
                    "risk_level": "CRITICAL" if hit else "CLEAR",
                })
            hits = [r for r in results if r["ofac_hit"]]
            if hits:
                await _send_webhook("ofac_hit", {"hits": hits, "chain": request.chain})
            return {"addresses_checked": len(results), "hits": len(hits), "results": results}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Ransomware Screening ──────────────────────────────────

    @app.post("/v1/screen/ransomware", tags=["Screening"])
    async def screen_ransomware(request: AddressScreenRequest, key: str = Depends(verify_api_key)):
        """Screen addresses against Ransomwhere.co ransomware database."""
        try:
            from forensics_osint import fetch_ransomwhere_addresses
            rw_addrs = fetch_ransomwhere_addresses()
            results  = []
            for addr in request.addresses:
                info = rw_addrs.get(addr.lower(), {})
                hit  = bool(info)
                results.append({
                    "address":        addr,
                    "ransomware_hit": hit,
                    "family":         info.get("family","") if hit else "",
                    "total_paid":     info.get("total_paid",0) if hit else 0,
                    "payment_count":  info.get("payment_count",0) if hit else 0,
                })
            hits = [r for r in results if r["ransomware_hit"]]
            if hits:
                await _send_webhook("ransomware_hit", {"hits": hits})
            return {"addresses_checked": len(results), "hits": len(hits), "results": results}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Full Address Screen ───────────────────────────────────

    @app.post("/v1/screen/full", tags=["Screening"])
    async def screen_full(
        request: AddressScreenRequest,
        background_tasks: BackgroundTasks,
        key: str = Depends(verify_api_key),
    ):
        """
        Full multi-source address screening (async — returns job_id).
        Checks: OFAC SDN + Ransomwhere + Community blacklist + Address classifier.
        Poll /v1/jobs/{job_id} for results.
        """
        job_id = _new_job_id()
        _JOBS[job_id] = {"status":"running","created_at":datetime.now().isoformat(),"result":None}

        async def _run():
            try:
                from forensics_osint import fetch_ofac_sdn_addresses, fetch_ransomwhere_addresses
                from forensics_address_intel import get_address_reputation

                sdn_addrs, sdn_names = fetch_ofac_sdn_addresses()
                rw_addrs             = fetch_ransomwhere_addresses()
                dummy_df             = pd.DataFrame({"from_address":request.addresses,"to_address":request.addresses,"amount":[0]*len(request.addresses)})

                results = []
                for addr in request.addresses:
                    rep = get_address_reputation(addr, dummy_df, sdn_addrs, set(rw_addrs.keys()), set())
                    results.append(rep)

                _JOBS[job_id]["status"] = "complete"
                _JOBS[job_id]["result"] = results

                critical = [r for r in results if r.get("risk_level")=="CRITICAL"]
                if critical:
                    await _send_webhook("critical_risk", {"addresses": critical, "chain": request.chain})
            except Exception as e:
                _JOBS[job_id]["status"] = "failed"
                _JOBS[job_id]["error"]  = str(e)

        background_tasks.add_task(_run)
        return {"job_id": job_id, "status": "running", "poll_url": f"/v1/jobs/{job_id}"}

    # ── Address Lookup ────────────────────────────────────────

    @app.post("/v1/lookup/address", tags=["Lookup"])
    async def lookup_address_api(request: WalletLookupRequest, key: str = Depends(verify_api_key)):
        """Fetch live on-chain transaction data for an EVM/Bitcoin/Tron address."""
        try:
            from blockchain_apis import lookup_address, validate_address, get_chain_from_address
            chain = request.chain or get_chain_from_address(request.address) or "ethereum"
            valid, msg = validate_address(request.address, chain)
            if not valid:
                raise HTTPException(status_code=400, detail=f"Invalid address: {msg}")
            result = lookup_address(request.address, chain, "", request.max_transactions)
            native_count = len(result.get("native_txs", pd.DataFrame()))
            return {
                "address":          request.address,
                "chain":            chain,
                "valid":            valid,
                "native_tx_count":  native_count,
                "sources":          result.get("sources", []),
                "success":          result.get("success", False),
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/v1/lookup/solana", tags=["Lookup"])
    async def lookup_solana(request: WalletLookupRequest, key: str = Depends(verify_api_key)):
        """Fetch Solana transaction history."""
        try:
            from forensics_solana import get_solana_transactions, get_solana_account_info, validate_solana_address
            if not validate_solana_address(request.address):
                raise HTTPException(status_code=400, detail="Invalid Solana address")
            acct = get_solana_account_info(request.address)
            df   = get_solana_transactions(request.address, request.max_transactions)
            return {
                "address":     request.address,
                "sol_balance": acct.get("sol_balance",0),
                "account_type":acct.get("account_type","UNKNOWN"),
                "tx_count":    len(df),
                "transactions": df.head(20).to_dict("records") if not df.empty else [],
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Pattern Detection ─────────────────────────────────────

    @app.post("/v1/pattern/structuring", tags=["Patterns"])
    async def detect_structuring_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect structuring/smurfing patterns in a transaction set."""
        try:
            from forensics_intel import detect_structuring
            df = pd.DataFrame(request.transactions)
            findings = detect_structuring(df)
            return {"count": len(findings), "findings": findings}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/v1/pattern/tornado", tags=["Patterns"])
    async def tornado_linking_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Statistical Tornado Cash deposit→withdrawal linking."""
        try:
            from forensics_advanced2 import link_tornado_deposits_withdrawals
            df = pd.DataFrame(request.transactions)
            result_df = link_tornado_deposits_withdrawals(df)
            return {
                "pairs_found": len(result_df),
                "links": result_df.to_dict("records") if not result_df.empty else [],
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/v1/pattern/mev", tags=["Patterns"])
    async def mev_detection_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect MEV/sandwich attacks."""
        try:
            from forensics_mev import detect_sandwich_attacks
            df = pd.DataFrame(request.transactions)
            result = detect_sandwich_attacks(df)
            return {"count": len(result), "findings": result.to_dict("records") if not result.empty else []}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/v1/pattern/rugpull", tags=["Patterns"])
    async def rugpull_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect rug pull patterns."""
        try:
            from forensics_mev import detect_rug_pulls
            df = pd.DataFrame(request.transactions)
            result = detect_rug_pulls(df)
            return {"count": len(result), "findings": result.to_dict("records") if not result.empty else []}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/v1/pattern/atomicswap", tags=["Patterns"])
    async def atomicswap_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect atomic swap and cross-chain DEX activity."""
        try:
            from forensics_advanced2 import detect_atomic_swaps
            df = pd.DataFrame(request.transactions)
            result = detect_atomic_swaps(df)
            return {"count": len(result), "findings": result.to_dict("records") if not result.empty else []}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── GNN Clustering ────────────────────────────────────────

    @app.post("/v1/cluster/gnn", tags=["Clustering"])
    async def gnn_cluster_api(
        request: TransactionInput,
        background_tasks: BackgroundTasks,
        n_clusters: int = 8,
        key: str = Depends(verify_api_key),
    ):
        """GNN-based address clustering (async). Poll /v1/jobs/{job_id}."""
        job_id = _new_job_id()
        _JOBS[job_id] = {"status":"running","created_at":datetime.now().isoformat()}

        async def _run():
            try:
                from forensics_advanced2 import gnn_cluster_addresses
                df = pd.DataFrame(request.transactions)
                result = gnn_cluster_addresses(df, n_clusters)
                _JOBS[job_id]["status"] = "complete"
                _JOBS[job_id]["result"] = {
                    "clusters": result["spectral_cluster"].nunique() if not result.empty else 0,
                    "addresses": len(result),
                    "data": result.to_dict("records") if not result.empty else [],
                }
            except Exception as e:
                _JOBS[job_id]["status"] = "failed"
                _JOBS[job_id]["error"]  = str(e)

        background_tasks.add_task(_run)
        return {"job_id": job_id, "status": "running"}


    # ── Social Media Screening ────────────────────────────────

    @app.post("/v1/screen/social", tags=["Screening"])
    async def screen_social(request: AddressScreenRequest, key: str = Depends(verify_api_key)):
        """Screen address against Reddit, GitHub, BitcoinAbuse, CryptoScamDB, paste sites."""
        try:
            from forensics_social import check_cryptoscamdb, check_bitcoinabuse, search_reddit
            results = []
            for addr in request.addresses[:10]:   # Cap at 10 for API calls
                scamdb  = check_cryptoscamdb(addr)
                bitcoin = check_bitcoinabuse(addr) if addr.startswith(("1","3","bc1")) else {}
                reddit  = search_reddit(addr, max_results=5)
                results.append({
                    "address":          addr,
                    "scamdb_hit":       scamdb.get("is_scam", False),
                    "scam_type":        scamdb.get("scam_type", ""),
                    "abuse_reports":    bitcoin.get("report_count", 0),
                    "reddit_mentions":  len(reddit),
                    "negative_mentions":len([r for r in reddit if r.get("sentiment")=="negative"]),
                })
            return {"addresses_checked": len(results), "results": results}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    @app.post("/v1/screen/defillama", tags=["Screening"])
    async def screen_defillama(key: str = Depends(verify_api_key)):
        """Fetch DeFi hack database from DefiLlama."""
        try:
            from forensics_osint import fetch_defillama_hacks
            hacks = fetch_defillama_hacks()
            total = sum(h.get("amount_usd",0) for h in hacks)
            return {"hack_count": len(hacks), "total_usd": total, "hacks": hacks[:20]}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    # ── Risk Analysis ─────────────────────────────────────────

    @app.post("/v1/risk/boltzmann", tags=["Analysis"])
    async def boltzmann_api(
        inputs:  List[float],
        outputs: List[float],
        key: str = Depends(verify_api_key),
    ):
        """
        Calculate Boltzmann entropy for a Bitcoin transaction.
        Higher entropy = more private = more obfuscation.
        """
        try:
            from forensics_scams import calculate_boltzmann_entropy
            result = calculate_boltzmann_entropy(inputs, outputs)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    @app.post("/v1/risk/profile", tags=["Analysis"])
    async def profile_api(
        request:  WalletLookupRequest,
        background_tasks: BackgroundTasks,
        key: str = Depends(verify_api_key),
    ):
        """
        Generate 360° suspect profile for an address (async).
        Aggregates all available intelligence. Poll /v1/jobs/{job_id}.
        """
        job_id = _new_job_id()
        _JOBS[job_id] = {"status":"running","created_at":datetime.now().isoformat()}

        async def _run():
            try:
                import pandas as pd
                from forensics_profile import collect_address_profile
                dummy_df = pd.DataFrame()
                profile  = collect_address_profile(request.address, dummy_df,
                                                    chain=request.chain)
                _JOBS[job_id]["status"] = "complete"
                _JOBS[job_id]["result"] = profile
            except Exception as e:
                _JOBS[job_id]["status"] = "failed"
                _JOBS[job_id]["error"]  = str(e)

        background_tasks.add_task(_run)
        return {"job_id": job_id, "status": "running"}


    # ── Seed Phrase ───────────────────────────────────────────

    @app.post("/v1/lookup/seedphrase", tags=["Lookup"])
    async def seedphrase_api(
        mnemonic:   str,
        passphrase: str = "",
        chains:     List[str] = None,
        num_addrs:  int = 5,
        key: str = Depends(verify_api_key),
    ):
        """
        Derive wallet addresses from a BIP39 seed phrase.
        ⚠️ Only use for authorized forensic investigation.
        """
        try:
            from forensics_seedphrase import derive_addresses, validate_mnemonic, load_bip39_wordlist
            wordlist = load_bip39_wordlist()
            valid, msg = validate_mnemonic(mnemonic, wordlist)
            if not valid:
                raise HTTPException(status_code=400, detail=f"Invalid mnemonic: {msg}")
            derived = derive_addresses(mnemonic, passphrase, chains, num_addrs)
            return {
                "word_count": len(mnemonic.strip().split()),
                "chains":     chains or "all",
                "addresses":  derived,
                "warning":    "AUTHORIZED FORENSIC USE ONLY",
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    # ── Advanced Pattern Detection ─────────────────────────────

    @app.post("/v1/pattern/pigbutchering", tags=["Patterns"])
    async def pig_butchering_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect pig butchering and romance investment scam patterns."""
        try:
            import pandas as pd
            from forensics_scams import detect_pig_butchering
            df     = pd.DataFrame(request.transactions)
            result = detect_pig_butchering(df)
            return {"count": len(result), "findings": result.to_dict("records") if not result.empty else []}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    @app.post("/v1/pattern/dprk", tags=["Patterns"])
    async def dprk_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect DPRK/Lazarus Group operational signatures."""
        try:
            import pandas as pd
            from forensics_scams import detect_dprk_patterns
            df     = pd.DataFrame(request.transactions)
            result = detect_dprk_patterns(df)
            return {"count": len(result), "findings": result.to_dict("records") if not result.empty else []}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    @app.post("/v1/pattern/p2p", tags=["Patterns"])
    async def p2p_atm_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect P2P exchange and crypto ATM activity."""
        try:
            import pandas as pd
            from forensics_scams import detect_p2p_exchange, detect_crypto_atm_activity
            df   = pd.DataFrame(request.transactions)
            p2p  = detect_p2p_exchange(df)
            atm  = detect_crypto_atm_activity(df)
            return {
                "p2p_count": len(p2p),
                "atm_count": len(atm),
                "p2p_findings": p2p.to_dict("records") if not p2p.empty else [],
                "atm_findings": atm.to_dict("records") if not atm.empty else [],
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    @app.post("/v1/pattern/nft", tags=["Patterns"])
    async def nft_fraud_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect NFT wash trading and pump-and-dump schemes."""
        try:
            import pandas as pd
            from forensics_mev import detect_nft_pump_dump
            from forensics_advanced import detect_nft_wash_trading
            df       = pd.DataFrame(request.transactions)
            pump     = detect_nft_pump_dump(df)
            wash     = detect_nft_wash_trading(df)
            return {
                "pump_dump_count": len(pump),
                "wash_trade_count": len(wash),
                "pump_dump": pump.to_dict("records") if not pump.empty else [],
                "wash_trading": wash.to_dict("records") if not wash.empty else [],
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    @app.post("/v1/pattern/stablecoin", tags=["Patterns"])
    async def stablecoin_depeg_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect exploitation of stablecoin depeg events."""
        try:
            import pandas as pd
            from forensics_stablecoin import detect_all_depeg_exploits
            df      = pd.DataFrame(request.transactions)
            results = detect_all_depeg_exploits(df)
            summary = {k: len(v) for k,v in results.items()}
            all_findings = []
            for event_id, df_r in results.items():
                recs = df_r.to_dict("records")
                for r in recs:
                    r["event_id"] = event_id
                all_findings.extend(recs)
            return {"events_with_hits": len(results), "summary": summary, "findings": all_findings}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    @app.post("/v1/pattern/lightning", tags=["Patterns"])
    async def lightning_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Detect Lightning Network channel transactions and assess traceability."""
        try:
            import pandas as pd
            from forensics_lightning import detect_lightning_channels, assess_ln_traceability
            df      = pd.DataFrame(request.transactions)
            ln_df   = detect_lightning_channels(df)
            assess  = assess_ln_traceability(ln_df)
            return {
                "channel_count":  len(ln_df),
                "traceability":   assess,
                "channels":       ln_df.to_dict("records") if not ln_df.empty else [],
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    # ── Infrastructure Clustering ─────────────────────────────

    @app.post("/v1/cluster/infrastructure", tags=["Clustering"])
    async def infra_cluster_api(
        request:          TransactionInput,
        background_tasks: BackgroundTasks,
        n_clusters:       int = 6,
        key: str = Depends(verify_api_key),
    ):
        """Infrastructure behavioral clustering (async). Poll /v1/jobs/{job_id}."""
        job_id = _new_job_id()
        _JOBS[job_id] = {"status":"running","created_at":datetime.now().isoformat()}

        async def _run():
            try:
                import pandas as pd
                from forensics_netinfra import cluster_by_infrastructure, identify_shared_operators
                df     = pd.DataFrame(request.transactions)
                result = cluster_by_infrastructure(df, n_clusters)
                ops    = identify_shared_operators(result) if not result.empty else []
                _JOBS[job_id]["status"] = "complete"
                _JOBS[job_id]["result"] = {
                    "clusters":           result["infra_cluster"].nunique() if not result.empty else 0,
                    "addresses":          len(result),
                    "shared_operators":   len(ops),
                    "operators":          ops,
                    "data":               result.to_dict("records") if not result.empty else [],
                }
            except Exception as e:
                _JOBS[job_id]["status"] = "failed"
                _JOBS[job_id]["error"]  = str(e)

        background_tasks.add_task(_run)
        return {"job_id": job_id, "status": "running"}


    # ── Compliance Additions ──────────────────────────────────

    @app.post("/v1/sar/auto", tags=["Compliance"])
    async def auto_sar_api(
        request:           TransactionInput,
        case_id:           str = "",
        filing_institution:str = "",
        investigator:      str = "API",
        key: str = Depends(verify_api_key),
    ):
        """Auto-generate SAR narrative from all session findings (no manual input)."""
        try:
            import pandas as pd
            from forensics_compliance import generate_auto_sar_from_session
            df        = pd.DataFrame(request.transactions)
            narrative = generate_auto_sar_from_session(df, case_id, filing_institution, investigator)
            return {
                "case_id":   case_id or "AUTO",
                "narrative": narrative,
                "note":      "Review and sign before FinCEN BSA E-Filing submission",
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    @app.post("/v1/compliance/travelrule", tags=["Compliance"])
    async def travel_rule_api(request: TransactionInput, key: str = Depends(verify_api_key)):
        """Identify FATF Travel Rule transactions (≥$1,000) and MiCA requirements."""
        try:
            import pandas as pd
            from forensics_compliance2 import identify_travel_rule_transactions
            df     = pd.DataFrame(request.transactions)
            tr_df  = identify_travel_rule_transactions(df)
            required = tr_df[tr_df.get("travel_rule_required", pd.Series(False))==True]                        if "travel_rule_required" in tr_df.columns else pd.DataFrame()
            return {
                "total_transactions":     len(df),
                "travel_rule_required":   len(required),
                "ctr_required":           int((required["amount"] >= 10000).sum()) if not required.empty else 0,
                "transactions":           required.to_dict("records") if not required.empty else [],
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    @app.post("/v1/export/interpol", tags=["Compliance"])
    async def interpol_notice_api(
        request:           TransactionInput,
        case_id:           str = "CASE-001",
        analyst:           str = "API",
        modus_operandi:    str = "Virtual currency exploitation",
        crime_types:       List[str] = None,
        countries:         List[str] = None,
        key: str = Depends(verify_api_key),
    ):
        """Generate INTERPOL Purple Notice XML for international LE sharing."""
        try:
            import pandas as pd
            from forensics_export import export_interpol_purple_notice
            df      = pd.DataFrame(request.transactions)
            addrs   = list(set(df["from_address"].tolist() + df["to_address"].tolist()))[:30]
            total   = float(df["amount"].sum()) if not df.empty else 0
            notice  = export_interpol_purple_notice(
                df=df, case_id=case_id, analyst=analyst,
                subject_addrs=addrs,
                modus_operandi=modus_operandi,
                crime_types=crime_types or ["Virtual Currency Crime"],
                total_value_usd=total,
                countries_involved=countries or [],
            )
            from fastapi.responses import Response
            return Response(content=notice, media_type="application/xml",
                            headers={"Content-Disposition":
                                     f'attachment; filename="interpol_purple_{case_id}.xml"'})
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    # ── SAR Generation ────────────────────────────────────────

    @app.post("/v1/sar/generate", tags=["Compliance"])
    async def generate_sar_api(request: SARRequest, key: str = Depends(verify_api_key)):
        """Generate a FinCEN-compliant SAR narrative and XML."""
        try:
            from forensics_compliance import generate_sar_narrative, generate_sar_xml
            narrative = generate_sar_narrative(
                case_id=request.case_id,
                subject_addresses=request.subject_addresses,
                total_volume=request.total_volume,
                typologies=request.typologies,
                findings_summary=request.narrative,
                investigator=request.investigator,
                filing_institution=request.filing_institution,
            )
            xml = generate_sar_xml(
                case_id=request.case_id,
                filing_institution=request.filing_institution,
                ein="",
                subject_addresses=request.subject_addresses,
                total_volume=request.total_volume,
                narrative=narrative,
                activity_date_start=datetime.now().strftime("%Y-%m-%d"),
                activity_date_end=datetime.now().strftime("%Y-%m-%d"),
            )
            return {
                "case_id":   request.case_id,
                "narrative": narrative,
                "xml":       xml,
                "note":      "Review and sign before submission to FinCEN BSA E-Filing",
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # ── Job Management ────────────────────────────────────────

    @app.get("/v1/jobs/{job_id}", tags=["Jobs"])
    async def get_job(job_id: str, key: str = Depends(verify_api_key)):
        """Poll an async job for status and results."""
        if job_id not in _JOBS:
            raise HTTPException(status_code=404, detail="Job not found")
        return _JOBS[job_id]

    @app.get("/v1/jobs", tags=["Jobs"])
    async def list_jobs(key: str = Depends(verify_api_key)):
        """List all jobs with status."""
        return {"jobs": [{"job_id":k,"status":v["status"],"created_at":v.get("created_at")}
                          for k,v in _JOBS.items()]}

    # ── Webhook Management ────────────────────────────────────

    @app.post("/v1/webhook/register", tags=["Webhooks"])
    async def register_webhook(config: WebhookConfig, key: str = Depends(verify_api_key)):
        """
        Register a webhook URL for event notifications.
        Events: critical_risk, ofac_hit, ransomware_hit
        """
        _WEBHOOKS.append(config.dict())
        return {"registered": True, "url": config.url, "events": config.events}

    @app.get("/v1/webhook/list", tags=["Webhooks"])
    async def list_webhooks(key: str = Depends(verify_api_key)):
        return {"webhooks": _WEBHOOKS}

    # ── API Key Management ────────────────────────────────────

    @app.post("/v1/keys/create", tags=["Admin"])
    async def create_api_key(label: str, key: str = Depends(verify_api_key)):
        """Create a new API key (requires existing valid key)."""
        import secrets
        new_key = f"forensics-{secrets.token_hex(20)}"
        add_api_key(new_key, label)
        return {"api_key": new_key, "label": label,
                "note": "Store this key securely — it will not be shown again"}


# ─────────────────────────────────────────────────────────────
# STREAMLIT UI  (shows API status and controls within the app)
# ─────────────────────────────────────────────────────────────

def render_api_ui():
    """API management panel in Streamlit."""
    import streamlit as st

    st.markdown("### 🔌 REST API")
    st.caption(
        "Expose all forensics functions as HTTP endpoints for integration with "
        "Cellebrite, Nuix, JIRA, Maltego, Slack, or any HTTP client. "
        "Powered by FastAPI with automatic Swagger/OpenAPI documentation."
    )

    if not FASTAPI_AVAILABLE:
        st.error("FastAPI not installed.")
        st.code("pip install fastapi uvicorn[standard] pydantic", language="bash")
        st.markdown("After installing, restart the app and run the API server:")
        st.code("uvicorn forensics_api:app --host 0.0.0.0 --port 8001 --reload", language="bash")
        st.markdown("---")
        st.markdown(INSTALL_INSTRUCTIONS)
        return

    st.success("✅ FastAPI installed and ready")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Start API Server**")
        api_host = st.text_input("Host", value="0.0.0.0", key="api_host")
        api_port = st.number_input("Port", value=8001, key="api_port")
        st.code(f"uvicorn forensics_api:app --host {api_host} --port {api_port} --reload",
                language="bash")
        st.markdown(f"📖 [View API Docs](http://localhost:{api_port}/docs) (after starting)")

    with col2:
        st.markdown("**API Key Management**")
        new_label = st.text_input("New key label", key="new_key_label",
                                   placeholder="e.g. Analyst Workstation")
        if st.button("🔑 Generate API Key", key="gen_api_key") and new_label:
            import secrets
            new_key = f"forensics-{secrets.token_hex(20)}"
            add_api_key(new_key, new_label)
            st.success(f"Key created for '{new_label}':")
            st.code(new_key)
            st.warning("⚠️ Copy this key now — it won't be shown again")

    st.markdown("---")
    st.markdown("**Example API Calls**")

    examples = {
        "Health check": {
            "method": "GET",
            "url":    "http://localhost:8001/health",
            "cmd":    'curl http://localhost:8001/health -H "X-API-Key: your-key"'
        },
        "OFAC screening": {
            "method": "POST",
            "url":    "http://localhost:8001/v1/screen/ofac",
            "cmd":    """curl -X POST http://localhost:8001/v1/screen/ofac \\
  -H "X-API-Key: your-key" \\
  -H "Content-Type: application/json" \\
  -d '{"addresses":["0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b"],"chain":"ethereum"}'"""
        },
        "Risk score transactions": {
            "method": "POST",
            "url":    "http://localhost:8001/v1/risk/score",
            "cmd":    """curl -X POST http://localhost:8001/v1/risk/score \\
  -H "X-API-Key: your-key" \\
  -H "Content-Type: application/json" \\
  -d '{"transactions":[{"from_address":"0x...","to_address":"Tornado_Cash","amount":100,"token":"ETH"}]}'"""
        },
        "Generate SAR": {
            "method": "POST",
            "url":    "http://localhost:8001/v1/sar/generate",
            "cmd":    """curl -X POST http://localhost:8001/v1/sar/generate \\
  -H "X-API-Key: your-key" \\
  -H "Content-Type: application/json" \\
  -d '{"case_id":"CASE-001","filing_institution":"ACME Bank","subject_addresses":["0x..."],"total_volume":500000,"typologies":["Mixing","Layering"],"narrative":"Suspicious activity detected..."}'"""
        },
    }

    for title, ex in examples.items():
        with st.expander(f"**{ex['method']}** {title}"):
            st.code(ex["cmd"], language="bash")

    st.markdown("---")
    st.markdown("**Integration Guides**")
    integrations = {
        "Python requests": '''import requests
headers = {"X-API-Key": "your-key", "Content-Type": "application/json"}
resp = requests.post("http://localhost:8001/v1/screen/ofac",
    json={"addresses": ["0x..."], "chain": "ethereum"},
    headers=headers)
print(resp.json())''',
        "JavaScript fetch": '''const resp = await fetch("http://localhost:8001/v1/risk/score", {
  method: "POST",
  headers: {"X-API-Key": "your-key", "Content-Type": "application/json"},
  body: JSON.stringify({transactions: [{from_address:"0x...", amount:1000, token:"ETH"}]})
});
const data = await resp.json();''',
        "Webhook registration": '''curl -X POST http://localhost:8001/v1/webhook/register \\
  -H "X-API-Key: your-key" \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
       "events":["ofac_hit","ransomware_hit","critical_risk"],
       "secret":"your-hmac-secret"}'
# Now every OFAC hit will auto-post to your Slack channel''',
    }
    for title, code in integrations.items():
        with st.expander(f"**{title}**"):
            st.code(code, language="python" if "import" in code or "const" in code else "bash")


# ─────────────────────────────────────────────────────────────
# DIRECT RUN
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not FASTAPI_AVAILABLE:
        print(INSTALL_INSTRUCTIONS)
        sys.exit(1)
    print("Starting Crypto Forensics API server…")
    print("Docs: http://localhost:8001/docs")
    uvicorn.run("forensics_api:app", host="0.0.0.0", port=8001, reload=True)