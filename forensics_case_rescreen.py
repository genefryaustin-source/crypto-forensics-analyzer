"""
forensics_case_rescreen.py — Crypto Forensics Analyzer Pro

Versioned case re-screening and investigative enrichment engine.

Design principles:
- Never overwrite prior findings.
- Append immutable screening runs to each case.
- Preserve evidence lineage and analyst action history.
- Allow open/pending/escalated/suspended cases to be re-screened.
- Do not mutate CLOSED cases unless the caller explicitly decides to reopen them.

Primary functions:
- rerun_case_screening()
- append_case_findings()
- calculate_case_delta()
- generate_case_version()
- compare_prior_findings()
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd
import streamlit as st


OPEN_CASE_STATUSES = {"OPEN", "PENDING", "ESCALATED", "SUSPENDED", "UNDER_INVESTIGATION"}
CRYPTO_ADDR_RE = re.compile(
    r"(0x[a-fA-F0-9]{40}|bc1[a-zA-Z0-9]{20,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,40}|T[a-zA-Z0-9]{25,40})"
)


# ─────────────────────────────────────────────────────────────
# Generic helpers
# ─────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_addr(value: Any) -> str:
    return _safe_text(value).lower()


def _case_is_screenable(case: Dict[str, Any]) -> bool:
    status = _safe_text(case.get("status", "OPEN")).upper()
    return status != "CLOSED"


def _stable_fingerprint(payload: Dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _finding_key(finding: Dict[str, Any]) -> str:
    parts = [
        _safe_text(finding.get("source")),
        _safe_text(finding.get("type")),
        _safe_text(finding.get("address")),
        _safe_text(finding.get("entity")),
        _safe_text(finding.get("label")),
        _safe_text(finding.get("jurisdiction")),
    ]
    raw = "|".join(parts).lower()
    if raw.strip("|"):
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    return _stable_fingerprint(finding)


def _ensure_case_lists(case: Dict[str, Any]) -> Dict[str, Any]:
    case.setdefault("screening_runs", [])
    case.setdefault("evidence_log", [])
    case.setdefault("notes", [])
    case.setdefault("case_versions", [])
    case.setdefault("reports", [])
    return case


def _extract_addresses_from_text(value: Any) -> List[str]:
    text = _safe_text(value)
    if not text:
        return []
    return [_normalize_addr(m.group(0)) for m in CRYPTO_ADDR_RE.finditer(text)]


def extract_case_addresses(case: Dict[str, Any], df: Optional[pd.DataFrame] = None) -> List[str]:
    """Collect known addresses from a case plus the active dataset."""
    addrs = set()

    # Direct common case fields
    direct_fields = [
        "address", "wallet", "wallet_address", "subject_address", "suspect_address",
        "victim_address", "scammer_address", "linked_crypto_address", "from_address", "to_address",
    ]
    for field in direct_fields:
        val = case.get(field)
        if val:
            addrs.add(_normalize_addr(val))

    # Scan common text fields for embedded addresses
    for field in ["name", "description", "summary", "narrative", "disposition", "analyst", "le_agency"]:
        addrs.update(_extract_addresses_from_text(case.get(field)))

    # Notes
    for note in case.get("notes", []) or []:
        if isinstance(note, dict):
            addrs.update(_extract_addresses_from_text(note.get("text")))
        else:
            addrs.update(_extract_addresses_from_text(note))

    # Off-chain payments
    for pay in case.get("offchain_payments", []) or []:
        if isinstance(pay, dict):
            for field in ["linked_crypto_address", "linked_tx_hash", "description", "notes"]:
                if field == "linked_crypto_address" and pay.get(field):
                    addrs.add(_normalize_addr(pay.get(field)))
                else:
                    addrs.update(_extract_addresses_from_text(pay.get(field)))

    # Evidence files metadata
    for ev in case.get("evidence_files", []) or []:
        if isinstance(ev, dict):
            for field in ["linked_address", "description", "filename"]:
                if field == "linked_address" and ev.get(field):
                    addrs.add(_normalize_addr(ev.get(field)))
                else:
                    addrs.update(_extract_addresses_from_text(ev.get(field)))

    # Fallback: if no case-specific address exists, collect top risky addresses from dataset.
    # This allows a newly created case to be enriched from the current loaded investigation.
    if not addrs and isinstance(df, pd.DataFrame) and not df.empty:
        work = df.copy()
        for col in ["from_address", "to_address"]:
            if col in work.columns:
                if "risk_level" in work.columns:
                    subset = work[work["risk_level"].astype(str).str.upper().isin(["CRITICAL", "HIGH"])]
                    if subset.empty:
                        subset = work
                else:
                    subset = work
                addrs.update(
                    subset[col]
                    .dropna()
                    .astype(str)
                    .str.strip()
                    .str.lower()
                    .head(50)
                    .tolist()
                )

    invalid = {"", "nan", "none", "null", "unknown"}
    return sorted(a for a in addrs if a and a not in invalid)



def _case_evidence_snapshot(case: Dict[str, Any], findings: List[Dict[str, Any]], df: Optional[pd.DataFrame]) -> Dict[str, Any]:
    """Build a compact immutable snapshot for report lineage."""
    snapshot = {
        "case_id": case.get("case_id", "UNKNOWN"),
        "case_status": case.get("status", "OPEN"),
        "case_priority": case.get("priority", case.get("risk_level", "LOW")),
        "captured_at": _now(),
        "finding_count": len(findings or []),
        "critical_findings": sum(1 for f in findings or [] if str(f.get("risk_level", "")).upper() == "CRITICAL"),
        "high_findings": sum(1 for f in findings or [] if str(f.get("risk_level", "")).upper() == "HIGH"),
        "evidence_events": len(case.get("evidence_log", []) or []),
        "prior_reports": len(case.get("reports", []) or []),
        "dataset_rows": int(len(df)) if isinstance(df, pd.DataFrame) else 0,
    }
    if isinstance(df, pd.DataFrame) and not df.empty:
        for col in ["from_address", "to_address"]:
            if col in df.columns:
                snapshot[f"unique_{col}"] = int(df[col].dropna().astype(str).nunique())
        if "amount" in df.columns:
            snapshot["dataset_total_amount"] = float(pd.to_numeric(df["amount"], errors="coerce").fillna(0).sum())
        if "risk_level" in df.columns:
            snapshot["risk_distribution"] = df["risk_level"].fillna("LOW").astype(str).str.upper().value_counts().to_dict()
    return snapshot


def _case_compliance_lineage(case: Dict[str, Any], run: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Capture compliance lineage for the generated report version."""
    jurisdictions = sorted({str(f.get("jurisdiction", "")).strip() for f in findings or [] if str(f.get("jurisdiction", "")).strip()})
    sources = sorted({str(f.get("source", "")).strip() for f in findings or [] if str(f.get("source", "")).strip()})
    return {
        "case_id": case.get("case_id", "UNKNOWN"),
        "run_id": run.get("run_id", ""),
        "version_id": run.get("version_id", ""),
        "actions": run.get("actions", []),
        "sources": sources or run.get("sources", []),
        "jurisdictions": jurisdictions,
        "analyst": run.get("analyst", "system"),
        "generated_at": _now(),
        "sar_recommended": any(str(f.get("risk_level", "")).upper() in {"CRITICAL", "HIGH"} for f in findings or []),
        "status_after": case.get("status", "OPEN"),
        "priority_after": case.get("priority", case.get("risk_level", "LOW")),
    }

# ─────────────────────────────────────────────────────────────
# Requested public functions
# ─────────────────────────────────────────────────────────────

def generate_case_version(case: Dict[str, Any]) -> Dict[str, Any]:
    """Return the next immutable case version descriptor."""
    prior_versions = case.get("case_versions", []) or []
    prior_runs = case.get("screening_runs", []) or []
    next_number = max(len(prior_versions), len(prior_runs)) + 1
    version_id = f"CASE-RUN-{next_number:04d}"
    return {
        "version_id": version_id,
        "version_number": next_number,
        "generated_at": _now(),
        "case_id": case.get("case_id", "UNKNOWN"),
    }


def compare_prior_findings(
    prior_findings: Optional[Iterable[Dict[str, Any]]],
    new_findings: Optional[Iterable[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Compare prior and new finding sets by stable finding key."""
    prior_findings = list(prior_findings or [])
    new_findings = list(new_findings or [])

    prior_map = {_finding_key(f): f for f in prior_findings if isinstance(f, dict)}
    new_map = {_finding_key(f): f for f in new_findings if isinstance(f, dict)}

    prior_keys = set(prior_map)
    new_keys = set(new_map)

    added_keys = new_keys - prior_keys
    removed_keys = prior_keys - new_keys
    unchanged_keys = new_keys & prior_keys

    return {
        "new": [new_map[k] for k in sorted(added_keys)],
        "removed": [prior_map[k] for k in sorted(removed_keys)],
        "unchanged": [new_map[k] for k in sorted(unchanged_keys)],
        "new_count": len(added_keys),
        "removed_count": len(removed_keys),
        "unchanged_count": len(unchanged_keys),
    }


def calculate_case_delta(case: Dict[str, Any], new_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate the delta between the most recent screening run and new findings."""
    runs = case.get("screening_runs", []) or []
    prior_findings = []
    if runs:
        latest = runs[-1]
        prior_findings = latest.get("findings", []) or []
    delta = compare_prior_findings(prior_findings, new_findings)
    delta["prior_run_count"] = len(runs)
    return delta


def append_case_findings(
    case: Dict[str, Any],
    findings: List[Dict[str, Any]],
    run_metadata: Optional[Dict[str, Any]] = None,
    analyst: str = "system",
) -> Dict[str, Any]:
    """Append a versioned screening run and evidence log entries without overwriting old findings."""
    case = _ensure_case_lists(case)
    run_metadata = dict(run_metadata or {})
    version = generate_case_version(case)
    delta = calculate_case_delta(case, findings)

    run_record = {
        **version,
        "run_id": run_metadata.get("run_id") or f"screen_{uuid.uuid4().hex[:12]}",
        "analyst": analyst or "system",
        "sources": run_metadata.get("sources", []),
        "actions": run_metadata.get("actions", []),
        "addresses_screened": run_metadata.get("addresses_screened", []),
        "findings": findings,
        "finding_count": len(findings),
        "delta": delta,
        "risk_before": case.get("priority", case.get("risk_level", "LOW")),
    }

    # Escalate priority/status if new serious findings appear.
    severities = [str(f.get("risk_level", f.get("severity", ""))).upper() for f in findings]
    if "CRITICAL" in severities:
        case["priority"] = "CRITICAL"
        if str(case.get("status", "OPEN")).upper() != "CLOSED":
            case["status"] = "ESCALATED"
    elif "HIGH" in severities and str(case.get("priority", "LOW")).upper() not in {"CRITICAL", "HIGH"}:
        case["priority"] = "HIGH"

    run_record["risk_after"] = case.get("priority", case.get("risk_level", "LOW"))
    case["screening_runs"].append(run_record)
    case["case_versions"].append(version)

    # Append evidence lineage entries.
    evidence_entry = {
        "timestamp": _now(),
        "action": "CASE_RESCREEN_RUN_APPENDED",
        "analyst": analyst or "system",
        "version_id": version["version_id"],
        "run_id": run_record["run_id"],
        "finding_count": len(findings),
        "new_finding_count": delta.get("new_count", 0),
        "sources": run_record["sources"],
        "entry_hash": _stable_fingerprint(run_record),
    }
    case["evidence_log"].append(evidence_entry)

    if delta.get("new_count", 0) > 0:
        case["notes"].append({
            "timestamp": _now(),
            "text": (
                f"Versioned re-screen {version['version_id']} appended "
                f"{delta['new_count']} new finding(s) from {', '.join(run_record['sources'])}."
            ),
        })

    case["updated_at"] = _now()
    return case


def rerun_case_screening(
    case: Dict[str, Any],
    df: Optional[pd.DataFrame] = None,
    *,
    run_global_sanctions: bool = True,
    rebuild_entity_graph: bool = True,
    recompute_chain_hops: bool = True,
    rerun_ai: bool = False,
    generate_report: bool = False,
    analyst: str = "system",
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Run selected re-screening actions and append a versioned case update."""
    if not isinstance(case, dict):
        raise ValueError("case must be a dictionary")

    if not _case_is_screenable(case):
        result = {
            "success": False,
            "message": "Closed cases are immutable. Reopen the case before re-screening.",
            "findings": [],
        }
        return case, result

    addresses = extract_case_addresses(case, df)
    findings: List[Dict[str, Any]] = []
    sources: List[str] = []
    actions: List[str] = []

    if run_global_sanctions:
        actions.append("global_sanctions")
        sanctions_findings = _run_global_sanctions(addresses)
        findings.extend(sanctions_findings)
        sources.extend(sorted({f.get("source", "GlobalSanctions") for f in sanctions_findings}) or ["GlobalSanctions"])

    if rebuild_entity_graph:
        actions.append("entity_graph")
        graph_findings = _rebuild_entity_graph(addresses, df)
        findings.extend(graph_findings)
        sources.append("EntityGraph")

    if recompute_chain_hops:
        actions.append("chain_hops")
        hop_findings = _recompute_chain_hops(addresses, df)
        findings.extend(hop_findings)
        sources.append("ChainHopCorrelation")

    if rerun_ai:
        actions.append("ai_narrative")
        ai_finding = _generate_ai_case_summary(case, findings)
        findings.append(ai_finding)
        sources.append("AINarrative")

    if generate_report:
        actions.append("updated_report")
        sources.append("UpdatedReport")

    # Deduplicate source names while preserving order.
    seen = set()
    deduped_sources = []
    for s in sources:
        if s not in seen:
            seen.add(s)
            deduped_sources.append(s)

    run_metadata = {
        "sources": deduped_sources,
        "actions": actions,
        "addresses_screened": addresses,
    }

    updated_case = append_case_findings(case, findings, run_metadata, analyst=analyst)
    latest_run = updated_case.get("screening_runs", [])[-1] if updated_case.get("screening_runs") else {}

    report_meta = None
    if generate_report:
        try:
            from forensics_report_registry import create_case_report

            updated_case, report_meta = create_case_report(
                updated_case,
                df,
                analyst=analyst,
                classification="CONFIDENTIAL",
                report_type="case_rescreen",
                run_id=latest_run.get("run_id", ""),
                version_id=latest_run.get("version_id", ""),
                summary=(
                    f"Updated case report generated from {latest_run.get('version_id', 'latest case version')} "
                    f"with {len(findings)} appended finding(s)."
                ),
                evidence_snapshot=_case_evidence_snapshot(updated_case, findings, df),
                findings_delta=latest_run.get("delta", {}),
                compliance_lineage=_case_compliance_lineage(updated_case, latest_run, findings),
            )
            # Link report metadata directly to the run for lineage.
            latest_run["report"] = report_meta
            latest_run["report_path"] = report_meta.get("report_path", "")
            latest_run["report_version"] = report_meta.get("version")
            report_finding = {
                "type": "UPDATED_REPORT_AVAILABLE",
                "source": "UpdatedReport",
                "address": "",
                "label": f"Updated PDF report v{report_meta.get('version')} registered for download.",
                "risk_level": "LOW",
                "confidence": 100,
                "report_path": report_meta.get("report_path", ""),
                "report_version": report_meta.get("version"),
            }
            findings.append(report_finding)
            latest_run.setdefault("findings", []).append(report_finding)
            latest_run["finding_count"] = len(latest_run.get("findings", []))
        except Exception as e:
            latest_run["report_error"] = str(e)
            fail_finding = {
                "type": "UPDATED_REPORT_FAILED",
                "source": "UpdatedReport",
                "address": "",
                "label": f"Updated report generation failed: {e}",
                "risk_level": "MEDIUM",
                "confidence": 100,
            }
            findings.append(fail_finding)
            latest_run.setdefault("findings", []).append(fail_finding)
            latest_run["finding_count"] = len(latest_run.get("findings", []))

    result = {
        "success": True,
        "message": "Case re-screen completed and appended as a new version." + (" Updated PDF report is available below." if report_meta else ""),
        "addresses_screened": addresses,
        "finding_count": len(findings),
        "new_finding_count": latest_run.get("delta", {}).get("new_count", 0),
        "run": latest_run,
        "findings": findings,
        "report": report_meta,
    }
    return updated_case, result


# ─────────────────────────────────────────────────────────────
# Screening implementations
# ─────────────────────────────────────────────────────────────

def _run_global_sanctions(addresses: List[str]) -> List[Dict[str, Any]]:
    """Use already-run sanctions data if available; fall back to session result sets."""
    findings: List[Dict[str, Any]] = []
    addr_set = {_normalize_addr(a) for a in addresses}
    if not addr_set:
        return findings

    # Preferred: optional global sanctions module from the prior expansion.
    try:
        from forensics_global_sanctions import screen_addresses_global  # type: ignore
        try:
            results = screen_addresses_global(list(addr_set))
        except TypeError:
            results = screen_addresses_global(list(addr_set), None)
        if isinstance(results, pd.DataFrame) and not results.empty:
            for _, row in results.iterrows():
                findings.append({
                    "type": "GLOBAL_SANCTIONS_MATCH",
                    "source": row.get("source", "GlobalSanctions"),
                    "jurisdiction": row.get("jurisdiction", "GLOBAL"),
                    "address": _normalize_addr(row.get("address", "")),
                    "label": row.get("label", row.get("entity", row.get("match_type", "Sanctions match"))),
                    "risk_level": row.get("risk_level", "CRITICAL"),
                    "confidence": row.get("confidence", 90),
                })
            return findings
    except Exception:
        pass

    # Fallback: inspect common session_state result dataframes created by OSINT modules.
    session_sources = {
        "ofac_df": ("OFAC", "US", "ofac_hit", "ofac_entity"),
        "global_sanctions_df": ("GlobalSanctions", "GLOBAL", "sanctions_hit", "entity"),
        "opensanctions_df": ("OpenSanctions", "GLOBAL", "hit", "entity"),
        "eu_sanctions_df": ("EU", "EU", "hit", "entity"),
        "uk_sanctions_df": ("UK OFSI", "UK", "hit", "entity"),
        "un_sanctions_df": ("UN", "UN", "hit", "entity"),
    }

    for key, (source, jurisdiction, hit_col, entity_col) in session_sources.items():
        sdf = st.session_state.get(key)
        if not isinstance(sdf, pd.DataFrame) or sdf.empty:
            continue
        work = sdf.copy()
        for addr_col in ["address", "from_address", "to_address", "wallet", "wallet_address"]:
            if addr_col not in work.columns:
                continue
            mask = work[addr_col].fillna("").astype(str).str.lower().isin(addr_set)
            if hit_col in work.columns:
                mask = mask & work[hit_col].fillna(False).astype(bool)
            for _, row in work[mask].iterrows():
                findings.append({
                    "type": "GLOBAL_SANCTIONS_MATCH",
                    "source": source,
                    "jurisdiction": jurisdiction,
                    "address": _normalize_addr(row.get(addr_col, "")),
                    "label": row.get(entity_col, "Sanctions/watchlist match"),
                    "risk_level": "CRITICAL" if source in {"OFAC", "UN"} else "HIGH",
                    "confidence": 95 if source == "OFAC" else 85,
                })

    return findings


def _rebuild_entity_graph(addresses: List[str], df: Optional[pd.DataFrame]) -> List[Dict[str, Any]]:
    if not isinstance(df, pd.DataFrame) or df.empty or not addresses:
        return []
    if not {"from_address", "to_address"}.issubset(df.columns):
        return []

    work = df.copy()
    work["from_norm"] = work["from_address"].fillna("").astype(str).str.lower().str.strip()
    work["to_norm"] = work["to_address"].fillna("").astype(str).str.lower().str.strip()
    if "amount" in work.columns:
        work["amount_num"] = pd.to_numeric(work["amount"], errors="coerce").fillna(0)
    else:
        work["amount_num"] = 0

    addr_set = set(addresses)
    related = work[work["from_norm"].isin(addr_set) | work["to_norm"].isin(addr_set)]
    if related.empty:
        return []

    counterparties = []
    for addr in sorted(addr_set):
        sent = related[related["from_norm"] == addr]
        recv = related[related["to_norm"] == addr]
        cps = set(sent["to_norm"].tolist()) | set(recv["from_norm"].tolist())
        cps.discard(addr)
        if cps:
            counterparties.append({
                "type": "ENTITY_GRAPH_REBUILD",
                "source": "EntityGraph",
                "address": addr,
                "label": f"{len(cps)} linked counterparty address(es)",
                "counterparty_count": len(cps),
                "tx_count": int(len(sent) + len(recv)),
                "volume": float(sent["amount_num"].sum() + recv["amount_num"].sum()),
                "risk_level": "HIGH" if len(cps) >= 10 else "MEDIUM" if len(cps) >= 3 else "LOW",
                "confidence": 75,
            })
    return counterparties


def _recompute_chain_hops(addresses: List[str], df: Optional[pd.DataFrame]) -> List[Dict[str, Any]]:
    if not isinstance(df, pd.DataFrame) or df.empty or not addresses:
        return []
    if not {"from_address", "to_address"}.issubset(df.columns):
        return []

    work = df.copy()
    work["from_norm"] = work["from_address"].fillna("").astype(str).str.lower().str.strip()
    work["to_norm"] = work["to_address"].fillna("").astype(str).str.lower().str.strip()
    if "chain" in work.columns:
        work["chain_norm"] = work["chain"].fillna("Unknown").astype(str)
    else:
        work["chain_norm"] = "Unknown"
    if "amount" in work.columns:
        work["amount_num"] = pd.to_numeric(work["amount"], errors="coerce").fillna(0)
    else:
        work["amount_num"] = 0

    findings = []
    addr_set = set(addresses)
    edges = work[work["from_norm"].isin(addr_set) | work["to_norm"].isin(addr_set)]
    if edges.empty:
        return findings

    for addr in sorted(addr_set):
        sub = edges[(edges["from_norm"] == addr) | (edges["to_norm"] == addr)]
        if sub.empty:
            continue
        chains = sorted(set(sub["chain_norm"].dropna().astype(str).tolist()))
        bridge_like = sub[
            sub[["from_address", "to_address"]]
            .astype(str)
            .agg(" ".join, axis=1)
            .str.lower()
            .str.contains("bridge|multichain|anyswap|wormhole|stargate|hop", regex=True, na=False)
        ]
        if len(chains) > 1 or not bridge_like.empty:
            findings.append({
                "type": "CHAIN_HOP_CORRELATION",
                "source": "ChainHopCorrelation",
                "address": addr,
                "label": f"Activity spans {len(chains)} chain(s); bridge-like txs: {len(bridge_like)}",
                "chains": chains,
                "bridge_like_tx_count": int(len(bridge_like)),
                "tx_count": int(len(sub)),
                "volume": float(sub["amount_num"].sum()),
                "risk_level": "HIGH" if not bridge_like.empty or len(chains) > 2 else "MEDIUM",
                "confidence": 70,
            })
    return findings


def _generate_ai_case_summary(case: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    critical = sum(1 for f in findings if str(f.get("risk_level", "")).upper() == "CRITICAL")
    high = sum(1 for f in findings if str(f.get("risk_level", "")).upper() == "HIGH")
    summary = (
        f"Case {case.get('case_id', 'UNKNOWN')} was re-screened. "
        f"The run identified {len(findings)} finding(s), including {critical} critical "
        f"and {high} high-risk item(s). Review sanctions and exposure findings before closure."
    )
    return {
        "type": "AI_CASE_NARRATIVE",
        "source": "AINarrative",
        "address": "",
        "label": summary,
        "risk_level": "HIGH" if critical or high else "LOW",
        "confidence": 60,
    }


def _generate_report_stub(case: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "type": "UPDATED_REPORT_REQUESTED",
        "source": "UpdatedReport",
        "address": "",
        "label": "Updated report generation requested. If successful, the PDF is available in the Investigation Reports panel below.",
        "risk_level": "LOW",
        "confidence": 100,
    }


# ─────────────────────────────────────────────────────────────
# Streamlit UI component for case dashboard
# ─────────────────────────────────────────────────────────────

def render_case_rescreen_ui(
    cases: List[Dict[str, Any]],
    case_idx: int,
    df: Optional[pd.DataFrame] = None,
    *,
    save_cases_fn=None,
    analyst: str = "system",
) -> List[Dict[str, Any]]:
    """Render re-screening controls for one case and return updated cases."""
    case = cases[case_idx]
    status = _safe_text(case.get("status", "OPEN")).upper()

    st.markdown("### 🔄 Versioned Case Re-Screening")
    st.caption(
        "Append-only re-screening. Prior findings, prior sanctions results, and prior reports are preserved."
    )

    if status == "CLOSED":
        st.warning("This case is CLOSED. Reopen or change status before appending a new screening run.")
        return cases

    addresses = extract_case_addresses(case, df)
    c1, c2, c3 = st.columns(3)
    c1.metric("Known Addresses", len(addresses))
    c2.metric("Prior Runs", len(case.get("screening_runs", []) or []))
    c3.metric("Evidence Events", len(case.get("evidence_log", []) or []))

    if addresses:
        with st.expander("Screened addresses", expanded=False):
            st.dataframe(pd.DataFrame({"address": addresses}), use_container_width=True, hide_index=True)
    else:
        st.info("No case-specific address found. The engine will use top risky addresses from the active dataset if available.")

    st.markdown("**Run one action or the full governed re-screen.**")
    b1, b2, b3 = st.columns(3)
    b4, b5, b6 = st.columns(3)

    action = None
    if b1.button("🔄 Re-Screen Case", key=f"case_rescreen_all_{case_idx}", use_container_width=True):
        action = "all"
    if b2.button("🌍 Run Global Sanctions", key=f"case_rescreen_sanctions_{case_idx}", use_container_width=True):
        action = "sanctions"
    if b3.button("🧬 Rebuild Entity Graph", key=f"case_rescreen_graph_{case_idx}", use_container_width=True):
        action = "graph"
    if b4.button("⛓ Recompute Chain Hops", key=f"case_rescreen_hops_{case_idx}", use_container_width=True):
        action = "hops"
    if b5.button("🧠 Re-run AI Narrative", key=f"case_rescreen_ai_{case_idx}", use_container_width=True):
        action = "ai"
    if b6.button("📑 Generate Updated Report", key=f"case_rescreen_report_{case_idx}", use_container_width=True):
        action = "report"

    if action:
        with st.spinner("Appending versioned case re-screening run…"):
            updated_case, result = rerun_case_screening(
                case,
                df,
                run_global_sanctions=action in {"all", "sanctions"},
                rebuild_entity_graph=action in {"all", "graph"},
                recompute_chain_hops=action in {"all", "hops"},
                rerun_ai=action in {"all", "ai"},
                generate_report=action in {"all", "report"},
                analyst=analyst,
            )
            cases[case_idx] = updated_case
            if save_cases_fn:
                save_cases_fn(cases)
            st.session_state[f"case_rescreen_result_{case_idx}"] = result
        st.success(result.get("message", "Case re-screen complete."))
        st.rerun()

    result = st.session_state.get(f"case_rescreen_result_{case_idx}")
    if result:
        st.markdown("#### Latest Re-Screen Result")
        r1, r2, r3 = st.columns(3)
        r1.metric("Findings", result.get("finding_count", 0))
        r2.metric("New Findings", result.get("new_finding_count", 0))
        r3.metric("Addresses", len(result.get("addresses_screened", []) or []))

        findings = result.get("findings", []) or []
        if findings:
            show = pd.DataFrame(findings)
            cols = [c for c in ["type", "source", "jurisdiction", "address", "label", "risk_level", "confidence"] if c in show.columns]
            st.dataframe(show[cols] if cols else show, use_container_width=True, hide_index=True)
        else:
            st.info("No findings were generated in the latest run.")

        report_meta = result.get("report") or result.get("run", {}).get("report")
        if report_meta:
            st.markdown("#### 📄 Latest Generated Report")
            try:
                from forensics_report_registry import read_report_bytes
                pdf_bytes = read_report_bytes(report_meta)
                if pdf_bytes:
                    st.download_button(
                        "📥 Open / Download Latest Updated PDF",
                        data=pdf_bytes,
                        file_name=report_meta.get("filename", "updated_case_report.pdf"),
                        mime="application/pdf",
                        key=f"latest_rescreen_report_download_{case_idx}_{report_meta.get('version', 'latest')}",
                        use_container_width=True,
                    )
                else:
                    st.warning("Latest report metadata exists, but the PDF file was not found on disk.")
            except Exception as e:
                st.warning(f"Latest report download unavailable: {e}")

    # Refresh the local case reference in case the caller saved or reran before this render.
    case = cases[case_idx]
    try:
        from forensics_report_registry import render_case_reports_panel
        render_case_reports_panel(case, case_idx=case_idx)
    except Exception as e:
        st.warning(f"Report registry unavailable: {e}")

    runs = case.get("screening_runs", []) or []
    if runs:
        st.markdown("#### Screening Lineage")
        lineage = []
        for run in reversed(runs[-10:]):
            lineage.append({
                "version": run.get("version_id"),
                "timestamp": run.get("generated_at"),
                "analyst": run.get("analyst"),
                "actions": ", ".join(run.get("actions", [])),
                "sources": ", ".join(run.get("sources", [])),
                "findings": run.get("finding_count", 0),
                "new": run.get("delta", {}).get("new_count", 0),
                "risk_after": run.get("risk_after", ""),
            })
        st.dataframe(pd.DataFrame(lineage), use_container_width=True, hide_index=True)

    return cases
