"""
forensics_report_registry.py — Crypto Forensics Analyzer Pro

Persistent, versioned case report registry.

Purpose:
- Save generated PDF reports to disk instead of leaving them only in memory.
- Attach report metadata to regulatory case records.
- Preserve immutable report history per case.
- Provide Streamlit download/open controls for Case Dashboard and PDF Report pages.

Design:
- Reports are stored under case_reports/<CASE_ID>/.
- Case records keep lightweight metadata only.
- No prior report is overwritten.
"""

from __future__ import annotations
import os
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st
import hashlib
import uuid
REPORT_ROOT = Path("case_reports")
REPORT_ROOT.mkdir(exist_ok=True)
REGISTRY_FILE = REPORT_ROOT / "report_registry.json"


def _load_registry() -> Dict[str, List[Dict[str, Any]]]:
    if not REGISTRY_FILE.exists():
        return {}
    try:
        data = json.loads(REGISTRY_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_registry(registry: Dict[str, List[Dict[str, Any]]]) -> None:
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_FILE.write_text(json.dumps(registry, indent=2, default=str))


def _append_registry(case_id: Any, metadata: Dict[str, Any]) -> None:
    safe_id = _safe_case_id(case_id)
    registry = _load_registry()
    rows = registry.setdefault(safe_id, [])
    # idempotent on exact report path
    path = str(metadata.get("report_path", ""))
    if path and not any(str(r.get("report_path", "")) == path for r in rows):
        rows.append(metadata)
    registry[safe_id] = rows
    _save_registry(registry)


def _registry_reports_for_case(case_id: Any) -> List[Dict[str, Any]]:
    registry = _load_registry()
    return [r for r in registry.get(_safe_case_id(case_id), []) if isinstance(r, dict)]


def _now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _safe_case_id(case_id: Any) -> str:
    raw = str(case_id or "UNKNOWN_CASE").strip()
    raw = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)
    return raw[:96] or "UNKNOWN_CASE"


def _case_report_dir(case_id: Any) -> Path:
    path = REPORT_ROOT / _safe_case_id(case_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _next_report_version(case: Dict[str, Any]) -> int:
    reports = case.get("reports", []) or []
    versions = []
    for r in reports:
        try:
            versions.append(int(r.get("version", 0)))
        except Exception:
            pass
    return (max(versions) + 1) if versions else 1


def _write_report_bytes(report_path: Path, pdf_bytes: bytes) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_bytes(pdf_bytes)


def register_case_report(
    case: Dict[str, Any],
    *,
    pdf_bytes: bytes,
    report_type: str = "case_rescreen",
    analyst: str = "system",
    run_id: str = "",
    version_id: str = "",
    summary: str = "",
    sections_included: Optional[List[str]] = None,
    evidence_snapshot: Optional[Dict[str, Any]] = None,
    findings_delta: Optional[Dict[str, Any]] = None,
    compliance_lineage: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Persist a PDF report and append immutable metadata to the case record."""
    case.setdefault("reports", [])
    case.setdefault("evidence_log", [])

    case_id = case.get("case_id", "UNKNOWN_CASE")
    version = _next_report_version(case)
    ts = _now()
    timestamp_label = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{_safe_case_id(case_id)}_report_v{version:03d}_{timestamp_label}.pdf"
    report_path = _case_report_dir(case_id) / filename

    _write_report_bytes(report_path, pdf_bytes)

    metadata = {
        "version": version,
        "report_id": f"REPORT-{version:04d}",
        "timestamp": ts,
        "case_id": case_id,
        "report_type": report_type,
        "analyst": analyst or "system",
        "run_id": run_id or "",
        "version_id": version_id or "",
        "filename": filename,
        "report_path": str(report_path),
        "size_bytes": int(len(pdf_bytes)),
        "summary": summary or f"Case report v{version} generated.",
        "sections_included": sections_included or [],
        "evidence_snapshot": evidence_snapshot or {},
        "findings_delta": findings_delta or {},
        "compliance_lineage": compliance_lineage or {},
    }

    case["reports"].append(metadata)
    case["latest_report_path"] = str(report_path)
    case["latest_report_version"] = version
    case["latest_report_id"] = metadata["report_id"]
    case["latest_report_timestamp"] = ts
    case["updated_at"] = ts

    _append_registry(case_id, metadata)

    case["evidence_log"].append({
        "timestamp": ts,
        "action": "CASE_REPORT_REGISTERED",
        "analyst": analyst or "system",
        "report_id": metadata["report_id"],
        "report_version": version,
        "run_id": run_id or "",
        "version_id": version_id or "",
        "report_path": str(report_path),
        "size_bytes": int(len(pdf_bytes)),
    })

    st.session_state["latest_case_report"] = metadata
    st.session_state["latest_report_path"] = str(report_path)

    return metadata


def create_case_report(
    case: Dict[str, Any],
    df: Optional[pd.DataFrame],
    *,
    analyst: str = "system",
    classification: str = "CONFIDENTIAL",
    report_type: str = "case_rescreen",
    run_id: str = "",
    version_id: str = "",
    summary: str = "",
    evidence_snapshot: Optional[Dict[str, Any]] = None,
    findings_delta: Optional[Dict[str, Any]] = None,
    compliance_lineage: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Generate a full PDF report, persist it, and attach metadata to the case."""
    if df is None or not isinstance(df, pd.DataFrame):
        df = pd.DataFrame()

    try:
        from forensics_fullreport import generate_full_report
    except Exception as e:
        raise RuntimeError(f"Unable to import generate_full_report: {e}") from e

    case_id = str(case.get("case_id", "UNKNOWN_CASE"))
    analyst_name = analyst or case.get("analyst", "system") or "system"

    pdf_buf = generate_full_report(
        df=df,
        case_id=case_id,
        analyst=analyst_name,
        classification=classification,
    )

    pdf_bytes = pdf_buf.getvalue()
    metadata = register_case_report(
        case,
        pdf_bytes=pdf_bytes,
        report_type=report_type,
        analyst=analyst_name,
        run_id=run_id,
        version_id=version_id,
        summary=summary,
        evidence_snapshot=evidence_snapshot,
        findings_delta=findings_delta,
        compliance_lineage=compliance_lineage,
    )

    return case, metadata


def get_case_reports(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return registered reports, including a safe fallback for older cases.

    Some earlier builds stored latest_report_path without appending a full
    reports[] entry. This function surfaces those legacy records so the UI
    never hides a generated report.
    """
    reports = case.get("reports", []) or []
    reports = [r for r in reports if isinstance(r, dict)]

    # Merge sidecar registry so report visibility survives older DB schemas,
    # migration gaps, and Streamlit reruns.
    for rr in _registry_reports_for_case(case.get("case_id", "")):
        if not any(str(r.get("report_path", "")) == str(rr.get("report_path", "")) for r in reports):
            reports.append(rr)

    latest_path = case.get("latest_report_path")
    if latest_path and not any(str(r.get("report_path", "")) == str(latest_path) for r in reports):
        path = Path(str(latest_path))
        reports.append({
            "version": case.get("latest_report_version", 1),
            "report_id": f"REPORT-{case.get('latest_report_version', 1):04d}",
            "timestamp": case.get("updated_at", ""),
            "case_id": case.get("case_id", ""),
            "report_type": "legacy_latest_report",
            "analyst": case.get("analyst", "system"),
            "filename": path.name,
            "report_path": str(path),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "summary": "Recovered latest report reference from case metadata.",
        })

    def _version(r):
        try:
            return int(r.get("version", 0))
        except Exception:
            return 0

    return sorted(reports, key=_version, reverse=True)


def get_latest_case_report(case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    reports = get_case_reports(case)
    return reports[0] if reports else None


def read_report_bytes(report_meta: Dict[str, Any]) -> Optional[bytes]:
    path = Path(str(report_meta.get("report_path", "")))
    if not path.exists() or not path.is_file():
        return None
    try:
        return path.read_bytes()
    except Exception:
        return None


def render_case_reports_panel(case: Dict[str, Any], *, case_idx: int = 0) -> None:
    """Render report history and download controls for one case."""
    reports = get_case_reports(case)
    st.markdown("### 📑 Investigation Reports")
    st.caption("Versioned reports generated for this case. Prior reports are preserved and never overwritten.")

    if not reports:
        st.info("No reports have been generated for this case yet. Use 📑 Generate Updated Report in Re-Screen.")
        return

    summary_rows = []
    for r in reports:
        summary_rows.append({
            "Version": f"v{r.get('version', '')}",
            "Generated": r.get("timestamp", ""),
            "Type": r.get("report_type", ""),
            "Analyst": r.get("analyst", ""),
            "Run": r.get("run_id", ""),
            "File": r.get("filename", ""),
            "Size KB": round((int(r.get("size_bytes", 0)) or 0) / 1024, 1),
        })

    st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)



    for idx, r in enumerate(reports):

        label = (
            f"📄 v{r.get('version')} — "
            f"{r.get('timestamp', '')} — "
            f"{r.get('report_type', '')}"
        )

        with st.expander(
                label,
                expanded=(idx == 0)
        ):

            st.write(
                r.get("summary", "")
            )

            pdf_bytes = read_report_bytes(r)

            if pdf_bytes:

                report_path = r.get(
                    "report_path",
                    ""
                )

                timestamp = r.get(
                    "timestamp",
                    ""
                )

                version = r.get(
                    "version",
                    ""
                )



                unique_key = (
                    f"{case_idx}_"
                    f"{idx}_"
                    f"{uuid.uuid4().hex}"
                )

                st.download_button(
                    "📥 Open / Download PDF Report",
                    data=pdf_bytes,
                    file_name=r.get(
                        "filename",
                        "case_report.pdf"
                    ),
                    mime="application/pdf",
                    key=f"download_case_report_{unique_key}",
                    use_container_width=True,
                )

            else:

                st.warning(
                    "Report file is registered but the PDF file was not found on disk. "
                    "Generate a new updated report from the Re-Screen tab."
                )

                st.caption(
                    f"Registered path: {r.get('report_path', '')}"
                )


def load_all_registered_reports(cases: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for c in cases or []:
        for r in get_case_reports(c):
            rows.append({
                "case_id": c.get("case_id", ""),
                "case_name": c.get("name", ""),
                "version": r.get("version", ""),
                "timestamp": r.get("timestamp", ""),
                "report_type": r.get("report_type", ""),
                "analyst": r.get("analyst", ""),
                "filename": r.get("filename", ""),
                "report_path": r.get("report_path", ""),
            })
    return pd.DataFrame(rows)


def render_all_case_reports_panel(cases: List[Dict[str, Any]]) -> None:
    st.markdown("### 📁 Registered Case Reports")
    rows = load_all_registered_reports(cases)
    if rows.empty:
        st.info("No case reports are currently registered.")
        return
    st.dataframe(rows.drop(columns=["report_path"], errors="ignore"), use_container_width=True, hide_index=True)

    selected = st.selectbox(
        "Open registered report",
        options=list(range(len(rows))),
        format_func=lambda i: f"{rows.iloc[i]['case_id']} · v{rows.iloc[i]['version']} · {rows.iloc[i]['filename']}",
        key="open_registered_report_selector",
    )
    report_path = Path(str(rows.iloc[selected].get("report_path", "")))
    if report_path.exists():
        st.download_button(
            "📥 Open / Download Selected Case Report",
            data=report_path.read_bytes(),
            file_name=report_path.name,
            mime="application/pdf",
            key="download_selected_registered_report",
            use_container_width=True,
        )
    else:
        st.warning("Selected report metadata exists, but the PDF file was not found on disk.")
