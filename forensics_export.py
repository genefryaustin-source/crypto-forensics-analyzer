"""
Export Module for Forensics Findings
Generates: JSON alerts, CSV reports, PDF forensics documents, email templates
"""

import pandas as pd
import json
import io
from datetime import datetime
from typing import Dict, List, Optional
import logging
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, Image
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# JSON ALERT EXPORTS
# ─────────────────────────────────────────────────────────────

def export_alerts_json(
        clusters: List[Dict] = None,
        circular_flows: List[Dict] = None,
        anomalies: List[Dict] = None,
        mixers: List[Dict] = None,
        case_id: str = "FORENSICS_REPORT",
        investigator: str = "Crypto Forensics Analyzer"
) -> bytes:
    """
    Export all forensics findings as structured JSON.
    Perfect for: SIEM integration, API webhooks, automation platforms

    Returns: JSON bytes ready for download
    """
    logger.info("Generating JSON alert export...")

    alert_package = {
        "metadata": {
            "case_id": case_id,
            "investigator": investigator,
            "generated_at": datetime.now().isoformat(),
            "version": "1.0",
            "findings_summary": {
                "cluster_count": len(clusters) if clusters else 0,
                "circular_flows": len(circular_flows) if circular_flows else 0,
                "behavioral_anomalies": len(anomalies) if anomalies else 0,
                "mixer_candidates": len(mixers) if mixers else 0,
            }
        },
        "clusters": _serialize_clusters(clusters or []),
        "circular_flows": _serialize_circular_flows(circular_flows or []),
        "behavioral_anomalies": _serialize_anomalies(anomalies or []),
        "mixer_patterns": _serialize_mixers(mixers or []),
        "recommendations": _generate_recommendations(clusters, circular_flows, anomalies, mixers)
    }

    json_bytes = json.dumps(alert_package, indent=2, default=str).encode('utf-8')
    logger.info(f"✅ JSON export complete: {len(json_bytes)} bytes")

    return json_bytes


def _serialize_clusters(clusters: List[Dict]) -> List[Dict]:
    """Convert cluster objects to JSON-serializable format"""
    serialized = []
    for cluster in clusters:
        serialized.append({
            "cluster_id": cluster.get("cluster_id"),
            "classification": cluster.get("classification"),
            "member_count": cluster.get("member_count"),
            "members": cluster.get("members", [])[:10],  # First 10
            "total_volume": float(cluster.get("total_volume", 0)),
            "avg_risk_score": float(cluster.get("avg_risk_score", 0)),
            "risk_level": cluster.get("risk_level"),
            "primary_token": cluster.get("primary_token"),
            "token_diversity": cluster.get("token_diversity"),
            "unique_recipients": cluster.get("unique_recipients"),
            "intra_cluster_ratio": float(cluster.get("intra_cluster_ratio", 0)),
            "severity": "CRITICAL" if cluster.get("avg_risk_score", 0) > 80 else "HIGH" if cluster.get("avg_risk_score",
                                                                                                       0) > 60 else "MEDIUM",
        })
    return sorted(serialized, key=lambda x: x["total_volume"], reverse=True)


def _serialize_circular_flows(flows: List[Dict]) -> List[Dict]:
    """Convert circular flows to JSON format"""
    serialized = []
    for flow in flows:
        serialized.append({
            "cycle_id": hash(tuple(flow.get("cycle", []))) % 100000,
            "cycle": flow.get("cycle", []),
            "cycle_length": flow.get("cycle_length"),
            "participants": flow.get("participants"),
            "total_volume": float(flow.get("total_volume", 0)),
            "avg_per_hop": float(flow.get("avg_per_hop", 0)),
            "time_span_hours": float(flow.get("time_span_hours", 0)),
            "tokens": flow.get("tokens", []),
            "critical_hops": flow.get("critical_hops"),
            "high_risk_hops": flow.get("high_risk_hops"),
            "severity_score": float(flow.get("severity_score", 0)),
            "classification": _classify_flow(flow),
            "tx_hashes": flow.get("tx_hashes", [])[:5],
        })
    return sorted(serialized, key=lambda x: x["severity_score"], reverse=True)


def _serialize_anomalies(anomalies: List[Dict]) -> List[Dict]:
    """Convert anomalies to JSON format"""
    serialized = []
    for anom in anomalies:
        serialized.append({
            "address": anom.get("address"),
            "type": anom.get("type"),
            "severity": int(anom.get("severity", 0)),
            "detail": anom.get("detail"),
            "timestamp": str(anom.get("timestamp")),
            "tx_hash": anom.get("tx_hash"),
            "alert_level": "CRITICAL" if anom.get("severity", 0) >= 80 else "HIGH" if anom.get("severity",
                                                                                               0) >= 60 else "MEDIUM",
        })
    return sorted(serialized, key=lambda x: x["severity"], reverse=True)


def _serialize_mixers(mixers: List[Dict]) -> List[Dict]:
    """Convert mixer candidates to JSON format"""
    serialized = []
    for mixer in mixers:
        serialized.append({
            "address": mixer.get("address"),
            "mixer_score": float(mixer.get("mixer_score", 0)),
            "fan_in": mixer.get("fan_in"),
            "fan_out": mixer.get("fan_out"),
            "reuse_ratio": float(mixer.get("reuse_ratio", 0)),
            "total_volume": float(mixer.get("total_volume", 0)),
            "transaction_count": mixer.get("transaction_count"),
            "classification": mixer.get("classification"),
            "confidence": "HIGH" if mixer.get("mixer_score", 0) >= 70 else "MEDIUM" if mixer.get("mixer_score",
                                                                                                 0) >= 50 else "LOW",
        })
    return sorted(serialized, key=lambda x: x["mixer_score"], reverse=True)


def _classify_flow(flow: Dict) -> str:
    """Classify circular flow type"""
    severity = flow.get('severity_score', 0)
    cycle_len = flow.get('cycle_length', 0)
    time_span = flow.get('time_span_hours', 24)
    volume = flow.get('total_volume', 0)

    if severity >= 80:
        return 'CRITICAL_CYCLE'
    elif cycle_len == 2 and volume > 10000:
        return 'TWO_PARTY_WASH'
    elif time_span < 1:
        return 'RAPID_CYCLE'
    elif cycle_len >= 5:
        return 'COMPLEX_CHAIN'
    elif len(flow.get('tokens', [])) > 1:
        return 'MULTI_TOKEN_CYCLE'
    else:
        return 'SUSPICIOUS_CYCLE'


def _generate_recommendations(clusters, circular_flows, anomalies, mixers) -> Dict:
    """Generate actionable recommendations based on findings"""
    recommendations = {
        "immediate_actions": [],
        "investigation_priorities": [],
        "regulatory_considerations": []
    }

    if clusters:
        critical_clusters = [c for c in clusters if c.get("avg_risk_score", 0) > 80]
        if critical_clusters:
            recommendations["immediate_actions"].append(
                f"Review {len(critical_clusters)} critical clusters for potential coordinated activity"
            )
            recommendations["investigation_priorities"].append(
                "Priority 1: Cluster-based coordinated activity patterns detected"
            )

    if circular_flows:
        critical_flows = [f for f in circular_flows if f.get("severity_score", 0) >= 80]
        if critical_flows:
            recommendations["immediate_actions"].append(
                f"Flag {len(critical_flows)} circular flows - possible wash trading"
            )
            recommendations["regulatory_considerations"].append(
                "Consider SAR filing for suspected wash trading patterns"
            )

    if anomalies:
        critical_anomalies = [a for a in anomalies if a.get("severity", 0) >= 80]
        if critical_anomalies:
            recommendations["immediate_actions"].append(
                f"Investigate {len(critical_anomalies)} accounts with critical behavioral shifts"
            )
            recommendations["investigation_priorities"].append(
                "Priority 2: Account compromise or unauthorized access indicators"
            )

    if mixers:
        high_confidence = [m for m in mixers if m.get("mixer_score", 0) >= 70]
        if high_confidence:
            recommendations["immediate_actions"].append(
                f"Monitor {len(high_confidence)} mixer/tumbler candidates"
            )
            recommendations["regulatory_considerations"].append(
                "Potential AML/CFT violation - mixer usage detected"
            )

    if not recommendations["immediate_actions"]:
        recommendations["immediate_actions"].append("No critical findings detected - routine monitoring recommended")

    return recommendations


# ─────────────────────────────────────────────────────────────
# CSV EXPORTS
# ─────────────────────────────────────────────────────────────

def export_alerts_csv(
        clusters: List[Dict] = None,
        circular_flows: List[Dict] = None,
        anomalies: List[Dict] = None,
        mixers: List[Dict] = None
) -> bytes:
    """
    Export all findings as multiple CSV files (zipped).
    Perfect for: spreadsheet analysis, compliance databases, audit trails
    """
    logger.info("Generating CSV exports...")

    import zipfile

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:

        # Clusters CSV
        if clusters:
            df_clusters = pd.DataFrame([
                {
                    'Cluster ID': c.get('cluster_id'),
                    'Classification': c.get('classification'),
                    'Members': len(c.get('members', [])),
                    'Total Volume': f"${c.get('total_volume', 0):,.2f}",
                    'Avg Risk Score': f"{c.get('avg_risk_score', 0):.1f}",
                    'Risk Level': c.get('risk_level'),
                    'Primary Token': c.get('primary_token'),
                    'Token Diversity': c.get('token_diversity'),
                    'Recipients': c.get('unique_recipients'),
                    'Intra Cluster Ratio': f"{c.get('intra_cluster_ratio', 0):.1%}",
                }
                for c in clusters
            ])
            zf.writestr('clusters.csv', df_clusters.to_csv(index=False))
            logger.info(f"  ✓ Clusters: {len(df_clusters)} rows")

        # Circular Flows CSV
        if circular_flows:
            df_flows = pd.DataFrame([
                {
                    'Cycle': ' → '.join(f.get('cycle', [])[:5]),
                    'Length': f.get('cycle_length'),
                    'Participants': f.get('participants'),
                    'Total Volume': f"${f.get('total_volume', 0):,.2f}",
                    'Avg per Hop': f"${f.get('avg_per_hop', 0):,.2f}",
                    'Time Span (hours)': f"{f.get('time_span_hours', 0):.1f}",
                    'Tokens': ', '.join(f.get('tokens', [])),
                    'Critical Hops': f.get('critical_hops'),
                    'High Risk Hops': f.get('high_risk_hops'),
                    'Severity Score': f.get('severity_score'),
                    'Classification': _classify_flow(f),
                }
                for f in circular_flows
            ])
            zf.writestr('circular_flows.csv', df_flows.to_csv(index=False))
            logger.info(f"  ✓ Circular Flows: {len(df_flows)} rows")

        # Anomalies CSV
        if anomalies:
            df_anomalies = pd.DataFrame([
                {
                    'Address': a.get('address'),
                    'Anomaly Type': a.get('type'),
                    'Severity': a.get('severity'),
                    'Detail': a.get('detail'),
                    'Timestamp': a.get('timestamp'),
                    'TX Hash': a.get('tx_hash'),
                }
                for a in anomalies
            ])
            zf.writestr('behavioral_anomalies.csv', df_anomalies.to_csv(index=False))
            logger.info(f"  ✓ Anomalies: {len(df_anomalies)} rows")

        # Mixers CSV
        if mixers:
            df_mixers = pd.DataFrame([
                {
                    'Address': m.get('address'),
                    'Mixer Score': f"{m.get('mixer_score', 0):.1f}",
                    'Fan In': m.get('fan_in'),
                    'Fan Out': m.get('fan_out'),
                    'Reuse Ratio': f"{m.get('reuse_ratio', 0):.1%}",
                    'Total Volume': f"${m.get('total_volume', 0):,.2f}",
                    'Transaction Count': m.get('transaction_count'),
                    'Classification': m.get('classification'),
                }
                for m in mixers
            ])
            zf.writestr('mixer_candidates.csv', df_mixers.to_csv(index=False))
            logger.info(f"  ✓ Mixers: {len(df_mixers)} rows")

    zip_buffer.seek(0)
    logger.info(f"✅ CSV export complete: {len(zip_buffer.getvalue())} bytes")
    return zip_buffer.getvalue()


# ─────────────────────────────────────────────────────────────
# PDF FORENSICS ALERT REPORT
# ─────────────────────────────────────────────────────────────

def export_alerts_pdf(
        clusters: List[Dict] = None,
        circular_flows: List[Dict] = None,
        anomalies: List[Dict] = None,
        mixers: List[Dict] = None,
        case_id: str = "FORENSICS_ALERT",
        investigator: str = "Crypto Forensics Analyzer",
        df_main: pd.DataFrame = None
) -> bytes:
    """
    Generate professional PDF alert report.
    Perfect for: regulatory submission, law enforcement briefing, board reports
    """
    logger.info("Generating PDF alert report...")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(letter),
        topMargin=0.5 * inch, bottomMargin=0.5 * inch,
        leftMargin=0.5 * inch, rightMargin=0.5 * inch
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle', parent=styles['Title'],
        fontSize=20, textColor=colors.HexColor("#ff4444"), spaceAfter=12, alignment=1
    )
    heading_style = ParagraphStyle(
        'CustomHeading', parent=styles['Heading1'],
        fontSize=12, textColor=colors.HexColor("#ff4444"), spaceBefore=12, spaceAfter=6
    )

    elements = []

    # Header
    elements.append(Paragraph("🔴 FORENSICS ALERT REPORT", title_style))
    elements.append(Paragraph(
        f"Case ID: {case_id} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | "
        f"Investigator: {investigator}",
        ParagraphStyle('subtitle', parent=styles['Normal'], fontSize=9, textColor=colors.grey)
    ))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#ff4444")))
    elements.append(Spacer(1, 0.2 * inch))

    # Executive Summary
    elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))

    summary_data = [["Metric", "Value"]]
    if df_main is not None:
        summary_data.extend([
            ["Total Transactions", str(len(df_main))],
            ["Total Volume", f"${df_main['amount'].sum():,.2f}"],
            ["Critical Risk Count", str(len(df_main[df_main['risk_level'] == 'CRITICAL']))],
        ])

    summary_data.extend([
        ["Clusters Detected", str(len(clusters) if clusters else 0)],
        ["Circular Flows Found", str(len(circular_flows) if circular_flows else 0)],
        ["Behavioral Anomalies", str(len(anomalies) if anomalies else 0)],
        ["Mixer Candidates", str(len(mixers) if mixers else 0)],
    ])

    summary_table = Table(summary_data, colWidths=[3 * inch, 3 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e1e2e")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f5f5f5"), colors.white]),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.2 * inch))

    # Clusters Section
    if clusters:
        elements.append(Paragraph("🤝 ADDRESS CLUSTERING ANALYSIS", heading_style))

        critical_clusters = [c for c in clusters if c.get('avg_risk_score', 0) > 80]
        if critical_clusters:
            elements.append(Paragraph(
                f"⚠️ <b>{len(critical_clusters)} CRITICAL CLUSTERS DETECTED</b>",
                ParagraphStyle('warning', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#ff4444"))
            ))

        cluster_data = [["Cluster", "Type", "Members", "Volume", "Avg Risk", "Status"]]
        for c in clusters[:15]:
            cluster_data.append([
                f"#{c.get('cluster_id')}",
                c.get('classification', '')[:20],
                str(c.get('member_count', 0)),
                f"${c.get('total_volume', 0) / 1e6:.2f}M",
                f"{c.get('avg_risk_score', 0):.0f}",
                "🔴 CRITICAL" if c.get('avg_risk_score', 0) > 80 else "🟠 HIGH" if c.get('avg_risk_score',
                                                                                       0) > 60 else "🟡 MED",
            ])

        cluster_table = Table(cluster_data,
                              colWidths=[0.8 * inch, 1.5 * inch, 0.8 * inch, 1 * inch, 0.8 * inch, 1.2 * inch])
        cluster_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e1e2e")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
        ]))
        elements.append(cluster_table)
        elements.append(Spacer(1, 0.15 * inch))

    # Circular Flows Section
    if circular_flows:
        elements.append(Paragraph("🔄 CIRCULAR FLOW DETECTION", heading_style))

        critical_flows = [f for f in circular_flows if f.get('severity_score', 0) >= 80]
        if critical_flows:
            elements.append(Paragraph(
                f"⚠️ <b>{len(critical_flows)} CRITICAL CYCLES DETECTED - POSSIBLE WASH TRADING</b>",
                ParagraphStyle('warning', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#ff4444"))
            ))

        flow_data = [["Cycle Path", "Length", "Volume", "Time Span", "Severity", "Type"]]
        for f in circular_flows[:12]:
            cycle_str = ' → '.join([a[:5] + '.' for a in f.get('cycle', [])[:4]])
            flow_data.append([
                cycle_str,
                str(f.get('cycle_length', 0)),
                f"${f.get('total_volume', 0) / 1e6:.2f}M",
                f"{f.get('time_span_hours', 0):.1f}h",
                f"{f.get('severity_score', 0):.0f}",
                _classify_flow(f)[:15],
            ])

        flow_table = Table(flow_data, colWidths=[2 * inch, 0.6 * inch, 0.9 * inch, 0.8 * inch, 0.7 * inch, 1.2 * inch])
        flow_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e1e2e")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
        ]))
        elements.append(flow_table)
        elements.append(Spacer(1, 0.15 * inch))

    # Anomalies Section
    if anomalies:
        elements.append(Paragraph("⚡ BEHAVIORAL ANOMALIES", heading_style))

        critical_anom = [a for a in anomalies if a.get('severity', 0) >= 80]
        if critical_anom:
            elements.append(Paragraph(
                f"⚠️ <b>{len(critical_anom)} CRITICAL BEHAVIORAL SHIFTS DETECTED</b>",
                ParagraphStyle('warning', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#ff4444"))
            ))

        anom_data = [["Address", "Type", "Severity", "Detail", "Timestamp"]]
        for a in anomalies[:12]:
            anom_data.append([
                a.get('address', '')[:10],
                a.get('type', '')[:15],
                f"{a.get('severity', 0):.0f}",
                a.get('detail', '')[:35],
                str(a.get('timestamp', ''))[:10],
            ])

        anom_table = Table(anom_data, colWidths=[1.2 * inch, 1.2 * inch, 0.7 * inch, 2 * inch, 1.2 * inch])
        anom_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e1e2e")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
        ]))
        elements.append(anom_table)
        elements.append(Spacer(1, 0.15 * inch))

    # Mixer Section
    if mixers:
        elements.append(Paragraph("🔄 MIXER/TUMBLER DETECTION", heading_style))

        confirmed_mixers = [m for m in mixers if m.get('mixer_score', 0) >= 70]
        if confirmed_mixers:
            elements.append(Paragraph(
                f"⚠️ <b>{len(confirmed_mixers)} CONFIRMED MIXER PATTERNS - POTENTIAL AML/CFT VIOLATION</b>",
                ParagraphStyle('warning', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor("#ff4444"))
            ))

        mixer_data = [["Address", "Score", "In", "Out", "Reuse", "Volume"]]
        for m in mixers[:12]:
            mixer_data.append([
                m.get('address', '')[:10],
                f"{m.get('mixer_score', 0):.0f}",
                str(m.get('fan_in', 0)),
                str(m.get('fan_out', 0)),
                f"{m.get('reuse_ratio', 0):.1%}",
                f"${m.get('total_volume', 0) / 1e6:.2f}M",
            ])

        mixer_table = Table(mixer_data,
                            colWidths=[1.2 * inch, 0.8 * inch, 0.7 * inch, 0.7 * inch, 0.8 * inch, 1 * inch])
        mixer_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e1e2e")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
        ]))
        elements.append(mixer_table)

    # Footer
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    elements.append(Paragraph(
        "CONFIDENTIAL - For authorized investigative use only. "
        "This report contains automated analysis and should be verified by qualified analysts.",
        ParagraphStyle('footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
    ))

    doc.build(elements)
    buffer.seek(0)
    logger.info(f"✅ PDF export complete: {len(buffer.getvalue())} bytes")

    return buffer.getvalue()


# ─────────────────────────────────────────────────────────────
# EMAIL ALERT TEMPLATE
# ─────────────────────────────────────────────────────────────

def generate_email_alert(
        clusters: List[Dict] = None,
        circular_flows: List[Dict] = None,
        anomalies: List[Dict] = None,
        mixers: List[Dict] = None,
        recipient: str = "security@institution.com",
        case_id: str = "FORENSICS_ALERT"
) -> Dict[str, str]:
    """
    Generate email alert template with HTML body
    """

    critical_items = 0
    findings_summary = []

    if clusters:
        critical_clusters = len([c for c in clusters if c.get('avg_risk_score', 0) > 80])
        if critical_clusters > 0:
            critical_items += critical_clusters
            findings_summary.append(f"🔴 {critical_clusters} critical address clusters")

    if circular_flows:
        critical_flows = len([f for f in circular_flows if f.get('severity_score', 0) >= 80])
        if critical_flows > 0:
            critical_items += critical_flows
            findings_summary.append(f"🔴 {critical_flows} critical circular flows")

    if anomalies:
        critical_anom = len([a for a in anomalies if a.get('severity', 0) >= 80])
        if critical_anom > 0:
            critical_items += critical_anom
            findings_summary.append(f"🔴 {critical_anom} critical behavioral anomalies")

    if mixers:
        confirmed = len([m for m in mixers if m.get('mixer_score', 0) >= 70])
        if confirmed > 0:
            critical_items += confirmed
            findings_summary.append(f"🔴 {confirmed} confirmed mixer patterns")

    severity_level = "🔴 CRITICAL" if critical_items >= 3 else "🟠 HIGH" if critical_items >= 1 else "🟡 MEDIUM"

    html_body = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
            .header {{ background: #ff4444; color: white; padding: 15px; border-radius: 4px; }}
            .section {{ margin: 20px 0; }}
            .alert {{ background: #fff3cd; border-left: 4px solid #ff4444; padding: 12px; margin: 10px 0; }}
            .critical {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
            table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #1e1e2e; color: white; }}
            .footer {{ margin-top: 20px; padding-top: 10px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔴 FORENSICS ALERT NOTIFICATION</h1>
                <p>Case ID: {case_id} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>

            <div class="section">
                <h2>Severity: {severity_level}</h2>
                <p>Multiple high-risk forensics patterns detected in transaction analysis.</p>
            </div>

            <div class="section">
                <h3>Critical Findings:</h3>
                {chr(10).join([f'<div class="alert critical">{finding}</div>' for finding in findings_summary]) if findings_summary else '<p>No critical findings.</p>'}
            </div>

            <div class="section">
                <h3>Summary by Category:</h3>
                <table>
                    <tr>
                        <th>Category</th>
                        <th>Count</th>
                        <th>Critical</th>
                    </tr>
                    <tr>
                        <td>Address Clusters</td>
                        <td>{len(clusters) if clusters else 0}</td>
                        <td>{len([c for c in (clusters or []) if c.get('avg_risk_score', 0) > 80])}</td>
                    </tr>
                    <tr>
                        <td>Circular Flows</td>
                        <td>{len(circular_flows) if circular_flows else 0}</td>
                        <td>{len([f for f in (circular_flows or []) if f.get('severity_score', 0) >= 80])}</td>
                    </tr>
                    <tr>
                        <td>Behavioral Anomalies</td>
                        <td>{len(anomalies) if anomalies else 0}</td>
                        <td>{len([a for a in (anomalies or []) if a.get('severity', 0) >= 80])}</td>
                    </tr>
                    <tr>
                        <td>Mixer Patterns</td>
                        <td>{len(mixers) if mixers else 0}</td>
                        <td>{len([m for m in (mixers or []) if m.get('mixer_score', 0) >= 70])}</td>
                    </tr>
                </table>
            </div>

            <div class="section">
                <h3>Recommended Actions:</h3>
                <ul>
                    <li>Review detailed PDF report for full forensic analysis</li>
                    <li>Cross-reference with internal compliance database</li>
                    <li>Determine SAR filing requirements</li>
                    <li>Escalate to senior investigator for disposition</li>
                </ul>
            </div>

            <div class="footer">
                <p>This is an automated alert from Crypto Forensics Analyzer Pro v5.0</p>
                <p>CONFIDENTIAL - For authorized investigative use only</p>
            </div>
        </div>
    </body>
    </html>
    """

    return {
        "to": recipient,
        "subject": f"{severity_level} - Forensics Alert {case_id}",
        "body_html": html_body,
        "body_text": f"""
CRYPTO FORENSICS ALERT
Case ID: {case_id}
Severity: {severity_level}
Generated: {datetime.now().isoformat()}

FINDINGS:
{chr(10).join(findings_summary) if findings_summary else 'No critical findings.'}

Please review the detailed PDF report for full analysis.

---
CONFIDENTIAL - For authorized investigative use only
        """,
    }


# ─────────────────────────────────────────────────────────────
# SIEM/SOAR INTEGRATION
# ─────────────────────────────────────────────────────────────

def export_to_siem(
        clusters: List[Dict] = None,
        circular_flows: List[Dict] = None,
        anomalies: List[Dict] = None,
        mixers: List[Dict] = None,
        severity_threshold: float = 60
) -> str:
    """
    Generate CEF (Common Event Format) for SIEM integration
    Compatible with: Splunk, ArcSight, QRadar, etc.
    """

    cef_events = []
    event_id = 1000

    # Cluster events
    if clusters:
        for cluster in clusters:
            if cluster.get('avg_risk_score', 0) >= severity_threshold:
                cef = (
                    f"CEF:0|CryptoForensics|AddressCluster|5.0|{event_id}|"
                    f"Cluster {cluster.get('cluster_id')}: {cluster.get('classification')}"
                    f"|{int(cluster.get('avg_risk_score', 0)) // 20}"
                    f"|act=DetectCluster cn1={cluster.get('member_count')} "
                    f"cn2={int(cluster.get('total_volume', 0))} "
                    f"cs1={cluster.get('primary_token')} "
                    f"cs2={cluster.get('risk_level')} "
                    f"msg=Address cluster detected with {cluster.get('member_count')} members"
                )
                cef_events.append(cef)
                event_id += 1

    # Circular flow events
    if circular_flows:
        for flow in circular_flows:
            if flow.get('severity_score', 0) >= severity_threshold:
                cef = (
                    f"CEF:0|CryptoForensics|CircularFlow|5.0|{event_id}|"
                    f"Circular Flow: {_classify_flow(flow)}"
                    f"|{int(flow.get('severity_score', 0)) // 20}"
                    f"|act=DetectCircularFlow cn1={flow.get('cycle_length')} "
                    f"cn2={int(flow.get('total_volume', 0))} "
                    f"cn3={flow.get('critical_hops')} "
                    f"cs1={', '.join(flow.get('tokens', []))} "
                    f"msg=Circular flow detected: {' → '.join(flow.get('cycle', [])[:3])}"
                )
                cef_events.append(cef)
                event_id += 1

    # Anomaly events
    if anomalies:
        for anom in anomalies:
            if anom.get('severity', 0) >= severity_threshold:
                cef = (
                    f"CEF:0|CryptoForensics|BehavioralAnomaly|5.0|{event_id}|"
                    f"{anom.get('type')}"
                    f"|{int(anom.get('severity', 0)) // 20}"
                    f"|act=DetectAnomaly src={anom.get('address')} "
                    f"cn1={int(anom.get('severity', 0))} "
                    f"msg={anom.get('detail')} "
                    f"rt={int(pd.Timestamp(anom.get('timestamp')).timestamp())}"
                )
                cef_events.append(cef)
                event_id += 1

    # Mixer events
    if mixers:
        for mixer in mixers:
            if mixer.get('mixer_score', 0) >= severity_threshold:
                cef = (
                    f"CEF:0|CryptoForensics|MixerDetection|5.0|{event_id}|"
                    f"Mixer Pattern Detected"
                    f"|{int(mixer.get('mixer_score', 0)) // 20}"
                    f"|act=DetectMixer src={mixer.get('address')} "
                    f"cn1={mixer.get('fan_in')} "
                    f"cn2={mixer.get('fan_out')} "
                    f"cn3={int(mixer.get('total_volume', 0))} "
                    f"msg=Mixer/tumbler pattern identified: {mixer.get('classification')}"
                )
                cef_events.append(cef)
                event_id += 1

    return "\n".join(cef_events)
