"""
Assemble le PDF final : sections narratives fournies (générées par Qwen
en amont) + tableaux structurés construits directement depuis l'actif.
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#C0392B"),
    "high": colors.HexColor("#E67E22"),
    "medium": colors.HexColor("#F1C40F"),
    "low": colors.HexColor("#3498DB"),
    "informational": colors.HexColor("#7F8C8D"),
}


def _collect_vulnerabilities(asset: dict) -> list[dict]:
    vulns = []
    for svc in asset.get("services", []):
        for cve in svc.get("cves", []):
            if cve.get("status") == "valid":
                vulns.append({
                    "id": cve.get("id", "—"),
                    "description": cve.get("description", ""),
                    "cvss": cve.get("cvss"),
                    "port": svc.get("port"),
                })
    return vulns


def build_asset_report_pdf(asset: dict, executive_summary: str, recommendations: str, output_path: str):
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", fontName="Helvetica-Bold", fontSize=18,
        alignment=TA_CENTER, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", fontName="Helvetica-Bold", fontSize=13,
        spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1A1A2E"),
    ))
    cell_style = ParagraphStyle(name="Cell", fontName="Helvetica", fontSize=9, leading=12)
    body_style = ParagraphStyle(name="Body", fontName="Helvetica", fontSize=10, leading=14)

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=40, bottomMargin=40, leftMargin=40, rightMargin=40,
        title=f"Rapport — {asset.get('ipAddress')}",
    )

    elements = []
    severity = asset.get("severity", "informational")
    severity_color = SEVERITY_COLORS.get(severity, colors.grey)

    elements.append(Paragraph("Rapport de détection d'actif", styles["ReportTitle"]))
    elements.append(Paragraph(
        f"Adresse IP : <b>{asset.get('ipAddress')}</b> — Sévérité : "
        f"<font color='{severity_color.hexval()}'><b>{severity.upper()}</b></font>",
        styles["Normal"],
    ))
    elements.append(Spacer(1, 10))

    # ── Résumé exécutif (généré par Qwen) ──
    elements.append(Paragraph("Résumé exécutif", styles["SectionHeading"]))
    elements.append(Paragraph(executive_summary.replace("\n", "<br/>"), body_style))
    elements.append(Spacer(1, 12))

    # ── Identification (structuré, pas de LLM) ──
    elements.append(Paragraph("Identification", styles["SectionHeading"]))
    identity = asset.get("identity", {})
    geo = asset.get("geo", {})
    asn = asset.get("asn", {})
    id_rows = [
        ["Fabricant", identity.get("vendor") or "—"],
        ["Modèle", identity.get("model") or "—"],
        ["Rôle principal", asset.get("primaryRoleForDisplay", "—")],
        ["ASN / Opérateur", f"{asn.get('asn', '—')} — {asn.get('org', '—')}"],
        ["Localisation", f"{geo.get('city', '—')}, {geo.get('country', '—')}"],
        ["Score de risque", f"{asset.get('riskScore', {}).get('value', '—')} / 10"],
    ]
    id_table = Table(
        [[Paragraph(str(c), cell_style) for c in row] for row in id_rows],
        colWidths=[150, 330],
    )
    id_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F5F5F5")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(id_table)
    elements.append(Spacer(1, 16))

    # ── Vulnérabilités (structuré) ──
    vulnerabilities = _collect_vulnerabilities(asset)
    elements.append(Paragraph(f"Vulnérabilités identifiées ({len(vulnerabilities)})", styles["SectionHeading"]))

    if vulnerabilities:
        table_data = [["CVE", "Port", "CVSS", "Description"]]
        for v in vulnerabilities:
            desc = v["description"]
            if len(desc) > 220:
                desc = desc[:217] + "..."
            table_data.append([
                Paragraph(v["id"], cell_style),
                Paragraph(str(v["port"]), cell_style),
                Paragraph(str(v["cvss"] or "—"), cell_style),
                Paragraph(desc, cell_style),
            ])
        vuln_table = Table(table_data, colWidths=[90, 40, 40, 310], repeatRows=1)
        vuln_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A2E")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(vuln_table)
    else:
        elements.append(Paragraph("Aucune vulnérabilité valide identifiée.", styles["Normal"]))
    elements.append(Spacer(1, 16))

    # ── Services exposés (structuré) ──
    elements.append(Paragraph("Services exposés", styles["SectionHeading"]))
    services = asset.get("services", [])
    svc_data = [["Port", "Protocole", "Service", "Produit"]]
    for svc in services:
        svc_data.append([
            str(svc.get("port", "—")), svc.get("protocol", "—"),
            svc.get("service", "—"), svc.get("product", "—") or "—",
        ])
    svc_table = Table(svc_data, colWidths=[60, 80, 120, 220], repeatRows=1)
    svc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A2E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(svc_table)
    elements.append(Spacer(1, 16))

    # ── Recommandations (générées par Qwen) ──
    elements.append(Paragraph("Recommandations", styles["SectionHeading"]))
    elements.append(Paragraph(recommendations.replace("\n", "<br/>"), body_style))

    doc.build(elements)