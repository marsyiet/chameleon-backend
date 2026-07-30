"""
Calcul du score de risque composite — basé sur primaryRoleForDisplay
(le rôle le plus critique parmi natureRoles), avec justification textuelle.
"""

from datetime import datetime

CRITICALITY_BY_ROLE = {
    "vpn_gateway": 9, "firewall_router": 9, "industrial_control": 9, "database": 9,
    "authentication_portal": 8, "remote_access": 7,
    "mail_server": 5, "dns_server": 5, "file_transfer": 5,
    "api": 6, "devops_tool": 7, "iot_device": 6, "network_device_generic": 6,
    "web_application": 4, "unknown": 2,
}

HUMAN_VECTOR_BONUS = 2.0
KEV_BONUS = 1.5


def calculate_risk_score(primary_role, exposure, services, human_vector_exposed, extra_reasons=None):
    cvss_max = 0.0
    epss_max = 0.0
    has_kev = False

    for svc in services:
        for cve in svc.get("cves", []):
            if cve.get("status") != "valid":
                continue
            cvss = cve.get("cvss") or 0
            epss = cve.get("epss") or 0
            if cvss > cvss_max:
                cvss_max = cvss
            if epss > epss_max:
                epss_max = epss
            if cve.get("kev"):
                has_kev = True

    criticality = CRITICALITY_BY_ROLE.get(primary_role, 2)
    if exposure == "externe":
        criticality *= 1.2

    human_factor = HUMAN_VECTOR_BONUS if human_vector_exposed else 0.0
    kev_bonus = KEV_BONUS if has_kev else 0.0

    raw_score = (cvss_max * 0.55) + (epss_max * 10 * 0.20) + (criticality * 0.20) + human_factor + kev_bonus
    score = round(min(raw_score, 10.0), 2)

    reasons = list(extra_reasons or [])
    if cvss_max > 0:
        reasons.append(f"CVSS max {cvss_max}")
    if has_kev:
        reasons.append("vulnérabilité activement exploitée (CISA KEV)")
    if human_vector_exposed:
        reasons.append("point d'authentification exposé")
    reasons.append(f"rôle principal : {primary_role}")

    return (
        {
            "value": score, "cvssMax": cvss_max or None, "epssMax": epss_max or None,
            "criticality": criticality, "humanVectorFactor": human_factor, "kevBonus": kev_bonus,
            "reasoning": ", ".join(reasons),
            "calculatedAt": datetime.utcnow(),
        },
        _severity_from_score(score),
    )


def _severity_from_score(score):
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "informational"