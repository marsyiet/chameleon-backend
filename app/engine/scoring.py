"""
Calcul du score de risque composite (chapitre 2, §2.3.1) :
Score = f(CVSS_max, EPSS_max, Criticité, Vecteur humain)

La fraîcheur n'entre pas dans ce calcul directement (elle est dérivée de
lastSeenAt à la lecture, pas stockée comme facteur multiplicatif) — cf.
tableau 2.1, "Fraîcheur" reste une dimension d'affichage séparée.
"""

from datetime import datetime

# Poids de criticité contextuelle par nature d'actif (chapitre 2, tableau 2.1 :
# "une base de données directement exposée pèse davantage qu'un service
# informationnel"). Réaligné sur la taxonomie de nature_detection.py —
# un équipement VPN/firewall mal exposé est au moins aussi critique qu'une
# base de données, car il constitue souvent le point d'entrée du réseau
# interne tout entier.
CRITICALITY_BY_NATURE = {
    "vpn_gateway":            9,
    "firewall_router":        9,
    "industrial_control":     9,
    "database":               9,
    "authentication_portal":  8,
    "remote_access":          7,
    "mail_server":            5,
    "dns_server":             5,
    "file_transfer":          5,
    "api":                    6,
    "network_device_generic": 6,
    "web_application":        4,
    "unknown":                2,
}

HUMAN_VECTOR_BONUS = 2.0

# Bonus appliqué si au moins une CVE valide de l'actif figure dans le
# catalogue CISA KEV (Known Exploited Vulnerabilities) — une vulnérabilité
# activement exploitée en conditions réelles mérite une priorité supérieure
# à une CVE théorique de même score CVSS.
KEV_BONUS = 1.5


def calculate_risk_score(nature_type, exposure, services, human_vector_exposed):
    """
    Retourne (riskScore_dict, severity_str), prêts pour
    AssetRepository.update_risk_score(asset_id, riskScore, severity).

    `nature_type` : natureType tel que dérivé par nature_detection.py
    (ex: "vpn_gateway", "database", "web_application"...).
    """
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

    criticality = CRITICALITY_BY_NATURE.get(nature_type, 2)
    if exposure == "externe":
        criticality *= 1.2

    human_factor = HUMAN_VECTOR_BONUS if human_vector_exposed else 0.0
    kev_bonus = KEV_BONUS if has_kev else 0.0

    # Pondération : CVSS reste le signal dominant (exploitabilité connue),
    # EPSS ajuste à la hausse selon la probabilité d'exploitation réelle,
    # la criticité contextuelle et le vecteur humain pèsent en complément,
    # le bonus KEV surclasse une CVE théorique face à une CVE activement
    # exploitée dans la nature.
    raw_score = (
        (cvss_max * 0.55)
        + (epss_max * 10 * 0.20)
        + (criticality * 0.20)
        + human_factor
        + kev_bonus
    )
    score = round(min(raw_score, 10.0), 2)

    return (
        {
            "value": score,
            "cvssMax": cvss_max or None,
            "epssMax": epss_max or None,
            "criticality": criticality,
            "humanVectorFactor": human_factor,
            "kevBonus": kev_bonus,
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