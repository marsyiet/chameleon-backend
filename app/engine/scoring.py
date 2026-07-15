"""
Calcul du score de risque composite (chapitre 2, §2.3.1) :
Score = f(CVSS_max, EPSS_max, Criticité, Vecteur humain)

La fraîcheur n'entre pas dans ce calcul directement (elle est dérivée de
lastSeenAt à la lecture, pas stockée comme facteur multiplicatif) — cf.
tableau 2.1, "Fraîcheur" reste une dimension d'affichage séparée.
"""

from datetime import datetime

# Poids de criticité contextuelle par type d'actif (chapitre 2, tableau 2.1 :
# "une base de données directement exposée pèse davantage qu'un service
# informationnel").
CRITICALITY_BY_TYPE = {
    "database":       9,
    "authentication": 8,
    "remote-access":  7,
    "api":            6,
    "network":        6,
    "mail":           5,
    "web":            4,
    "unknown":        2,
}

HUMAN_VECTOR_BONUS = 2.0


def calculate_risk_score(asset_type, exposure, services, human_vector_exposed):
    """
    Retourne (riskScore_dict, severity_str), prêts pour
    AssetRepository.update_risk_score(asset_id, riskScore, severity).
    """
    cvss_max = 0.0
    epss_max = 0.0

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

    criticality = CRITICALITY_BY_TYPE.get(asset_type, 2)
    if exposure == "externe":
        criticality *= 1.2

    human_factor = HUMAN_VECTOR_BONUS if human_vector_exposed else 0.0

    # Pondération : CVSS reste le signal dominant (exploitabilité connue),
    # EPSS ajuste à la hausse selon la probabilité d'exploitation réelle,
    # la criticité contextuelle et le vecteur humain pèsent en complément.
    raw_score = (
        (cvss_max * 0.55)
        + (epss_max * 10 * 0.20)
        + (criticality * 0.20)
        + human_factor
    )
    score = round(min(raw_score, 10.0), 2)

    return (
        {
            "value": score,
            "cvssMax": cvss_max or None,
            "epssMax": epss_max or None,
            "criticality": criticality,
            "humanVectorFactor": human_factor,
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