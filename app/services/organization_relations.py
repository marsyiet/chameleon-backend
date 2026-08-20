"""
Relations d'une organisation avec les actifs et scans qui lui sont
rattachés. Le rattachement se fait strictement via `organizationId` —
un lien structuré fiable — et non via `ownerOrganization.name`, une
correspondance textuelle inférée qui reste sujette à erreur
d'attribution (cf. corrections apportées au moteur d'attribution).
"""

from app.models.db import get_db


def get_assets_for_organization(organization_id: str, limit: int = 200) -> list[dict]:
    db = get_db()
    assets = list(
        db.assets.find({"organizationId": organization_id, "isDeleted": False})
        .sort("lastSeenAt", -1)
        .limit(limit)
    )
    for a in assets:
        a["_id"] = str(a["_id"])
    return assets


def get_scans_for_organization(organization_id: str, limit: int = 100) -> list[dict]:
    db = get_db()
    scans = list(
        db.scans.find({"organizationId": organization_id, "isDeleted": False})
        .sort("createdAt", -1)
        .limit(limit)
    )
    for s in scans:
        s["_id"] = str(s["_id"])
    return scans


def get_organization_stats(organization_id: str) -> dict:
    """Compte rapide, utile pour la liste (badge nombre d'actifs) sans
    charger l'inventaire complet à chaque ligne du tableau."""
    db = get_db()
    assets_count = db.assets.count_documents({"organizationId": organization_id, "isDeleted": False})
    scans_count = db.scans.count_documents({"organizationId": organization_id, "isDeleted": False})
    critical_count = db.assets.count_documents({
        "organizationId": organization_id, "isDeleted": False, "severity": "critical",
    })
    return {
        "assetsCount": assets_count,
        "scansCount": scans_count,
        "criticalAssetsCount": critical_count,
    }