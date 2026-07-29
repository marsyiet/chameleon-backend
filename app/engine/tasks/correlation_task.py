"""
Corrélation d'actifs par signaux partagés (certificat, favicon, rDNS,
bloc ASN, domaine parent) — modélise les relations entre actifs sous
forme d'arêtes stockées en base, en réponse au besoin de graphe posé au
chapitre 2. Implémentation sur magasin documentaire (Mongo), pas une
base de graphe dédiée : compromis retenu pour rester dans le périmètre
du stage.
"""

from datetime import datetime
from itertools import combinations
from app.models.db import get_db


def compute_correlations_for_scan(scan_id: str, organization_id: str):
    db = get_db()
    assets = list(db.assets.find({"scanId": scan_id, "isDeleted": False}))

    if len(assets) < 2:
        return

    edges = []
    edges.extend(_correlate_by_certificate(assets))
    edges.extend(_correlate_by_favicon(assets))
    edges.extend(_correlate_by_rdns_root(assets))
    edges.extend(_correlate_by_asn_block(assets))
    edges.extend(_correlate_by_parent_domain(assets))

    now = datetime.utcnow()
    for edge in edges:
        db.correlations.update_one(
            {
                "fromAssetId": edge["fromAssetId"],
                "toAssetId": edge["toAssetId"],
                "relationType": edge["relationType"],
            },
            {
                "$set": {
                    **edge,
                    "organizationId": organization_id,
                    "updatedAt": now,
                },
                "$setOnInsert": {"createdAt": now},
            },
            upsert=True,
        )


def _cert_fingerprints(asset):
    fps = set()
    for svc in asset.get("services", []):
        tls = svc.get("tls") or {}
        fp = tls.get("fingerprintSha256")
        if fp:
            fps.add(fp)
    return fps


def _favicon_hashes(asset):
    hashes = set()
    for svc in asset.get("services", []):
        http = svc.get("http") or {}
        h = http.get("faviconHash")
        if h is not None:
            hashes.add(h)
    return hashes


def _correlate_by_certificate(assets):
    edges = []
    for a, b in combinations(assets, 2):
        shared = _cert_fingerprints(a) & _cert_fingerprints(b)
        if shared:
            edges.append({
                "fromAssetId": str(a["_id"]), "toAssetId": str(b["_id"]),
                "relationType": "shares_certificate",
                "evidence": f"certFingerprint={next(iter(shared))}",
                "confidence": "certaine",
            })
    return edges


def _correlate_by_favicon(assets):
    edges = []
    for a, b in combinations(assets, 2):
        shared = _favicon_hashes(a) & _favicon_hashes(b)
        if shared:
            edges.append({
                "fromAssetId": str(a["_id"]), "toAssetId": str(b["_id"]),
                "relationType": "shares_favicon",
                "evidence": f"faviconHash={next(iter(shared))}",
                "confidence": "probable",
            })
    return edges


def _rdns_root(asset):
    rdns = asset.get("rdns") or ""
    parts = rdns.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else None


def _correlate_by_rdns_root(assets):
    edges = []
    for a, b in combinations(assets, 2):
        root_a, root_b = _rdns_root(a), _rdns_root(b)
        if root_a and root_a == root_b:
            edges.append({
                "fromAssetId": str(a["_id"]), "toAssetId": str(b["_id"]),
                "relationType": "same_rdns_root",
                "evidence": f"rdnsRoot={root_a}",
                "confidence": "probable",
            })
    return edges


def _correlate_by_asn_block(assets):
    edges = []
    for a, b in combinations(assets, 2):
        asn_a = (a.get("asn") or {}).get("asn")
        asn_b = (b.get("asn") or {}).get("asn")
        if asn_a and asn_a == asn_b:
            edges.append({
                "fromAssetId": str(a["_id"]), "toAssetId": str(b["_id"]),
                "relationType": "same_asn_block",
                "evidence": f"asn={asn_a}",
                "confidence": "probable",
            })
    return edges


def _parent_domain(hostname):
    if not hostname:
        return None
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _correlate_by_parent_domain(assets):
    """
    Relie les actifs qui partagent le même domaine racine (ex: admin.,
    app., www.kirilearn.com -> kirilearn.com) — le lien organisationnel
    le plus direct pour une cartographie par domaine, indépendant de
    l'infrastructure d'hébergement (qui peut différer d'un sous-domaine
    à l'autre sur des architectures cloud modernes : Google Cloud pour
    l'un, Vercel pour un autre, par exemple).
    """
    edges = []
    for a, b in combinations(assets, 2):
        hostname_a = a.get("hostname") or ""
        hostname_b = b.get("hostname") or ""
        if not hostname_a or not hostname_b:
            continue

        root_a = _parent_domain(hostname_a)
        root_b = _parent_domain(hostname_b)

        if root_a and root_a == root_b and hostname_a != hostname_b:
            edges.append({
                "fromAssetId": str(a["_id"]), "toAssetId": str(b["_id"]),
                "relationType": "same_parent_domain",
                "evidence": f"rootDomain={root_a}",
                "confidence": "certaine",
            })
    return edges