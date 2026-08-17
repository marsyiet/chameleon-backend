"""
Migration ponctuelle : recalcule ownerOrganization pour les assets dont ce
champ a été rempli, avant la correction de masscan_task.py, à partir d'une
bannière purement protocolaire (ex: "protocol 2.0", "SSH-2.0-...") plutôt
que d'un vrai nom d'organisation.

Usage :
    python migrate_clean_owner_organization.py            # dry-run
    python migrate_clean_owner_organization.py --apply     # applique réellement
"""

import argparse
import re

from app.models.db import get_db

GENERIC_NETWORK_NAMES = [
    "camtel", "orange", "mtn", "afrinic", "ripe", "arin", "apnic",
    "letsencrypt", "cloudflare", "akamai", "fastly", "vercel",
    "amazon", "google", "microsoft", "sectigo", "digicert",
    "comodo", "globalstars",
]

# Motifs purement techniques/protocolaires — jamais un nom d'organisation,
# même s'ils apparaissent en première ligne d'une bannière SSH/Telnet.
BANNER_NOISE_PATTERNS = [
    r"^protocol\s+[\d.]+$",
    r"^ssh-[\d.]+",
    r"^\d+\.\d+$",
]


def _is_banner_noise(text: str) -> bool:
    if not text:
        return True
    lowered = text.strip().lower()
    return any(re.match(p, lowered) for p in BANNER_NOISE_PATTERNS)


def _is_generic_name(name: str) -> bool:
    if not name:
        return True
    lowered = name.lower()
    return any(g in lowered for g in GENERIC_NETWORK_NAMES)


def _recompute_owner_organization(asset: dict):
    """
    Reproduit _infer_owner_organization (masscan_task.py version corrigée),
    mais uniquement les branches pertinentes pour une réévaluation a
    posteriori : TLS, rDNS, hostname, titre HTTP, bannière (filtrée), SNMP.
    Ne dépend d'aucun appel réseau — travaille uniquement sur les données
    déjà stockées.
    """
    services = asset.get("services", [])
    enriched_rdns = asset.get("rdns", "")
    domain = asset.get("hostname")

    for svc in services:
        tls = svc.get("tls") or {}
        subject = (tls.get("subject") or "").strip()
        if subject and not subject.startswith("*.") and not _is_generic_name(subject):
            return {"name": subject, "source": "tls_subject", "confidence": "probable"}
        for san in (tls.get("san") or []):
            san = san.strip()
            if san and not san.startswith("*.") and not _is_generic_name(san):
                return {"name": san, "source": "tls_san", "confidence": "probable"}

    if enriched_rdns and not _is_generic_name(enriched_rdns):
        return {"name": enriched_rdns, "source": "rdns", "confidence": "faible"}

    if domain and not _is_generic_name(domain):
        return {"name": domain, "source": "hostname", "confidence": "probable"}

    for svc in services:
        http = svc.get("http") or {}
        title = (http.get("title") or "").strip()
        if title and len(title) > 3 and not _is_generic_name(title):
            return {"name": title, "source": "http_title", "confidence": "faible"}

    for svc in services:
        banner = (svc.get("banner") or "").strip()
        if banner and not _is_generic_name(banner) and len(banner) > 5:
            first_line = banner.splitlines()[0].strip()
            if first_line and not _is_generic_name(first_line) and not _is_banner_noise(first_line):
                return {"name": first_line, "source": "banner", "confidence": "faible"}

    for svc in services:
        snmp = svc.get("snmp") or {}
        sys_name = (snmp.get("sysName") or "").strip().strip('"')
        if sys_name and not _is_generic_name(sys_name):
            return {"name": sys_name, "source": "snmp_sysname", "confidence": "faible"}

    whois_name = (asset.get("whois") or {}).get("ipNetwork", {}).get("name")
    if whois_name and not _is_generic_name(whois_name):
        return {"name": whois_name, "source": "whois_ip", "confidence": "faible"}

    return None


def migrate(apply_changes: bool):
    db = get_db()

    # Cible les assets dont ownerOrganization vient d'une bannière et
    # dont le nom ressemble à du bruit protocolaire.
    candidates = list(db.assets.find({"ownerOrganization.source": "banner"}))

    print(f"[MIGRATION] {len(candidates)} asset(s) avec ownerOrganization issu d'une bannière.")

    updated_count = 0
    for asset in candidates:
        current_name = (asset.get("ownerOrganization") or {}).get("name", "")
        if not _is_banner_noise(current_name):
            continue

        new_owner = _recompute_owner_organization(asset)

        print(f"  - {asset.get('ipAddress')} ({asset['_id']})")
        print(f"      ownerOrganization: {current_name!r} -> {(new_owner or {}).get('name')!r}")

        if apply_changes:
            db.assets.update_one(
                {"_id": asset["_id"]},
                {"$set": {"ownerOrganization": new_owner}},
            )

        updated_count += 1

    if apply_changes:
        print(f"[MIGRATION] {updated_count} asset(s) mis à jour en base.")
    else:
        print(f"[MIGRATION] Dry-run — {updated_count} asset(s) seraient mis à jour. Relancer avec --apply pour appliquer.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recalcule ownerOrganization pour les bannières protocolaires (ex: 'protocol 2.0').")
    parser.add_argument("--apply", action="store_true", help="Applique réellement les modifications (sinon dry-run)")
    args = parser.parse_args()

    migrate(apply_changes=args.apply)