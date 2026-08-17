r"""
Migration unique consolidée, à lancer une fois après avoir déployé la
version corrigée de masscan_task.py / nmap_task.py. Corrige, sur les
assets déjà en base, les trois problèmes traités dans ce fichier :

  1. Bannières polluées par le texte littéral "\xHH" que Nmap insère dans
     sa sortie XML pour représenter les octets non imprimables de la
     négociation Telnet (IAC, RFC 854).
  2. ownerOrganization rempli à tort à partir d'une bannière SSH/Telnet
     (texte générique du vendeur de l'équipement, jamais un nom
     d'organisation exploitante) — recalculé, en ne gardant la branche
     bannière que pour FTP.
  3. attribution (propriétaire du bloc IP) vide alors que asn.org est
     connu — repli manquant avant correction du code.

Usage :
    python migrate_fix_asset_attribution.py            # dry-run
    python migrate_fix_asset_attribution.py --apply     # applique réellement
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

BANNER_NOISE_PATTERNS = [
    r"^protocol\s+[\d.]+$",
    r"^ssh-[\d.]+",
    r"^\d+\.\d+$",
    r"^[-=_~*#]{3,}$",
]

# Texte littéral "\xHH" (backslash, x, deux chiffres hex) que Nmap insère
# dans sa sortie XML pour représenter un octet non imprimable — PAS un
# octet binaire brut.
ESCAPED_HEX_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2})+")
MONGO_ESCAPED_HEX_PATTERN = r"\\x[0-9A-Fa-f]{2}"


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


def _strip_telnet_negotiation(raw: str) -> str:
    if not raw:
        return raw
    return ESCAPED_HEX_RUN.sub(" ", raw).strip()


def _recompute_owner_organization(asset: dict, services: list):
    """
    Reproduit _infer_owner_organization (masscan_task.py, version finale) :
    la branche bannière ne considère que les services FTP.
    """
    rdns = asset.get("rdns", "")
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

    if rdns and not _is_generic_name(rdns):
        return {"name": rdns, "source": "rdns", "confidence": "faible"}

    if domain and not _is_generic_name(domain):
        return {"name": domain, "source": "hostname", "confidence": "probable"}

    for svc in services:
        http = svc.get("http") or {}
        title = (http.get("title") or "").strip()
        if title and len(title) > 3 and not _is_generic_name(title):
            return {"name": title, "source": "http_title", "confidence": "faible"}

    for svc in services:
        if svc.get("service") != "ftp":
            continue
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
    updated_banners = 0
    updated_owners = 0
    updated_attribution = 0

    # ── 1 & 2 : bannières polluées + ownerOrganization non-FTP ──
    all_assets = list(db.assets.find({}))
    print(f"[MIGRATION] {len(all_assets)} asset(s) au total, analyse en cours...")

    for asset in all_assets:
        services = asset.get("services", [])
        set_fields = {}

        # 1. Nettoyage des bannières
        banner_changed = False
        for svc in services:
            old_banner = svc.get("banner")
            if old_banner and ESCAPED_HEX_RUN.search(old_banner):
                new_banner = _strip_telnet_negotiation(old_banner)
                if new_banner != old_banner:
                    svc["banner"] = new_banner
                    banner_changed = True
        if banner_changed:
            set_fields["services"] = services
            updated_banners += 1

        # 2. ownerOrganization à recalculer si sa source était une bannière
        # non-FTP (cas impossible dans la version finale du code), ou si son
        # nom matche un motif de bruit protocolaire
        current_owner = asset.get("ownerOrganization") or {}
        if current_owner.get("source") == "banner":
            owning_svc = next(
                (s for s in services if (s.get("banner") or "").strip().startswith(current_owner.get("name", "")[:20])),
                None,
            )
            was_non_ftp = owning_svc is not None and owning_svc.get("service") != "ftp"
            is_noise = _is_banner_noise(current_owner.get("name", ""))
            if was_non_ftp or is_noise:
                new_owner = _recompute_owner_organization(asset, services)
                set_fields["ownerOrganization"] = new_owner
                updated_owners += 1

        # 3. attribution vide alors que asn.org est connu
        attribution = asset.get("attribution") or {}
        asn_org = (asset.get("asn") or {}).get("org")
        if not attribution.get("guessedOrganizationName") and asn_org:
            existing_signals = attribution.get("signals", [])
            set_fields["attribution"] = {
                "guessedOrganizationName": asn_org,
                "confidence": "probable",
                "signals": list(set(existing_signals + ["asn_org"])),
            }
            updated_attribution += 1

        if set_fields:
            print(f"  - {asset.get('ipAddress')} ({asset['_id']}) : {list(set_fields.keys())}")
            if apply_changes:
                db.assets.update_one({"_id": asset["_id"]}, {"$set": set_fields})

    print(f"[MIGRATION] Bannières nettoyées : {updated_banners}")
    print(f"[MIGRATION] ownerOrganization recalculés : {updated_owners}")
    print(f"[MIGRATION] attribution complétée depuis asn.org : {updated_attribution}")

    if not apply_changes:
        print("[MIGRATION] Dry-run — relancer avec --apply pour appliquer réellement.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migration consolidée : bannières, ownerOrganization, attribution.")
    parser.add_argument("--apply", action="store_true", help="Applique réellement les modifications (sinon dry-run)")
    args = parser.parse_args()

    migrate(apply_changes=args.apply)