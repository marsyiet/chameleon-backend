import json
import os
import random
import subprocess
import tempfile
import time
from datetime import datetime

from bson import ObjectId

from app.engine.tasks.nmap_task import fingerprint_host
from app.engine.tasks.enrichment import enrich_host
from app.engine.tasks.zgrab_task import zgrab_http, zgrab_tls, fetch_favicon
from app.engine.tasks.crawler_task import crawl_site
from app.engine.scoring import calculate_risk_score
from app.models.asset import Asset
from app.models.db import get_db

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,143,161,443,445,993,995,"
    "3000,3005,3006,3306,3389,5000,5432,5900,6379,8080,8443,27017"
)

HTTP_PORTS = [80, 443, 3000, 3005, 3006, 5000, 8080, 8443]
WEB_LIKE_TYPES = ("web", "api", "authentication")

MASSCAN_BASE_RATE = "300"
JITTER_MIN_SECONDS = 0.3
JITTER_MAX_SECONDS = 1.2
CIRCUIT_BREAKER_THRESHOLD = 3
CIRCUIT_BREAKER_COOLDOWN_SECONDS = 30

# Fournisseurs PaaS/CDN/cloud connus (mot-clé dans asn.org ou product) pour
# lesquels un OS fingerprint TCP/IP (Nmap -O) ne représente pas l'app réelle
# mais l'infra d'edge/load-balancing du fournisseur — donc trompeur à garder tel quel.
PAAS_ASN_KEYWORDS = [
    "vercel", "netlify", "cloudflare", "fastly", "akamai",
    "amazon", "google", "microsoft", "digitalocean", "heroku",
]


def scan_cidr(scan_id: str, target_id: str, cidr: str, site_id: str = None):
    open_hosts = _run_masscan(cidr)

    print("[OPEN HOSTS]")
    print(open_hosts)

    consecutive_failures = 0

    for host_ip, ports in open_hosts.items():
        time.sleep(random.uniform(JITTER_MIN_SECONDS, JITTER_MAX_SECONDS))

        try:
            _process_host(
                scan_id, host_ip, ports,
                target_type="cidr", domain=None, site_id=site_id,
            )
            consecutive_failures = 0
        except Exception as e:
            print(f"[HOST ERROR] {host_ip} -> {e}")
            consecutive_failures += 1
            if consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
                print(
                    f"[CIRCUIT BREAKER] {consecutive_failures} échecs consécutifs, "
                    f"pause de {CIRCUIT_BREAKER_COOLDOWN_SECONDS}s"
                )
                time.sleep(CIRCUIT_BREAKER_COOLDOWN_SECONDS)
                consecutive_failures = 0


def _process_host(scan_id, host_ip, ports, target_type, domain, site_id):
    nmap_data = fingerprint_host(host_ip, ports)
    enriched = enrich_host(host_ip, nmap_data)

    # Cible pour les requêtes HTTP/TLS/crawl : hostname si connu (scan
    # organisationnel), sinon rDNS résolu par l'enrichissement comme
    # candidat de secours, sinon l'IP nue en dernier recours.
    # C'EST CE CHAMP QUI CORRIGE LE BUG VERCEL : avant, on utilisait
    # systématiquement host_ip, donc sur un hébergeur mutualisé on tombait
    # sur le vhost par défaut au lieu du vrai site.
    web_target = domain or enriched.get("rdns") or host_ip

    services = enriched.get("services", nmap_data.get("services", []))

    http_data = {}
    tls_data = {}
    crawl_data = {}
    favicon_data = {}

    http_port = next(
        (s.get("port") for s in services if s.get("port") in HTTP_PORTS),
        None,
    )

    if http_port:
        http_data = zgrab_http(web_target, http_port)
        use_https = http_port in (443, 8443)
        if use_https:
            tls_data = zgrab_tls(web_target, http_port)
        favicon_data = fetch_favicon(web_target, http_port, use_https)

    provisional_type = Asset.derive_asset_type(
        [s.get("service", "") for s in services]
    )

    if http_port and provisional_type in WEB_LIKE_TYPES:
        crawl_data = crawl_site(web_target, http_port, http_port in (443, 8443))

    # Neutralisation de l'OS fingerprint sur PaaS/cloud connu (chapitre 3,
    # limite à documenter : le fingerprint TCP/IP d'un edge Vercel/Cloudflare
    # ne renseigne pas sur l'application réelle).
    is_paas = _is_paas_hosting(enriched, services)
    os_value = None if is_paas else nmap_data.get("os")

    _save_asset(
        scan_id, host_ip, ports, nmap_data, enriched,
        http_data=http_data, tls_data=tls_data, crawl_data=crawl_data,
        favicon_data=favicon_data, os_override=os_value, is_paas=is_paas,
        target_type=target_type, domain=domain, site_id=site_id,
    )


def _is_paas_hosting(enriched, services) -> bool:
    asn_org = (enriched.get("asn", {}).get("org") or "").lower()
    if any(keyword in asn_org for keyword in PAAS_ASN_KEYWORDS):
        return True
    for svc in services:
        product = (svc.get("product") or "").lower()
        if any(keyword in product for keyword in PAAS_ASN_KEYWORDS):
            return True
    return False


def _run_masscan(cidr: str) -> dict:
    out_file = tempfile.mktemp(suffix=".json")

    cmd = [
        "masscan",
        cidr,
        "-p", DEFAULT_PORTS,
        "--rate", MASSCAN_BASE_RATE,
        "--output-format", "json",
        "--output-filename", out_file,
        "--wait", "1",
    ]

    print("[MASSCAN]", " ".join(cmd))

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    print("[MASSCAN RETURN CODE]", result.returncode)
    if result.stderr:
        print("[MASSCAN STDERR]")
        print(result.stderr)

    if result.returncode not in (0, 1):
        raise RuntimeError(f"Masscan failed: {result.stderr}")

    if not os.path.exists(out_file):
        return {}

    hosts = _parse_masscan_output(out_file)
    print("[MASSCAN PARSED]")
    print(hosts)
    return hosts


def _parse_masscan_output(filepath: str) -> dict:
    try:
        with open(filepath, "r") as f:
            raw = f.read().strip()
        if not raw:
            return {}
        raw = raw.rstrip(",")
        if not raw.startswith("["):
            raw = "[" + raw + "]"
        data = json.loads(raw)
        hosts = {}
        for entry in data:
            ip = entry.get("ip")
            ports = entry.get("ports", [])
            for port_info in ports:
                port = port_info.get("port")
                if not ip or not port:
                    continue
                hosts.setdefault(ip, []).append(port)
        return hosts
    finally:
        if os.path.exists(filepath):
            os.unlink(filepath)


def _save_asset(
    scan_id, ip, ports, nmap_data, enriched,
    http_data=None, tls_data=None, crawl_data=None, favicon_data=None,
    os_override=None, is_paas=False,
    target_type="cidr", domain=None, site_id=None,
):
    db = get_db()
    now = datetime.utcnow()

    scan = db.scans.find_one({"_id": ObjectId(scan_id)})

    services = enriched.get("services", nmap_data.get("services", []))
    asset_type = Asset.derive_asset_type([svc.get("service", "") for svc in services])

    organization_id = None
    attribution = {"guessedOrganizationName": None, "confidence": "inconnue", "signals": []}

    # Propagation directe : si la structure auditée a été déclarée sur le scan
    # (ex: "MINFI"), tous les actifs qu'il découvre lui sont rattachés — que
    # le seed soit un domaine ou une plage CIDR. Sinon, tentative d'attribution
    # automatique (carte nationale, chapitre 2 §2.1.4), qui reste une estimation.
    target_organization = scan.get("targetOrganization") if scan else None

    if target_organization:
        organization_id = target_organization
        attribution = {
            "guessedOrganizationName": target_organization,
            "confidence": "certaine",
            "signals": ["declared"],
        }
    else:
        whois_name = enriched.get("whois", {}).get("name")
        rdns = enriched.get("rdns", "")
        signals = []
        if whois_name:
            signals.append("whois_org")
        if rdns:
            signals.append("rdns")
        if signals:
            attribution = {
                "guessedOrganizationName": whois_name or rdns,
                "confidence": "probable",
                "signals": signals,
            }

    http_block = dict(http_data or {})
    if crawl_data:
        http_block["technologies"] = crawl_data.get("technologies", [])
        http_block["loginPoints"] = crawl_data.get("loginPoints", [])
        http_block["contactForms"] = crawl_data.get("contactForms", [])
    if favicon_data:
        http_block["faviconUrl"] = favicon_data.get("faviconUrl")
        http_block["faviconHash"] = favicon_data.get("faviconHash")

    human_vector_exposed = bool(http_block.get("loginPoints"))

    risk_score, severity = calculate_risk_score(
        asset_type, Asset._derive_exposure(ip), services, human_vector_exposed,
    )

    tags = list(enriched.get("tags", []))
    if is_paas:
        tags.append("paas-hosting")

    db.assets.update_one(
        {"ipAddress": ip, "scanId": scan_id},
        {
            "$set": {
                "organizationId": organization_id,
                "scanId":         scan_id,
                "siteId":         site_id,
                "ipAddress":      ip,
                "hostname":       domain,
                "rootDomain":     domain,
                "assetType":      asset_type,
                "exposure":       Asset._derive_exposure(ip),
                "humanVector": {
                    "exposed": human_vector_exposed,
                    "matchedAt": now if human_vector_exposed else None,
                    "source": "crawler" if human_vector_exposed else None,
                },
                "severity":        severity,
                "riskScore":       risk_score,
                "services":        services,
                # None si is_paas (fingerprint TCP/IP non pertinent sur edge PaaS)
                "os":              os_override if os_override is not None else nmap_data.get("os"),
                "geo":             enriched.get("geo", {}),
                "asn":             enriched.get("asn", {}),
                "rdns":            enriched.get("rdns", ""),
                "attribution":     attribution,
                "tags":            tags,
                "http":            http_block,
                "tls":             tls_data or {},
                "lastSeenAt":      now,
                "isDeleted":       False,
                "deletedAt":       None,
                "updatedAt":       now,
            },
            "$setOnInsert": {
                "createdAt":   now,
                "firstSeenAt": now,
            },
        },
        upsert=True,
    )

    db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$inc": {"assetsDiscovered": 1}},
    )