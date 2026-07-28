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
from app.engine.tasks.nature_detection import derive_service_nature, derive_asset_nature
from app.engine.scoring import calculate_risk_score
from app.models.asset import Asset
from app.models.db import get_db

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,143,161,443,445,993,995,"
    "3000,3005,3006,3306,3389,5000,5432,5900,6379,8080,8443,27017"
)
UDP_PORTS = "161,500,4500"

HTTP_PORTS = [80, 443, 3000, 3005, 3006, 5000, 8080, 8443]
LOGIN_CHECK_NATURES = ("web_application", "authentication_portal", "firewall_router", "vpn_gateway")

MASSCAN_BASE_RATE = "300"
JITTER_MIN_SECONDS = 0.3
JITTER_MAX_SECONDS = 1.2
CIRCUIT_BREAKER_THRESHOLD = 3
CIRCUIT_BREAKER_COOLDOWN_SECONDS = 30

PAAS_ASN_KEYWORDS = [
    "vercel", "netlify", "cloudflare", "fastly", "akamai",
    "amazon", "google", "microsoft", "digitalocean", "heroku",
]


def scan_cidr(scan_id: str, target_id: str, cidr: str, site_id: str = None, organization_id: str = None):
    open_hosts_tcp = _run_masscan(cidr, DEFAULT_PORTS, udp=False)
    open_hosts_udp = _run_masscan(cidr, UDP_PORTS, udp=True)

    open_hosts = {}
    for ip, ports in open_hosts_tcp.items():
        open_hosts.setdefault(ip, {"tcp": [], "udp": []})["tcp"] = ports
    for ip, ports in open_hosts_udp.items():
        open_hosts.setdefault(ip, {"tcp": [], "udp": []})["udp"] = ports

    print("[OPEN HOSTS]")
    print(open_hosts)

    consecutive_failures = 0

    for host_ip, ports in open_hosts.items():
        time.sleep(random.uniform(JITTER_MIN_SECONDS, JITTER_MAX_SECONDS))

        try:
            _process_host(
                scan_id, host_ip, ports,
                target_type="cidr", domain=None, site_id=site_id,
                organization_id=organization_id,
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


def _process_host(scan_id, host_ip, ports, target_type, domain, site_id, organization_id=None):
    tcp_ports = ports.get("tcp", []) if isinstance(ports, dict) else ports
    udp_ports = ports.get("udp", []) if isinstance(ports, dict) else []

    nmap_data = fingerprint_host(host_ip, tcp_ports)
    enriched = enrich_host(host_ip, nmap_data)

    web_target = domain or enriched.get("rdns") or host_ip
    services = enriched.get("services", nmap_data.get("services", []))

    # Ports UDP détectés mais non fingerprintés par Nmap TCP — ajoutés tels
    # quels, avec une identification minimale par port connu.
    for udp_port in udp_ports:
        if not any(s.get("port") == udp_port and s.get("protocol") == "udp" for s in services):
            services.append({
                "port": udp_port, "protocol": "udp", "state": "open",
                "service": "isakmp" if udp_port in (500, 4500) else "unknown",
                "product": "", "version": "", "banner": "",
                "cves": [], "productConfirmed": False,
            })

    is_paas = _is_paas_hosting(enriched, services)
    os_value = None if is_paas else nmap_data.get("os")

    # ── Enrichissement PAR SERVICE : http/tls/nature propres à chaque port,
    # corrige le bug où un seul bloc http/tls global écrasait les données
    # d'un service par un autre sur le même actif. ──
    enriched_services = []
    for svc in services:
        svc_http = None
        svc_tls = None

        if svc["protocol"] == "tcp" and svc.get("port") in HTTP_PORTS:
            http_port = svc["port"]
            svc_http = zgrab_http(web_target, http_port)
            use_https = http_port in (443, 8443)
            if use_https:
                svc_tls = zgrab_tls(web_target, http_port)
            favicon_data = fetch_favicon(web_target, http_port, use_https)
            if favicon_data:
                svc_http = svc_http or {}
                svc_http["faviconUrl"] = favicon_data.get("faviconUrl")
                svc_http["faviconHash"] = favicon_data.get("faviconHash")

        nature = derive_service_nature(
            port=svc.get("port"), service_name=svc.get("service"),
            http_data=svc_http, snmp_data=None,
        )

        if svc_http is not None and nature["natureType"] in LOGIN_CHECK_NATURES:
            http_port = svc["port"]
            use_https = http_port in (443, 8443)
            crawl_data = crawl_site(web_target, http_port, use_https)
            svc_http["technologies"] = crawl_data.get("technologies", [])
            svc_http["loginPoints"] = crawl_data.get("loginPoints", [])
            svc_http["contactForms"] = crawl_data.get("contactForms", [])
            # Re-dérive la nature avec les nouveaux signaux (login form trouvé)
            nature = derive_service_nature(
                port=svc.get("port"), service_name=svc.get("service"),
                http_data=svc_http, snmp_data=None,
            )

        enriched_services.append(
            Asset.build_service({
                **svc,
                "http": svc_http,
                "tls": svc_tls,
                "natureType": nature["natureType"],
                "vendorGuess": nature["vendorGuess"],
                "natureConfidence": nature["natureConfidence"],
                "natureSignals": nature["natureSignals"],
            })
        )

    asset_nature = derive_asset_nature([
        {"natureType": s["natureType"], "vendorGuess": s["vendorGuess"],
         "natureConfidence": s["natureConfidence"], "natureSignals": s["natureSignals"]}
        for s in enriched_services
    ])

    _save_asset(
        scan_id, host_ip, enriched_services, nmap_data, enriched,
        asset_nature=asset_nature, os_override=os_value, is_paas=is_paas,
        target_type=target_type, domain=domain, site_id=site_id,
        organization_id=organization_id,
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


def _run_masscan(cidr: str, ports: str, udp: bool = False) -> dict:
    out_file = tempfile.mktemp(suffix=".json")

    cmd = ["masscan", cidr]
    if udp:
        cmd += ["-pU:" + ports]
    else:
        cmd += ["-p", ports]
    cmd += [
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
    print(f"[MASSCAN PARSED {'UDP' if udp else 'TCP'}]")
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
    scan_id, ip, services, nmap_data, enriched,
    asset_nature=None, os_override=None, is_paas=False,
    target_type="cidr", domain=None, site_id=None, organization_id=None,
):
    db = get_db()
    now = datetime.utcnow()

    scan = db.scans.find_one({"_id": ObjectId(scan_id)})
    organization_id = organization_id or (scan.get("organizationId") if scan else None)

    attribution = {"guessedOrganizationName": None, "confidence": "inconnue", "signals": []}

    # Structure auditée déclarée sur le scan (résolue à la création du scan,
    # cf. Scan.build) — distincte de organizationId (propriétaire du scan).
    target_organization_id = scan.get("targetOrganizationId") if scan else None
    target_organization_name = scan.get("targetOrganizationName") if scan else None

    if target_organization_name:
        attribution = {
            "guessedOrganizationName": target_organization_name,
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

    human_vector_exposed = any(
        bool((svc.get("http") or {}).get("loginPoints")) for svc in services
    )

    risk_score, severity = calculate_risk_score(
        asset_nature["natureType"] if asset_nature else "unknown",
        Asset._derive_exposure(ip), services, human_vector_exposed,
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
                "natureType":       asset_nature["natureType"] if asset_nature else "unknown",
                "natureConfidence": asset_nature["natureConfidence"] if asset_nature else "faible",
                "natureSignals":    asset_nature["natureSignals"] if asset_nature else [],
                "vendorGuess":      asset_nature["vendorGuess"] if asset_nature else None,
                "exposure":       Asset._derive_exposure(ip),
                "humanVector": {
                    "exposed": human_vector_exposed,
                    "matchedAt": now if human_vector_exposed else None,
                    "source": "crawler" if human_vector_exposed else None,
                },
                "severity":        severity,
                "riskScore":       risk_score,
                "services":        services,
                "os":              os_override if os_override is not None else nmap_data.get("os"),
                "geo":             enriched.get("geo", {}),
                "asn":             enriched.get("asn", {}),
                "bgp":             enriched.get("bgp", {}),
                "rdns":            enriched.get("rdns", ""),
                "attribution":     attribution,
                "tags":            tags,
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