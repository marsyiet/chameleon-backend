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
from app.engine.tasks.crawler_task import get_site_intelligence
from app.engine.tasks.nature_detection import (
    derive_service_roles, resolve_asset_identity, derive_asset_roles,
)
from app.engine.tasks.banner_parser import parse_banner
from app.engine.tasks.snmp_task import query_snmp
from app.engine.tasks.protocol_probes import (
    probe_ftp_anonymous, probe_smtp, probe_dns_service,
    probe_http_methods_and_cors, probe_sensitive_files,
    detect_cdn_waf_from_headers, probe_devops_tool,
)
from app.engine.scoring import calculate_risk_score
from app.models.asset import Asset
from app.models.db import get_db

DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,143,161,443,445,993,995,"
    "3000,3005,3006,3306,3389,5000,5432,5900,6379,8080,8291,8443,27017"
)
UDP_PORTS = "161,500,4500"

LIKELY_REAL_PORTS = {80, 443, 8080, 8443}
HTTP_PORTS = [80, 443, 3000, 3005, 3006, 5000, 8080, 8443]

MASSCAN_BASE_RATE = "300"
JITTER_MIN_SECONDS = 0.3
JITTER_MAX_SECONDS = 1.2
CIRCUIT_BREAKER_THRESHOLD = 3
CIRCUIT_BREAKER_COOLDOWN_SECONDS = 30
SUSPICIOUS_OPEN_RATIO = 0.8

PAAS_ASN_KEYWORDS = [
    "vercel", "netlify", "cloudflare", "fastly", "akamai",
    "amazon", "google", "microsoft", "digitalocean", "heroku",
]


def _filter_suspicious_ports(ip, ports, total_scanned):
    if total_scanned == 0:
        return ports
    open_ratio = len(ports) / total_scanned
    if open_ratio < SUSPICIOUS_OPEN_RATIO:
        return ports
    filtered = [p for p in ports if p in LIKELY_REAL_PORTS]
    print(f"[MASSCAN SUSPICIOUS] {ip} : {len(ports)}/{total_scanned} ports ouverts ({open_ratio:.0%}) — restriction à {filtered or ports}.")
    return filtered if filtered else ports


def scan_cidr(scan_id, target_id, cidr, site_id=None, organization_id=None):
    open_hosts_tcp = _run_masscan(cidr, DEFAULT_PORTS, udp=False)
    open_hosts_udp = _run_masscan(cidr, UDP_PORTS, udp=True)
    total_tcp_ports = len(DEFAULT_PORTS.split(","))

    open_hosts = {}
    for ip, ports in open_hosts_tcp.items():
        open_hosts.setdefault(ip, {"tcp": [], "udp": []})["tcp"] = _filter_suspicious_ports(ip, ports, total_tcp_ports)
    for ip, ports in open_hosts_udp.items():
        open_hosts.setdefault(ip, {"tcp": [], "udp": []})["udp"] = ports

    print("[OPEN HOSTS]", open_hosts)

    consecutive_failures = 0
    for host_ip, ports in open_hosts.items():
        time.sleep(random.uniform(JITTER_MIN_SECONDS, JITTER_MAX_SECONDS))
        try:
            _process_host(scan_id, host_ip, ports, target_type="cidr", domain=None,
                           site_id=site_id, organization_id=organization_id)
            consecutive_failures = 0
        except Exception as e:
            print(f"[HOST ERROR] {host_ip} -> {e}")
            consecutive_failures += 1
            if consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
                print(f"[CIRCUIT BREAKER] pause {CIRCUIT_BREAKER_COOLDOWN_SECONDS}s")
                time.sleep(CIRCUIT_BREAKER_COOLDOWN_SECONDS)
                consecutive_failures = 0


def _ensure_http_services_present(services, tcp_ports):
    confirmed_ports = {s.get("port") for s in services}
    for port in tcp_ports:
        if port in HTTP_PORTS and port not in confirmed_ports:
            services.append({
                "port": port, "protocol": "tcp", "state": "open",
                "service": "https" if port in (443, 8443) else "http",
                "product": "", "version": "", "banner": "", "cves": [], "productConfirmed": False,
            })
    return services


def _process_host(scan_id, host_ip, ports, target_type, domain, site_id, organization_id=None,
                   dns_data=None, subdomains_discovered=None, whois_domain=None, all_hostnames_for_ip=None):
    tcp_ports = ports.get("tcp", []) if isinstance(ports, dict) else ports
    udp_ports = ports.get("udp", []) if isinstance(ports, dict) else []

    nmap_data = fingerprint_host(host_ip, tcp_ports)
    enriched = enrich_host(host_ip, nmap_data)

    web_target = domain or enriched.get("rdns") or host_ip
    services = enriched.get("services", nmap_data.get("services", []))
    services = _ensure_http_services_present(services, tcp_ports)

    for udp_port in udp_ports:
        if not any(s.get("port") == udp_port and s.get("protocol") == "udp" for s in services):
            services.append({
                "port": udp_port, "protocol": "udp", "state": "open",
                "service": "isakmp" if udp_port in (500, 4500) else "unknown",
                "product": "", "version": "", "banner": "", "cves": [], "productConfirmed": False,
            })

    is_paas = _is_paas_hosting(enriched, services)
    os_value = None if is_paas else nmap_data.get("os")

    enriched_services = []
    for svc in services:
        port = svc.get("port")
        protocol = svc.get("protocol")
        service_name = svc.get("service")

        banner_parsed = parse_banner(svc.get("banner", ""), protocol_hint=service_name)

        svc_http, svc_tls, svc_snmp, svc_ftp, svc_mail, svc_dns_service, svc_devops = (None,) * 7

        if protocol == "tcp" and port in HTTP_PORTS:
            use_https = port in (443, 8443)
            svc_http = zgrab_http(web_target, port, use_https=use_https)
            if use_https:
                svc_tls = zgrab_tls(web_target, port)
            favicon_data = fetch_favicon(web_target, port, use_https)
            if favicon_data:
                svc_http = svc_http or {}
                svc_http["faviconUrl"] = favicon_data.get("faviconUrl")
                svc_http["faviconHash"] = favicon_data.get("faviconHash")

            if svc_http and svc_http.get("statusCode"):
                site_intel = get_site_intelligence(
                    web_target, port, use_https,
                    homepage_body=svc_http.get("bodyPreview"),
                    homepage_status=svc_http.get("statusCode"),
                    homepage_headers=svc_http.get("headers"),
                )
                svc_http["title"] = svc_http.get("title") or site_intel.get("pageTitle")
                svc_http["metaDescription"] = site_intel.get("metaDescription")
                svc_http["technologies"] = site_intel.get("technologies", [])
                svc_http["loginPoints"] = site_intel.get("loginPoints", [])
                svc_http["contactForms"] = site_intel.get("contactForms", [])
                svc_http["apiSignalsFound"] = site_intel.get("apiSignalsFound", [])
                svc_http["isApi"] = site_intel.get("isApi", False)

                base_url = f"{'https' if use_https else 'http'}://{web_target}:{port}"
                methods_cors = probe_http_methods_and_cors(base_url)
                svc_http["httpMethodsAllowed"] = methods_cors.get("httpMethodsAllowed", [])
                svc_http["corsMisconfigured"] = methods_cors.get("corsMisconfigured")
                svc_http["sensitiveFilesFound"] = probe_sensitive_files(base_url)

                cdn_waf = detect_cdn_waf_from_headers(svc_http.get("headers"))
                svc_http["cdnDetected"] = cdn_waf.get("cdnProvider")
                svc_http["wafDetected"] = cdn_waf.get("wafProvider")

                svc_devops = probe_devops_tool(base_url, svc_http.get("bodyPreview"), svc_http.get("headers"))

        elif protocol == "tcp" and port == 21:
            svc_ftp = probe_ftp_anonymous(host_ip, port)
        elif protocol == "tcp" and port == 25:
            svc_mail = probe_smtp(host_ip, port)
        elif protocol == "udp" and port == 161:
            svc_snmp = query_snmp(host_ip)
        elif port == 53:
            svc_dns_service = probe_dns_service(host_ip)

        svc["bannerParsed"] = banner_parsed
        svc["http"] = svc_http
        svc["tls"] = svc_tls
        svc["snmp"] = svc_snmp
        svc["ftp"] = svc_ftp
        svc["mail"] = svc_mail
        svc["dnsService"] = svc_dns_service
        svc["devopsTool"] = svc_devops

        role_entries = derive_service_roles(svc, service_name, port)
        svc["_roles"] = role_entries

        enriched_services.append(Asset.build_service(svc))

    identity = resolve_asset_identity(enriched_services)
    all_roles = [r for svc in enriched_services for r in svc.get("_roles", [])]
    nature_roles, primary_role = derive_asset_roles(all_roles)

    for svc in enriched_services:
        svc.pop("_roles", None)

    auth_surfaces = _build_authentication_surfaces(enriched_services)

    _save_asset(
        scan_id, host_ip, enriched_services, nmap_data, enriched,
        identity=identity, nature_roles=nature_roles, primary_role=primary_role,
        auth_surfaces=auth_surfaces,
        os_override=os_value, is_paas=is_paas,
        target_type=target_type, domain=domain, site_id=site_id, organization_id=organization_id,
        dns_data=dns_data, subdomains_discovered=subdomains_discovered,
        whois_domain=whois_domain, all_hostnames_for_ip=all_hostnames_for_ip,
    )


def _build_authentication_surfaces(services):
    surfaces = []
    for svc in services:
        port = svc.get("port")
        protocol = svc.get("protocol")

        http = svc.get("http")
        if http:
            for lp in (http.get("loginPoints") or []):
                surfaces.append({
                    "port": port, "protocol": protocol, "method": "web_form",
                    "confidence": lp.get("confidence", "probable"),
                    "literalTextFound": [],
                    "note": lp.get("url", ""),
                })

        if svc.get("service") == "ssh":
            surfaces.append({
                "port": port, "protocol": protocol, "method": "ssh_login",
                "confidence": "certaine", "literalTextFound": [],
                "note": "SSH constitue par nature une surface d'authentification",
            })

        ftp = svc.get("ftp")
        if ftp and ftp.get("anonymousLoginAllowed") is False:
            surfaces.append({
                "port": port, "protocol": protocol, "method": "ftp_login",
                "confidence": "certaine", "literalTextFound": [],
                "note": "authentification FTP requise (accès anonyme refusé)",
            })

        if port == 8291:
            surfaces.append({
                "port": port, "protocol": protocol, "method": "vendor_proprietary",
                "confidence": "probable", "literalTextFound": [],
                "note": "protocole Winbox (MikroTik), authentification supposée",
            })

    return surfaces


def _is_paas_hosting(enriched, services):
    asn_org = (enriched.get("asn", {}).get("org") or "").lower()
    if any(k in asn_org for k in PAAS_ASN_KEYWORDS):
        return True
    return any(k in (svc.get("product") or "").lower() for svc in services for k in PAAS_ASN_KEYWORDS)


def _run_masscan(cidr, ports, udp=False):
    out_file = tempfile.mktemp(suffix=".json")
    cmd = ["masscan", cidr]
    cmd += ["-pU:" + ports] if udp else ["-p", ports]
    cmd += ["--rate", MASSCAN_BASE_RATE, "--output-format", "json", "--output-filename", out_file, "--wait", "1"]

    print("[MASSCAN]", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    print("[MASSCAN RETURN CODE]", result.returncode)
    if result.stderr:
        print("[MASSCAN STDERR]", result.stderr)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"Masscan failed: {result.stderr}")
    if not os.path.exists(out_file):
        return {}
    hosts = _parse_masscan_output(out_file)
    print(f"[MASSCAN PARSED {'UDP' if udp else 'TCP'}]", hosts)
    return hosts


def _parse_masscan_output(filepath):
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
            for port_info in entry.get("ports", []):
                port = port_info.get("port")
                if ip and port:
                    hosts.setdefault(ip, []).append(port)
        return hosts
    finally:
        if os.path.exists(filepath):
            os.unlink(filepath)


def _merge_services(old_services: list, new_services: list) -> list:
    """
    Fusionne les services par (port, protocole) entre un scan précédent et
    le nouveau, pour qu'un rescan partiel ou dégradé (ex: échec réseau
    temporaire) n'efface jamais silencieusement une information déjà
    obtenue lors d'un scan antérieur plus complet.
    """
    old_by_port = {(s["port"], s["protocol"]): s for s in old_services}
    merged = []

    for new_svc in new_services:
        key = (new_svc["port"], new_svc["protocol"])
        old_svc = old_by_port.get(key)

        if not old_svc:
            merged.append(new_svc)
            continue

        combined = dict(new_svc)

        for field in ["http", "tls", "snmp", "ftp", "mail", "dnsService", "devopsTool", "bannerParsed"]:
            new_value = new_svc.get(field)
            old_value = old_svc.get(field)
            if not new_value and old_value:
                combined[field] = old_value
            elif field == "http" and new_value and old_value:
                if not new_value.get("statusCode") and old_value.get("statusCode"):
                    combined[field] = old_value

        if not new_svc.get("cves") and old_svc.get("cves"):
            combined["cves"] = old_svc["cves"]
        if not new_svc.get("product") and old_svc.get("product"):
            combined["product"] = old_svc["product"]
            combined["version"] = old_svc.get("version") or combined.get("version")
            combined["productConfirmed"] = old_svc.get("productConfirmed", False)

        merged.append(combined)

    return merged


def _save_asset(scan_id, ip, services, nmap_data, enriched, identity=None, nature_roles=None,
                 primary_role="unknown", auth_surfaces=None, os_override=None, is_paas=False,
                 target_type="cidr", domain=None, site_id=None, organization_id=None,
                 dns_data=None, subdomains_discovered=None, whois_domain=None, all_hostnames_for_ip=None):
    db = get_db()
    now = datetime.utcnow()

    scan = db.scans.find_one({"_id": ObjectId(scan_id)})
    organization_id = organization_id or (scan.get("organizationId") if scan else None)

    attribution = {"guessedOrganizationName": None, "confidence": "inconnue", "signals": []}
    target_organization_name = scan.get("targetOrganizationName") if scan else None
    if target_organization_name:
        attribution = {"guessedOrganizationName": target_organization_name, "confidence": "certaine", "signals": ["declared"]}
    else:
        whois_name = enriched.get("whois", {}).get("name")
        rdns = enriched.get("rdns", "")
        signals = [s for s, v in [("whois_org", whois_name), ("rdns", rdns)] if v]
        if signals:
            attribution = {"guessedOrganizationName": whois_name or rdns, "confidence": "probable", "signals": signals}

    # ── Identité stable de l'actif : (ipAddress, organizationId), plus scanId.
    # Un rescan met à jour le même document au lieu d'en créer un nouveau ;
    # deux scans différents qui retrouvent la même IP convergent aussi vers
    # le même document, au lieu de produire des doublons. ──
    existing = db.assets.find_one({"ipAddress": ip, "organizationId": organization_id})

    if existing:
        services = _merge_services(existing.get("services", []), services)
        if existing.get("identity", {}).get("vendor") and not (identity or {}).get("vendor"):
            identity = existing["identity"]
        if existing.get("natureRoles") and (not nature_roles or primary_role == "unknown"):
            nature_roles = nature_roles or existing["natureRoles"]
            if primary_role == "unknown":
                primary_role = existing.get("primaryRoleForDisplay", "unknown")

    human_vector_exposed = any((svc.get("http") or {}).get("loginPoints") for svc in services)

    reasons = []
    if identity and identity.get("vendor"):
        reasons.append(f"identifié comme {identity['vendor']}" + (f" {identity.get('model')}" if identity.get("model") else ""))

    risk_score, severity = calculate_risk_score(primary_role, Asset._derive_exposure(ip), services, human_vector_exposed, extra_reasons=reasons)

    tags = list(enriched.get("tags", []))
    if is_paas:
        tags.append("paas-hosting")
    if all_hostnames_for_ip and len(all_hostnames_for_ip) > 1:
        tags.append("shared-hosting")

    update_fields = {
        "organizationId": organization_id, "lastScanId": scan_id, "siteId": site_id,
        "ipAddress": ip, "hostname": domain, "rootDomain": domain,
        "identity": identity or {},
        "natureRoles": nature_roles or [], "primaryRoleForDisplay": primary_role,
        "exposure": Asset._derive_exposure(ip),
        "humanVector": {"exposed": human_vector_exposed, "matchedAt": now if human_vector_exposed else None,
                         "source": "crawler" if human_vector_exposed else None},
        "severity": severity, "riskScore": risk_score, "services": services,
        "os": os_override if os_override is not None else nmap_data.get("os"),
        "geo": enriched.get("geo", {}), "asn": enriched.get("asn", {}), "bgp": enriched.get("bgp", {}),
        "rdns": enriched.get("rdns", ""), "attribution": attribution, "tags": tags,
        "authenticationSurfaces": auth_surfaces or [],
        "lastSeenAt": now, "isDeleted": False, "deletedAt": None, "updatedAt": now,
    }

    if dns_data is not None:
        update_fields["dns"] = dns_data
    if subdomains_discovered is not None:
        update_fields["subdomainsDiscovered"] = [{"subdomain": s, "source": "ct_logs"} for s in subdomains_discovered]
    if whois_domain is not None:
        update_fields["whois"] = {"ipNetwork": enriched.get("whois", {}), "domain": whois_domain}

    db.assets.update_one(
        {"ipAddress": ip, "organizationId": organization_id},
        {"$set": update_fields, "$setOnInsert": {"createdAt": now, "firstSeenAt": now}},
        upsert=True,
    )
    db.scans.update_one({"_id": ObjectId(scan_id)}, {"$inc": {"assetsDiscovered": 1}})