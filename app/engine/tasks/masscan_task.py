import json
import os
import random
import subprocess
import tempfile
import time
from datetime import datetime

from bson import ObjectId

from app.engine.tasks.nmap_task import fingerprint_host
from app.engine.tasks.enrichment import enrich_host, TAGS_MAP
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
    "3000,3005,3006,3306,3389,5000,5432,5900,6379,8080,8291,8443,8728,27017"
)
UDP_PORTS = "161,500,4500"

LIKELY_REAL_PORTS = {21, 22, 23, 25, 53, 80, 443, 8080, 8291, 8443, 8728}
HTTP_PORTS = [80, 443, 3000, 3005, 3006, 5000, 8080, 8443]

MASSCAN_BASE_RATE = "300"
MASSCAN_WAIT_SECONDS = "5"
JITTER_MIN_SECONDS = 0.3
JITTER_MAX_SECONDS = 1.2
CIRCUIT_BREAKER_THRESHOLD = 3
CIRCUIT_BREAKER_COOLDOWN_SECONDS = 30
SUSPICIOUS_OPEN_RATIO = 0.8

PAAS_ASN_KEYWORDS = [
    "vercel", "netlify", "cloudflare", "fastly", "akamai",
    "amazon", "google", "microsoft", "digitalocean", "heroku",
]

# Opérateurs/hébergeurs dont le nom dans un subject TLS ou hostname
# ne désigne PAS l'organisation finale exploitant le service.
GENERIC_NETWORK_NAMES = [
    "camtel", "orange", "mtn", "afrinic", "ripe", "arin", "apnic",
    "letsencrypt", "cloudflare", "akamai", "fastly", "vercel",
    "amazon", "google", "microsoft", "sectigo", "digicert",
    "comodo", "globalstars",
]


def _is_generic_name(name: str) -> bool:
    if not name:
        return True
    lowered = name.lower()
    return any(g in lowered for g in GENERIC_NETWORK_NAMES)


def _infer_owner_organization(services: list, enriched: dict, domain: str = None,
                               target_organization_name: str = None) -> dict | None:
    """
    Infère l'organisation exploitant le service à partir de plusieurs sources,
    par ordre décroissant de fiabilité. Distinct de l'attribution réseau
    (propriétaire du bloc IP) qui reste dans le champ `attribution`.

    Retourne un dict {name, source, confidence} ou None si rien de fiable.
    """

    # 1. Déclaration explicite (scan micro ciblé)
    if target_organization_name:
        return {"name": target_organization_name, "source": "declared", "confidence": "certaine"}

    # 2. Certificat TLS — subject ou SANs
    for svc in services:
        tls = svc.get("tls") or {}
        subject = (tls.get("subject") or "").strip()
        if subject and not subject.startswith("*.") and not _is_generic_name(subject):
            return {"name": subject, "source": "tls_subject", "confidence": "probable"}
        # SANs : prend le premier qui ressemble à un domaine organisationnel
        for san in (tls.get("san") or []):
            san = san.strip()
            if san and not san.startswith("*.") and not _is_generic_name(san):
                return {"name": san, "source": "tls_san", "confidence": "probable"}

    # 3. Hostname / rDNS significatif (pas juste l'IP inversée de l'opérateur)
    rdns = enriched.get("rdns", "")
    if rdns and not _is_generic_name(rdns):
        return {"name": rdns, "source": "rdns", "confidence": "faible"}

    if domain and not _is_generic_name(domain):
        return {"name": domain, "source": "hostname", "confidence": "probable"}

    # 4. Titre HTTP
    for svc in services:
        http = svc.get("http") or {}
        title = (http.get("title") or "").strip()
        if title and len(title) > 3 and not _is_generic_name(title):
            return {"name": title, "source": "http_title", "confidence": "faible"}

    # 5. Bannières FTP / SSH
    for svc in services:
        banner = (svc.get("banner") or "").strip()
        if banner and not _is_generic_name(banner) and len(banner) > 5:
            # On ne prend que la première ligne de la bannière
            first_line = banner.splitlines()[0].strip()
            if first_line and not _is_generic_name(first_line):
                return {"name": first_line, "source": "banner", "confidence": "faible"}

    # 6. sysName SNMP
    for svc in services:
        snmp = svc.get("snmp") or {}
        sys_name = (snmp.get("sysName") or "").strip().strip('"')
        if sys_name and not _is_generic_name(sys_name):
            return {"name": sys_name, "source": "snmp_sysname", "confidence": "faible"}

    # 7. WHOIS domaine (registrant) si différent des noms génériques réseau
    whois_name = enriched.get("whois", {}).get("name")
    if whois_name and not _is_generic_name(whois_name):
        return {"name": whois_name, "source": "whois_ip", "confidence": "faible"}

    return None


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

    # Pré-filtre : si Nmap n'a identifié aucun service sur un hôte avec
    # beaucoup de ports, c'est un tarpit — skip immédiatement.
    nmap_services = nmap_data.get("services", [])
    if not nmap_services and len(tcp_ports) > 5:
        print(f"[SKIP] {host_ip} — Nmap n'a identifié aucun service sur {len(tcp_ports)} ports")
        return

    enriched = enrich_host(host_ip, nmap_data)

    web_target = domain or enriched.get("rdns") or host_ip
    services = enriched.get("services", nmap_data.get("services", []))
    services = _ensure_http_services_present(services, tcp_ports)

    udp_service_map = {500: "isakmp", 4500: "isakmp", 161: "snmp"}
    for udp_port in udp_ports:
        if not any(s.get("port") == udp_port and s.get("protocol") == "udp" for s in services):
            services.append({
                "port": udp_port, "protocol": "udp", "state": "open",
                "service": udp_service_map.get(udp_port, "unknown"),
                "product": "", "version": "", "banner": "", "cves": [], "productConfirmed": False,
            })

    is_paas = _is_paas_hosting(enriched, services)
    os_value = None if is_paas else nmap_data.get("os")

    if is_paas:
        paas_filtered = [s for s in services if s.get("port") in HTTP_PORTS or s.get("protocol") == "udp"]
        if paas_filtered:
            services = paas_filtered

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

                if not is_paas:
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

        enriched_services.append(Asset.build_service(svc))

    # ── Filtre : ne garder que les services avec au moins une donnée exploitable ──
    enriched_services = [
        svc for svc in enriched_services
        if not (
            not svc.get("product")
            and not svc.get("banner")
            and not (svc.get("http") or {}).get("statusCode")
            and not (svc.get("tls") or {}).get("issuer")
            and not (svc.get("snmp") or {}).get("sysDescr")
            and not (svc.get("ftp") or {}).get("anonymousLoginAllowed")
        )
    ]

    if not enriched_services:
        print(f"[SKIP] {host_ip} — aucun service exploitable après filtrage")
        return

    # ── Rôles, identité et tags calculés APRÈS le filtre ──
    final_role_entries = []
    for svc in enriched_services:
        final_role_entries.extend(
            derive_service_roles(svc, svc.get("service", ""), svc.get("port", 0))
        )

    identity = resolve_asset_identity(enriched_services)
    nature_roles, primary_role = derive_asset_roles(final_role_entries)
    auth_surfaces = _build_authentication_surfaces(enriched_services)

    filtered_tags = list({TAGS_MAP[svc["port"]] for svc in enriched_services if svc.get("port") in TAGS_MAP})
    if is_paas:
        filtered_tags.append("paas-hosting")
    if all_hostnames_for_ip and len(all_hostnames_for_ip) > 1:
        filtered_tags.append("shared-hosting")

    # ── Organisation exploitante (distinct du propriétaire réseau) ──
    scan = None
    try:
        db = get_db()
        scan = db.scans.find_one({"_id": ObjectId(scan_id)})
    except Exception:
        pass
    target_organization_name = scan.get("targetOrganizationName") if scan else None

    owner_organization = _infer_owner_organization(
        services=enriched_services,
        enriched=enriched,
        domain=domain,
        target_organization_name=target_organization_name,
    )

    _save_asset(
        scan_id, host_ip, enriched_services, nmap_data, enriched,
        identity=identity, nature_roles=nature_roles, primary_role=primary_role,
        auth_surfaces=auth_surfaces, filtered_tags=filtered_tags,
        owner_organization=owner_organization,
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

        if port == 8728:
            surfaces.append({
                "port": port, "protocol": protocol, "method": "vendor_proprietary",
                "confidence": "probable", "literalTextFound": [],
                "note": "API RouterOS (MikroTik), authentification requise",
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
    cmd += ["--rate", MASSCAN_BASE_RATE, "--output-format", "json", "--output-filename", out_file, "--wait", MASSCAN_WAIT_SECONDS]

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
                 primary_role="unknown", auth_surfaces=None, filtered_tags=None,
                 owner_organization=None, os_override=None, is_paas=False,
                 target_type="cidr", domain=None, site_id=None, organization_id=None,
                 dns_data=None, subdomains_discovered=None, whois_domain=None, all_hostnames_for_ip=None):
    db = get_db()
    now = datetime.utcnow()

    scan = db.scans.find_one({"_id": ObjectId(scan_id)})
    organization_id = organization_id or (scan.get("organizationId") if scan else None)

    # ── Attribution réseau : propriétaire du bloc IP ──
    attribution = {"guessedOrganizationName": None, "confidence": "inconnue", "signals": []}
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
        signals = [s for s, v in [("whois_org", whois_name), ("rdns", rdns)] if v]
        if signals:
            attribution = {
                "guessedOrganizationName": whois_name or rdns,
                "confidence": "probable",
                "signals": signals,
            }

    existing = db.assets.find_one({"ipAddress": ip, "organizationId": organization_id})

    if existing:
        services = _merge_services(existing.get("services", []), services)
        if existing.get("identity", {}).get("vendor") and not (identity or {}).get("vendor"):
            identity = existing["identity"]
        if existing.get("natureRoles") and (not nature_roles or primary_role == "unknown"):
            nature_roles = nature_roles or existing["natureRoles"]
            if primary_role == "unknown":
                primary_role = existing.get("primaryRoleForDisplay", "unknown")
        # Conserver ownerOrganization existant si le nouveau scan n'a rien trouvé de mieux
        if not owner_organization and existing.get("ownerOrganization"):
            owner_organization = existing["ownerOrganization"]

    human_vector_exposed = (
        any((svc.get("http") or {}).get("loginPoints") for svc in services)
        or "authentication_portal" in {r.get("role") for r in (nature_roles or [])}
    )

    reasons = []
    if identity and identity.get("vendor"):
        vendor_label = identity["vendor"]
        if identity.get("model"):
            vendor_label += f" {identity['model']}"
        reasons.append(f"identifié comme {vendor_label}")

    risk_score, severity = calculate_risk_score(
        primary_role, Asset._derive_exposure(ip), services, human_vector_exposed, extra_reasons=reasons
    )

    tags = filtered_tags if filtered_tags is not None else list(enriched.get("tags", []))

    update_fields = {
        "organizationId": organization_id, "lastScanId": scan_id, "siteId": site_id,
        "ipAddress": ip, "hostname": domain, "rootDomain": domain,
        "identity": identity or {},
        "natureRoles": nature_roles or [], "primaryRoleForDisplay": primary_role,
        "exposure": Asset._derive_exposure(ip),
        "humanVector": {
            "exposed": human_vector_exposed,
            "matchedAt": now if human_vector_exposed else None,
            "source": "crawler" if human_vector_exposed else None,
        },
        "severity": severity, "riskScore": risk_score, "services": services,
        "os": os_override if os_override is not None else nmap_data.get("os"),
        "geo": enriched.get("geo", {}), "asn": enriched.get("asn", {}), "bgp": enriched.get("bgp", {}),
        "rdns": enriched.get("rdns", ""), "attribution": attribution, "tags": tags,
        "authenticationSurfaces": auth_surfaces or [],
        "ownerOrganization": owner_organization,
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