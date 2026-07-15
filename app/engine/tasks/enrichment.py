import re
import socket
import requests
from app.config.config import config

# Hébergeurs PaaS/CDN connus dont le nom de produit détecté indique que
# certaines CVE applicatives ne s'appliquent pas telles quelles (le
# fournisseur patche/mitige lui-même côté plateforme).
PAAS_PRODUCTS = ["vercel", "netlify", "heroku", "render", "cloudflare pages"]


def enrich_host(ip: str, nmap_data: dict) -> dict:
    services_with_cves = _attach_cves(nmap_data.get("services", []))
    services_with_epss = _attach_epss(services_with_cves)
    return {
        "geo":      _get_geoip(ip),
        "asn":      _get_asn(ip),
        "bgp":      _get_bgp(ip),
        "whois":    _get_whois(ip),
        "rdns":     _get_rdns(ip),
        "services": services_with_epss,
        "tags":     _auto_tag(nmap_data.get("services", [])),
    }


def _get_geoip(ip: str) -> dict:
    try:
        import maxminddb
        with maxminddb.open_database(config.GEOIP_DB_PATH) as reader:
            record = reader.get(ip)
            if not record:
                return {}
            return {
                "country": record.get("country", {}).get("names", {}).get("en", ""),
                "city":    record.get("city", {}).get("names", {}).get("en", ""),
                "lat":     record.get("location", {}).get("latitude"),
                "lon":     record.get("location", {}).get("longitude"),
            }
    except Exception:
        return {}


def _get_asn(ip: str) -> dict:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = r.json()
        return {
            "asn": data.get("org", "").split(" ")[0],
            "org": " ".join(data.get("org", "").split(" ")[1:]),
            "isp": data.get("org", ""),
        }
    except Exception:
        return {}


def _get_rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _version_tuple(version_str):
    if not version_str:
        return None
    nums = re.findall(r"\d+", version_str)
    if not nums:
        return None
    return tuple(int(n) for n in nums[:3])


def _version_in_range(detected, start_including, end_excluding, end_including):
    d = _version_tuple(detected)
    if d is None:
        return True
    if start_including and d < (_version_tuple(start_including) or d):
        return False
    if end_excluding and d >= (_version_tuple(end_excluding) or d):
        return False
    if end_including and d > (_version_tuple(end_including) or d):
        return False
    return True


def _cve_matches_version(cve_raw, detected_version):
    configurations = cve_raw.get("configurations", [])
    if not configurations or not detected_version:
        return True
    for config_node in configurations:
        for node in config_node.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", True):
                    continue
                start_inc = match.get("versionStartIncluding")
                end_exc = match.get("versionEndExcluding")
                end_inc = match.get("versionEndIncluding")
                if not (start_inc or end_exc or end_inc):
                    continue
                if _version_in_range(detected_version, start_inc, end_exc, end_inc):
                    return True
    return True


def _paas_mitigation_status(description: str, product: str) -> str:
    """
    Si la CVE elle-même documente qu'elle ne s'applique pas sur le PaaS
    détecté (cas fréquent chez Vercel/Netlify, qui patchent ou neutralisent
    côté plateforme), on déclasse en "mitigated" plutôt que de la compter
    comme un risque valide dans le scoring.
    """
    product_lower = (product or "").lower()
    matched_paas = next((p for p in PAAS_PRODUCTS if p in product_lower), None)
    if not matched_paas:
        return "valid"

    description_lower = description.lower()
    not_affected_markers = ["not affected", "unaffected", "are not affected", "isn't affected"]
    if matched_paas in description_lower and any(
        marker in description_lower for marker in not_affected_markers
    ):
        return "mitigated"

    return "valid"


def _attach_cves(services: list) -> list:
    enriched_services = []

    for svc in services:
        # BUG CORRIGÉ : avant, on retombait sur svc["service"] (le nom
        # générique du port, ex: "https", "redis") quand Nmap ne confirmait
        # pas de produit précis. Chercher un mot générique dans l'API NVD
        # (recherche texte libre) remonte des CVE sans aucun rapport réel
        # avec le service détecté — c'est ce qui polluait riskScore.
        product = svc.get("product", "")
        version = (svc.get("version", "") or "").replace("for_Windows_", "")

        cves = []

        if product:
            keyword = f"{product} {version}".strip()
            try:
                r = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": keyword, "resultsPerPage": 10},
                    timeout=10,
                )
                data = r.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    description = cve.get("descriptions", [{}])[0].get("value", "")

                    if description.startswith("Rejected reason"):
                        continue

                    if not _cve_matches_version(cve, version):
                        continue

                    status = _paas_mitigation_status(description, product)

                    cves.append({
                        "id": cve.get("id"),
                        "description": description,
                        "cvss": (
                            cve.get("metrics", {})
                            .get("cvssMetricV31", [{}])[0]
                            .get("cvssData", {})
                            .get("baseScore")
                        ),
                        "epss": None,
                        # valid | mitigated (exclue du scoring, gardée pour transparence)
                        "status": status,
                    })
            except Exception:
                pass

        # Pas de produit confirmé -> pas de recherche CVE ; on garde une trace
        # explicite que l'identification est incomplète, plutôt que de laisser
        # croire que "cves: []" veut dire "vérifié, rien trouvé".
        enriched_services.append({
            **svc,
            "cves": cves,
            "productConfirmed": bool(product),
        })

    return enriched_services


def _attach_epss(services: list) -> list:
    all_cve_ids = [
        cve["id"]
        for svc in services
        for cve in svc.get("cves", [])
        if cve.get("id")
    ]
    if not all_cve_ids:
        return services

    epss_by_id = {}
    try:
        r = requests.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": ",".join(all_cve_ids[:100])},
            timeout=10,
        )
        for entry in r.json().get("data", []):
            epss_by_id[entry.get("cve")] = float(entry.get("epss", 0))
    except Exception:
        pass

    for svc in services:
        for cve in svc.get("cves", []):
            cve["epss"] = epss_by_id.get(cve.get("id"))

    return services


def _get_bgp(ip: str) -> dict:
    try:
        r = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=5)
        data = r.json().get("data", {})
        prefixes = data.get("prefixes", [])
        if not prefixes:
            return {}
        p = prefixes[0]
        return {
            "prefix":      p.get("prefix"),
            "asn":         p.get("asn", {}).get("asn"),
            "asn_name":    p.get("asn", {}).get("name"),
            "asn_country": p.get("asn", {}).get("country_code"),
            "description": p.get("description"),
        }
    except Exception:
        return {}


def _get_whois(ip: str) -> dict:
    try:
        import ipwhois
        obj = ipwhois.IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        return {
            "name":    result.get("network", {}).get("name"),
            "country": result.get("network", {}).get("country"),
            "abuse":   next(iter([
                e.get("email") for e in result.get("objects", {}).values()
                if "abuse" in str(e.get("roles", [])).lower()
                and e.get("contact", {}).get("email")
            ]), None),
        }
    except Exception:
        return {}


TAGS_MAP = {
    21:    "ftp",
    22:    "remote/ssh",
    23:    "remote/telnet",
    25:    "mail/smtp",
    53:    "dns",
    80:    "web/http",
    102:   "ics/s7",
    110:   "mail/pop3",
    143:   "mail/imap",
    161:   "network/snmp",
    443:   "web/https",
    445:   "windows/smb",
    554:   "camera/rtsp",
    993:   "mail/imaps",
    995:   "mail/pop3s",
    1883:  "iot/mqtt",
    2375:  "container/docker",
    3306:  "database/mysql",
    3389:  "remote/rdp",
    5432:  "database/postgresql",
    5900:  "remote/vnc",
    6379:  "database/redis",
    8080:  "web/http-alt",
    8443:  "web/https-alt",
    8554:  "camera/rtsp",
    9200:  "database/elasticsearch",
    27017: "database/mongodb",
    47808: "ics/bacnet",
}


def _auto_tag(services: list) -> list:
    ports = {svc.get("port") for svc in services}
    return list({TAGS_MAP[p] for p in ports if p in TAGS_MAP})