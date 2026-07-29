import re
import socket
import time
import requests
import dns.resolver
import dns.query
import dns.zone
from app.config.config import config

# Hébergeurs PaaS/CDN connus dont le nom de produit détecté indique que
# certaines CVE applicatives ne s'appliquent pas telles quelles (le
# fournisseur patche/mitige lui-même côté plateforme).
PAAS_PRODUCTS = ["vercel", "netlify", "heroku", "render", "cloudflare pages"]

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CRT_SH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"

# Cache en mémoire du process worker — le catalogue KEV compte plusieurs
# milliers d'entrées et change peu dans la journée ; le retélécharger à
# chaque host scanné serait un gaspillage de bande passante et de temps.
_kev_cache = {"ids": None, "fetched_at": None}
KEV_CACHE_TTL_SECONDS = 6 * 3600  # 6h


def _get_kev_ids() -> set:
    now = time.time()

    if _kev_cache["ids"] is not None and (now - _kev_cache["fetched_at"]) < KEV_CACHE_TTL_SECONDS:
        return _kev_cache["ids"]

    try:
        r = requests.get(CISA_KEV_URL, timeout=10)
        data = r.json()
        ids = {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}
        _kev_cache["ids"] = ids
        _kev_cache["fetched_at"] = now
        return ids
    except Exception as e:
        print("[CISA KEV ERROR]", e)
        return _kev_cache["ids"] or set()


def enrich_host(ip: str, nmap_data: dict) -> dict:
    services_with_cves = _attach_cves(nmap_data.get("services", []))
    services_with_epss = _attach_epss(services_with_cves)
    services_with_kev = _attach_kev(services_with_epss)

    geo, asn = _get_geoip_and_asn(ip)

    return {
        "geo":      geo,
        "asn":      asn,
        "bgp":      _get_bgp(ip),
        "whois":    _get_whois(ip),
        "rdns":     _get_rdns(ip),
        "services": services_with_kev,
        "tags":     _auto_tag(nmap_data.get("services", [])),
    }


def _attach_kev(services: list) -> list:
    kev_ids = _get_kev_ids()
    if not kev_ids:
        return services

    for svc in services:
        for cve in svc.get("cves", []):
            cve["kev"] = cve.get("id") in kev_ids

    return services


def _get_geoip_and_asn(ip: str) -> tuple:
    """
    Un seul appel ipinfo.io fournit à la fois géolocalisation et ASN, avec
    une précision généralement meilleure que GeoLite2 gratuit sur les plages
    IP africaines. MaxMind reste utilisé en secours si ipinfo.io échoue.
    """
    geo, asn = {}, {}
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = r.json()

        org_raw = data.get("org", "")
        asn = {
            "asn": org_raw.split(" ")[0] if org_raw else None,
            "org": " ".join(org_raw.split(" ")[1:]) if org_raw else None,
            "isp": org_raw or None,
        }

        loc = data.get("loc", "")
        if loc and "," in loc:
            lat_str, lon_str = loc.split(",")
            geo = {
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "lat": float(lat_str),
                "lon": float(lon_str),
            }
    except Exception:
        pass

    if not geo:
        geo = _get_geoip(ip)

    return geo, asn


def _get_geoip(ip: str) -> dict:
    """Repli MaxMind (GeoLite2 local) si ipinfo.io n'a rien retourné."""
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


def _get_rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _clean_subdomain_name(name: str) -> str:
    """
    Nettoyage défensif : certaines réponses (crt.sh notamment) contiennent
    parfois un format Markdown [nom](url) ou des espaces parasites au lieu
    d'un nom de domaine brut.
    """
    name = name.strip().lower()
    match = re.match(r"^\[([^\]]+)\]", name)
    if match:
        name = match.group(1)
    if name.startswith("*."):
        name = name[2:]
    return name


def _discover_subdomains_crtsh(domain: str, max_retries: int = 3) -> list:
    for attempt in range(max_retries):
        try:
            r = requests.get(
                CRT_SH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=15,
            )
            if r.status_code == 200:
                entries = r.json()
                subdomains = set()
                for entry in entries:
                    name_value = entry.get("name_value", "")
                    for raw_name in name_value.split("\n"):
                        name = _clean_subdomain_name(raw_name)
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
                return sorted(subdomains)

            print(f"[CT LOGS crt.sh] status={r.status_code} pour {domain} (tentative {attempt+1}/{max_retries})")
        except Exception as e:
            print(f"[CT LOGS crt.sh ERROR] {type(e).__name__} {e} (tentative {attempt+1}/{max_retries})")

        if attempt < max_retries - 1:
            time.sleep(3 * (attempt + 1))

    return []


def _discover_subdomains_certspotter(domain: str) -> list:
    """
    Source de repli si crt.sh échoue — certspotter (Sectigo) expose une API
    Certificate Transparency équivalente, sans clé pour un usage raisonnable.
    """
    try:
        r = requests.get(
            CERTSPOTTER_URL,
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=15,
        )
        if r.status_code != 200:
            print(f"[CT LOGS certspotter] status={r.status_code} pour {domain}")
            return []
        entries = r.json()
        subdomains = set()
        for entry in entries:
            for raw_name in entry.get("dns_names", []):
                name = _clean_subdomain_name(raw_name)
                if name.endswith(domain) and name != domain:
                    subdomains.add(name)
        return sorted(subdomains)
    except Exception as e:
        print(f"[CT LOGS certspotter ERROR] {type(e).__name__} {e}")
        return []


def discover_subdomains_ct(domain: str) -> list:
    """
    Découverte de sous-domaines par Certificate Transparency (chapitre 1,
    §reconnaissance). crt.sh est la source primaire ; en cas d'échec après
    plusieurs tentatives (service public peu fiable, observé en pratique :
    404/502 intermittents), on retombe sur certspotter comme source de
    secours plutôt que d'abandonner la découverte.
    """
    subdomains = _discover_subdomains_crtsh(domain)
    if subdomains:
        print(f"[CT LOGS] {len(subdomains)} sous-domaines trouvés pour {domain} (crt.sh)")
        return subdomains

    print(f"[CT LOGS] crt.sh indisponible pour {domain}, tentative via certspotter")
    subdomains = _discover_subdomains_certspotter(domain)
    print(f"[CT LOGS] {len(subdomains)} sous-domaines trouvés pour {domain} (certspotter)")
    return subdomains


def resolve_dns_records(domain: str) -> dict:
    """
    Enregistrements DNS complets — A, AAAA, MX, NS, TXT — et vérification
    basique SPF/DMARC à partir des TXT (chapitre 1, §DNS).
    """
    records = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [],
               "spfValid": None, "dmarcPresent": None}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        records["a"] = [str(r) for r in resolver.resolve(domain, "A")]
    except Exception:
        pass
    try:
        records["aaaa"] = [str(r) for r in resolver.resolve(domain, "AAAA")]
    except Exception:
        pass
    try:
        records["mx"] = [str(r.exchange) for r in resolver.resolve(domain, "MX")]
    except Exception:
        pass
    try:
        records["ns"] = [str(r) for r in resolver.resolve(domain, "NS")]
    except Exception:
        pass
    try:
        txt_records = [str(r) for r in resolver.resolve(domain, "TXT")]
        records["txt"] = txt_records
        records["spfValid"] = any("v=spf1" in t for t in txt_records)
    except Exception:
        pass
    try:
        dmarc_records = [str(r) for r in resolver.resolve(f"_dmarc.{domain}", "TXT")]
        records["dmarcPresent"] = any("v=DMARC1" in t for t in dmarc_records)
    except Exception:
        records["dmarcPresent"] = False

    return records


def test_zone_transfer(domain: str, nameservers: list) -> bool:
    """
    Tente un transfert de zone AXFR sur chaque nameserver du domaine — une
    zone transférable expose l'intégralité de la structure DNS interne.
    Retourne True si AU MOINS un nameserver accepte le transfert.
    """
    for ns in nameservers:
        ns_clean = ns.rstrip(".")
        try:
            resolved_ns = dns.resolver.resolve(ns_clean, "A")
            ns_ip = str(resolved_ns[0])
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            if zone:
                return True
        except Exception:
            continue
    return False


def get_whois_domain(domain: str) -> dict:
    """
    WHOIS du nom de domaine (registrar, dates, nameservers) — distinct du
    WHOIS de l'IP déjà géré par _get_whois.
    """
    try:
        import whois
        w = whois.whois(domain)
        registrar = w.registrar
        created = w.creation_date
        expires = w.expiration_date
        if isinstance(created, list):
            created = created[0] if created else None
        if isinstance(expires, list):
            expires = expires[0] if expires else None
        nameservers = w.name_servers
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        return {
            "registrar": registrar,
            "createdAt": created.isoformat() if created else None,
            "expiresAt": expires.isoformat() if expires else None,
            "nameservers": list(nameservers) if nameservers else [],
        }
    except ImportError:
        print("[WHOIS DOMAIN] python-whois non installé — pip install python-whois")
        return {}
    except Exception as e:
        print("[WHOIS DOMAIN ERROR]", e)
        return {}


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
    détecté, on déclasse en "mitigated" plutôt que de la compter comme un
    risque valide dans le scoring.
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
                        "kev": False,
                        "status": status,
                    })
            except Exception:
                pass

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
    500:   "vpn/ike",
    554:   "camera/rtsp",
    993:   "mail/imaps",
    995:   "mail/pop3s",
    1883:  "iot/mqtt",
    2375:  "container/docker",
    3306:  "database/mysql",
    3389:  "remote/rdp",
    4500:  "vpn/ike-natt",
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