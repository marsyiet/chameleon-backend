import socket
import requests
from app.config.config import config


def enrich_host(ip: str, nmap_data: dict) -> dict:
    return {
        "geo":   _get_geoip(ip),
        "asn":   _get_asn(ip),
        "bgp":   _get_bgp(ip),      # ← nouveau
        "whois": _get_whois(ip),    # ← nouveau
        "rdns":  _get_rdns(ip),
        "cves":  _get_cves(nmap_data.get("services", [])),
        "tags":  _auto_tag(nmap_data.get("services", [])),
    }


def _get_geoip(ip: str) -> dict:
    try:
        import maxminddb
        with maxminddb.open_database(config.GEOIP_DB_PATH) as reader:
            record = reader.get(ip)
            if not record:
                return {}
            return {
                "country":   record.get("country", {}).get("names", {}).get("en", ""),
                "city":      record.get("city", {}).get("names", {}).get("en", ""),
                "latitude":  record.get("location", {}).get("latitude"),
                "longitude": record.get("location", {}).get("longitude"),
            }
    except Exception:
        return {}


def _get_asn(ip: str) -> dict:
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=5,
        )
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


def _get_cves(services: list) -> list:
    cves = []
    for svc in services:
        product = svc.get("product", "") or svc.get("service", "")
        version = svc.get("version", "").replace("for_Windows_", "")

        if not product:
            continue

        keyword = f"{product} {version}".strip()

        try:
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                timeout=10,
            )
            data = r.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cves.append({
                    "id": cve.get("id"),
                    "description": (
                        cve.get("descriptions", [{}])[0].get("value", "")
                    ),
                    "cvss": (
                        cve.get("metrics", {})
                        .get("cvssMetricV31", [{}])[0]
                        .get("cvssData", {})
                        .get("baseScore")
                    ),
                })
        except Exception:
            continue

    return cves

def _get_bgp(ip: str) -> dict:
    """Préfixes BGP via bgpview.io"""
    try:
        r = requests.get(
            f"https://api.bgpview.io/ip/{ip}",
            timeout=5
        )
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
    """WHOIS via python-whois"""
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
    25:    "smtp",
    53:    "dns",
    80:    "web/http",
    102:   "ics/s7",
    443:   "web/https",
    445:   "windows/smb",
    554:   "camera/rtsp",
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