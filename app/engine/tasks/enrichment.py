import socket, requests
from config import config
 
 
def enrich_host(ip: str, nmap_data: dict) -> dict:
    return {
        "geo":  _get_geoip(ip),
        "asn":  _get_asn(ip),
        "rdns": _get_rdns(ip),
        "cves": _get_cves(nmap_data.get("services", [])),
        "tags": _auto_tag(nmap_data.get("services", [])),
    }
 
 
def _get_geoip(ip: str) -> dict:
    """GeoIP via base MaxMind locale (GeoLite2-City.mmdb)."""
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
    """ASN via API publique ipinfo.io (500 req/jour gratuit)."""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = r.json()
        return {
            "asn":  data.get("org", "").split(" ")[0],
            "org":  " ".join(data.get("org", "").split(" ")[1:]),
            "isp":  data.get("org", ""),
        }
    except Exception:
        return {}
 
 
def _get_rdns(ip: str) -> str:
    """Reverse DNS (PTR record)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
 
 
def _get_cves(services: list) -> list:
    """Lookup CVEs via NVD API pour les services/versions détectés."""
    cves = []
    for svc in services:
        product = svc.get("product", "")  # ex: "Apache httpd"
        version = svc.get("version", "")  # ex: "2.4.51"
        if not product:
            continue
        keyword = f"{product} {version}".strip()
        try:
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                timeout=10
            )
            data = r.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cves.append({
                    "id":          cve.get("id"),
                    "description": cve.get("descriptions", [{}])[0].get("value", ""),
                    "cvss":        cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                                      .get("cvssData", {}).get("baseScore"),
                })
        except Exception:
            continue
    return cves
 
 
TAGS_MAP = {
    # Port → tag
    554:   "camera/rtsp",
    8554:  "camera/rtsp",
    47808: "ics/bacnet",
    102:   "ics/s7",
    1883:  "iot/mqtt",
    5900:  "remote/vnc",
    3389:  "remote/rdp",
    27017: "database/mongodb",
    5432:  "database/postgresql",
    3306:  "database/mysql",
    6379:  "database/redis",
    9200:  "database/elasticsearch",
    2375:  "container/docker",
    8080:  "web/http-alt",
    443:   "web/https",
}
 
def _auto_tag(services: list) -> list:
    ports = {svc.get("port") for svc in services}
    return list({TAGS_MAP[p] for p in ports if p in TAGS_MAP})
