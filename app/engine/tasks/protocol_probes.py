"""
Sondes protocolaires directes, réalisables sans aucun service tiers —
uniquement des connexions socket/HTTP que le pipeline effectue lui-même.
"""

import socket
import ftplib
import smtplib
import ssl
import requests
import dns.resolver


# ── FTP ──────────────────────────────────────────────────────────────────

def probe_ftp_anonymous(ip: str, port: int = 21, timeout: int = 5) -> dict:
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=timeout)
        try:
            ftp.login("anonymous", "anonymous@example.com")
            anonymous_allowed = True
            listing_exposed = False
            try:
                listing = ftp.nlst()
                listing_exposed = bool(listing)
            except Exception:
                pass
            ftp.quit()
            return {"anonymousLoginAllowed": anonymous_allowed, "directoryListingExposed": listing_exposed}
        except ftplib.error_perm:
            ftp.quit()
            return {"anonymousLoginAllowed": False, "directoryListingExposed": None}
    except Exception as e:
        print("[FTP PROBE ERROR]", ip, e)
        return {"anonymousLoginAllowed": None, "directoryListingExposed": None}


# ── SMTP ─────────────────────────────────────────────────────────────────

def probe_smtp(ip: str, port: int = 25, timeout: int = 6) -> dict:
    result = {"startTlsSupported": None, "openRelayDetected": None, "authMechanismsSupported": []}
    try:
        smtp = smtplib.SMTP(timeout=timeout)
        smtp.connect(ip, port)
        smtp.ehlo()

        result["startTlsSupported"] = smtp.has_extn("starttls")

        if smtp.has_extn("auth"):
            auth_line = smtp.esmtp_features.get("auth", "")
            result["authMechanismsSupported"] = auth_line.split()

        try:
            smtp.mail("probe@example-antic-easm-test.invalid")
            code, _ = smtp.rcpt("probe-dest@example-antic-easm-test-external.invalid")
            result["openRelayDetected"] = (code == 250)
        except Exception:
            result["openRelayDetected"] = False

        smtp.quit()
    except Exception as e:
        print("[SMTP PROBE ERROR]", ip, e)
    return result


# ── DNS (le service lui-même, port 53) ──────────────────────────────────

def probe_dns_service(ip: str, timeout: int = 4) -> dict:
    result = {"versionBind": None, "recursionEnabled": None}
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.timeout = timeout
        resolver.lifetime = timeout

        try:
            query = dns.message.make_query("version.bind", dns.rdatatype.TXT, dns.rdataclass.CH)
            response = dns.query.udp(query, ip, timeout=timeout)
            if response.answer:
                result["versionBind"] = str(response.answer[0][0])
        except Exception:
            pass

        try:
            answer = resolver.resolve("google.com", "A")
            result["recursionEnabled"] = bool(answer)
        except Exception:
            result["recursionEnabled"] = False

    except Exception as e:
        print("[DNS SERVICE PROBE ERROR]", ip, e)
    return result


# ── HTTP : méthodes autorisées, CORS, fichiers sensibles ────────────────

SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/backup.sql", "/.svn/entries",
    "/wp-config.php.bak", "/config.php.bak", "/.DS_Store", "/dump.sql",
]


def probe_http_methods_and_cors(base_url: str, timeout: int = 6) -> dict:
    result = {"httpMethodsAllowed": [], "corsMisconfigured": None}
    try:
        r = requests.options(base_url, timeout=timeout, verify=False)
        allow = r.headers.get("Allow", "")
        if allow:
            result["httpMethodsAllowed"] = [m.strip() for m in allow.split(",")]

        r2 = requests.get(base_url, timeout=timeout, verify=False,
                           headers={"Origin": "https://untrusted-origin-test.invalid"})
        acao = r2.headers.get("Access-Control-Allow-Origin", "")
        acac = r2.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" or (acao == "https://untrusted-origin-test.invalid" and acac.lower() == "true"):
            result["corsMisconfigured"] = True
        else:
            result["corsMisconfigured"] = False
    except Exception as e:
        print("[HTTP METHODS/CORS PROBE ERROR]", base_url, e)
    return result


def probe_sensitive_files(base_url: str, timeout: int = 5) -> list:
    found = []
    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(base_url + path, timeout=timeout, verify=False)
            if r.status_code == 200 and len(r.content) > 0:
                found.append(path)
        except Exception:
            continue
    return found


# ── CDN / WAF — pur pattern matching sur les en-têtes déjà récupérés ────

def detect_cdn_waf_from_headers(headers: dict) -> dict:
    lowered_headers = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}

    cdn = None
    if "cf-ray" in lowered_headers or "cloudflare" in lowered_headers.get("server", ""):
        cdn = "Cloudflare"
    elif any("akamai" in k for k in lowered_headers):
        cdn = "Akamai"
    elif "x-amz-cf-id" in lowered_headers:
        cdn = "Amazon CloudFront"
    elif "x-vercel-id" in lowered_headers:
        cdn = "Vercel"

    waf = None
    if "x-sucuri-id" in lowered_headers:
        waf = "Sucuri"

    return {"cdnProvider": cdn, "wafProvider": waf}


# ── Outils DevOps exposés ────────────────────────────────────────────────

DEVOPS_TOOL_SIGNATURES = [
    ("grafana", "grafana"), ("jenkins", "jenkins"),
    ("kubernetes", "kubernetes"), ("rabbitmq management", "rabbitmq"),
    ("kafka", "kafka"),
]

# Contenu attendu dans une vraie page de statut nginx/haproxy
NGINX_STATUS_MARKERS = ["active connections", "server accepts handled requests"]
HAPROXY_STATUS_MARKERS = ["haproxy", "frontend", "backend"]


def probe_devops_tool(base_url: str, homepage_body: str, homepage_headers: dict, timeout: int = 5) -> dict:
    """
    Détection par signature dans le contenu déjà récupéré (pas de requête
    réseau supplémentaire) + sondage de quelques chemins de statut connus.

    IMPORTANT : ne pas appeler sur des hôtes PaaS/CDN — Vercel/Cloudflare
    retournent 200 sur /nginx_status sans que ce soit un vrai statut nginx.
    Le filtrage PaaS se fait dans _process_host, pas ici.
    """
    lowered_body = (homepage_body or "").lower()
    for keyword, tool_type in DEVOPS_TOOL_SIGNATURES:
        if keyword in lowered_body:
            return {"toolType": tool_type, "authRequired": None, "exposedInfoSummary": f"détecté via mot-clé '{keyword}' dans le contenu"}

    # Sondage /nginx_status — vérifie que le contenu ressemble vraiment
    # à une page de statut nginx, pas juste un 200 générique d'un CDN.
    try:
        r = requests.get(base_url + "/nginx_status", timeout=timeout, verify=False)
        if r.status_code == 200:
            body_lower = r.text.lower()
            if any(marker in body_lower for marker in NGINX_STATUS_MARKERS):
                return {"toolType": "loadbalancer_status", "authRequired": False,
                         "exposedInfoSummary": "page de statut nginx accessible sur /nginx_status"}
    except Exception:
        pass

    # Sondage /haproxy?stats
    try:
        r = requests.get(base_url + "/haproxy?stats", timeout=timeout, verify=False)
        if r.status_code == 200:
            body_lower = r.text.lower()
            if any(marker in body_lower for marker in HAPROXY_STATUS_MARKERS):
                return {"toolType": "loadbalancer_status", "authRequired": False,
                         "exposedInfoSummary": "page de statut haproxy accessible sur /haproxy?stats"}
    except Exception:
        pass

    return None


# ── Risque de subdomain takeover ─────────────────────────────────────────

TAKEOVER_FINGERPRINTS = [
    ("herokuapp.com", "no such app"),
    ("github.io", "there isn't a github pages site here"),
    ("s3.amazonaws.com", "nosuchbucket"),
    ("azurewebsites.net", "404 web site not found"),
]


def check_subdomain_takeover(subdomain: str, cname_target: str, timeout: int = 6) -> dict:
    if not cname_target:
        return None

    cname_lower = cname_target.lower()
    matched_service = next((svc for svc, _ in TAKEOVER_FINGERPRINTS if svc in cname_lower), None)
    if not matched_service:
        return None

    try:
        r = requests.get(f"http://{subdomain}", timeout=timeout, verify=False)
        body_lower = r.text.lower()
        for svc, fingerprint in TAKEOVER_FINGERPRINTS:
            if svc == matched_service and fingerprint in body_lower:
                return {
                    "subdomain": subdomain,
                    "danglingCname": cname_target,
                    "confidence": "certaine",
                }
    except Exception:
        pass

    return None