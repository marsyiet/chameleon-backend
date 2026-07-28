"""
Détection de la nature d'un actif à partir de signaux croisés (favicon,
titre HTTP, bannières, OS, SNMP) — remplace la classification par simple
nom de service Nmap, qui ne distingue pas un routeur d'un site web dès
que tous deux exposent du HTTP.
"""

# Table de favicons connus (hash mmh3, convention Shodan/Censys).
# À enrichir au fil des découvertes — ce n'est volontairement pas exhaustif.
KNOWN_FAVICON_HASHES = {
    -1653412201: {"vendor": "MikroTik", "nature": "firewall_router"},
    116323821: {"vendor": "Fortinet", "nature": "vpn_gateway"},
    -1220785474: {"vendor": "pfSense", "nature": "firewall_router"},
    -395468399: {"vendor": "Cisco", "nature": "vpn_gateway"},
    1768726119: {"vendor": "UniFi", "nature": "network_device_generic"},
}

# Mots-clés dans le titre HTTP ou le corps de page, insensibles à la casse.
HTTP_TITLE_SIGNATURES = [
    (["routeros", "mikrotik"], "MikroTik", "firewall_router"),
    (["+cscoe+", "cisco adaptive security"], "Cisco", "vpn_gateway"),
    (["fortinet", "fortigate", "sslvpn"], "Fortinet", "vpn_gateway"),
    (["pfsense"], "pfSense", "firewall_router"),
    (["opnsense"], "OPNsense", "firewall_router"),
    (["unifi network"], "Ubiquiti", "network_device_generic"),
    (["synology"], "Synology", "network_device_generic"),
]

# Ports dont l'ouverture seule est un signal fort et suffisant.
PORT_NATURE_MAP = {
    3306: "database", 5432: "database", 27017: "database",
    6379: "database", 9200: "database", 1433: "database",
    22: "remote_access", 3389: "remote_access", 5900: "remote_access",
    23: "remote_access",
    25: "mail_server", 110: "mail_server", 143: "mail_server",
    993: "mail_server", 995: "mail_server",
    21: "file_transfer",
    53: "dns_server",
    500: "vpn_gateway", 4500: "vpn_gateway",
    502: "industrial_control", 102: "industrial_control", 47808: "industrial_control",
}

SERVICE_NAME_NATURE_MAP = {
    "ssh": "remote_access", "rdp": "remote_access", "vnc": "remote_access", "telnet": "remote_access",
    "mysql": "database", "postgresql": "database", "mongodb": "database", "redis": "database",
    "elasticsearch": "database", "ms-sql-s": "database",
    "smtp": "mail_server", "pop3": "mail_server", "imap": "mail_server",
    "ftp": "file_transfer",
    "domain": "dns_server",
    "isakmp": "vpn_gateway",
}


def _match_favicon(favicon_hash):
    if favicon_hash is None:
        return None
    entry = KNOWN_FAVICON_HASHES.get(favicon_hash)
    if entry:
        return entry["nature"], entry["vendor"], f"favicon_hash:{favicon_hash}"
    return None


def _match_http_title(http_title, http_body_excerpt=""):
    haystack = f"{http_title or ''} {http_body_excerpt or ''}".lower()
    for keywords, vendor, nature in HTTP_TITLE_SIGNATURES:
        for kw in keywords:
            if kw in haystack:
                return nature, vendor, f"http_title:{kw}"
    return None


def _match_port_or_service(port, service_name):
    if port in PORT_NATURE_MAP:
        return PORT_NATURE_MAP[port], f"port:{port}"
    if service_name and service_name.lower() in SERVICE_NAME_NATURE_MAP:
        return SERVICE_NAME_NATURE_MAP[service_name.lower()], f"service:{service_name}"
    return None, None


def _has_login_form(http_data):
    return bool((http_data or {}).get("loginPoints"))


def _has_http(services):
    return any(s.get("service") in ("http", "https") or s.get("port") in (80, 443, 8080, 8443) for s in services)


def derive_service_nature(port, service_name, http_data=None, snmp_data=None):
    """
    Détermine la nature d'un service individuel (un port), avec ses propres
    signaux — un actif peut avoir plusieurs services de natures différentes
    (ex: 80/http = authentication_portal, 502/modbus = industrial_control).
    """
    signals = []

    if http_data:
        favicon_match = _match_favicon(http_data.get("faviconHash"))
        if favicon_match:
            nature, vendor, sig = favicon_match
            return {
                "natureType": nature, "vendorGuess": vendor,
                "natureConfidence": "certaine", "natureSignals": [sig],
            }

        title_match = _match_http_title(http_data.get("title"))
        if title_match:
            nature, vendor, sig = title_match
            return {
                "natureType": nature, "vendorGuess": vendor,
                "natureConfidence": "probable", "natureSignals": [sig],
            }

        if _has_login_form(http_data):
            return {
                "natureType": "authentication_portal", "vendorGuess": None,
                "natureConfidence": "probable", "natureSignals": ["login_form_detected"],
            }

    if snmp_data and snmp_data.get("vendor"):
        return {
            "natureType": "network_device_generic", "vendorGuess": snmp_data["vendor"],
            "natureConfidence": "probable", "natureSignals": ["snmp_sysdescr"],
        }

    nature, sig = _match_port_or_service(port, service_name)
    if nature:
        signals.append(sig)
        return {
            "natureType": nature, "vendorGuess": None,
            "natureConfidence": "probable", "natureSignals": signals,
        }

    if service_name in ("http", "https"):
        return {
            "natureType": "web_application", "vendorGuess": None,
            "natureConfidence": "probable", "natureSignals": [f"service:{service_name}"],
        }

    return {
        "natureType": "unknown", "vendorGuess": None,
        "natureConfidence": "faible", "natureSignals": [],
    }


def derive_asset_nature(services_with_nature: list) -> dict:
    """
    Nature "dominante" de l'actif entier, à partir des natures individuelles
    de chaque service. Priorité aux natures les plus spécifiques/critiques
    (VPN/firewall/database avant web_application générique).
    """
    if not services_with_nature:
        return {
            "natureType": "unknown", "vendorGuess": None,
            "natureConfidence": "faible", "natureSignals": [],
        }

    priority = [
        "vpn_gateway", "firewall_router", "industrial_control", "database",
        "remote_access", "mail_server", "dns_server", "file_transfer",
        "authentication_portal", "api", "network_device_generic",
        "web_application", "unknown",
    ]

    def rank(svc_nature):
        try:
            return priority.index(svc_nature["natureType"])
        except ValueError:
            return len(priority)

    best = min(services_with_nature, key=rank)
    return {
        "natureType": best["natureType"],
        "vendorGuess": best["vendorGuess"],
        "natureConfidence": best["natureConfidence"],
        "natureSignals": best["natureSignals"],
    }