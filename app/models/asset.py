from datetime import datetime


class Asset:
    """
    Un Asset = un point sur une carte, identifiable par une icône déterminée par
    assetType. Chaque type peuple un sous-bloc de détail qui lui est propre
    (http pour un site web, networkDevice pour un routeur, api pour une API) —
    les blocs non pertinents pour un actif donné restent simplement vides.
    """

    # Ordre de priorité pour dériver assetType quand plusieurs services coexistent
    # sur le même actif (ex: HTTP + MySQL sur la même IP -> database l'emporte).
    TYPE_PRIORITY = (
        "authentication",
        "database",
        "remote-access",
        "mail",
        "network",
        "api",
        "web",
        "unknown",
    )

    @staticmethod
    def build(data):
        now = datetime.utcnow()
        return {
            # Propriétaire CONFIRMÉ (scan sur domaine déclaré, ou attribution validée
            # manuellement) — null pour un actif de carte nationale non encore attribué.
            "organizationId": data.get("organizationId"),
            "scanId": data.get("scanId"),
            "siteId": data.get("siteId"),

            "ipAddress": data.get("ipAddress"),
            "hostname": data.get("hostname"),
            "rootDomain": data.get("rootDomain"),
            "rdns": data.get("rdns"),
            "os": data.get("os"),

            # ---- Attribution ESTIMÉE (carte nationale, avant confirmation) ----
            "attribution": {
                "guessedOrganizationName": None,
                # certaine | probable | inconnue
                "confidence": "inconnue",
                # signaux ayant permis la déduction : rdns | certificate_cn | whois_org
                "signals": [],
            },

            # ---- Taxonomie de classification (chapitre 2, tableau 2.1) ----
            "exposure": Asset._derive_exposure(data.get("ipAddress")),
            # database | web | api | remote-access | mail | network | authentication | unknown
            "assetType": data.get("assetType", "unknown"),
            "humanVector": {"exposed": False, "matchedAt": None, "source": None},
            "severity": "informational",
            "detectionConfidence": "probable",

            "geo": {"country": None, "city": None, "lat": None, "lon": None},
            "asn": {"asn": None, "org": None, "isp": None},
            "tags": data.get("tags", []),

            # ---- Détail spécifique : SITE WEB ----
            # Peuplé si assetType in (web, api, authentication, mail-webmail).
            "http": {
                "title": None,
                "statusCode": None,
                "technologies": [],        # ex: ["WordPress 6.4", "PHP 8.1", "nginx"]
                "faviconUrl": None,
                "faviconHash": None,
                "screenshotUrl": None,     # capture prise par l'agent de crawl léger
                "redirectChain": [],
                # chaque élément : { url, type: basic|form|sso, confidence }
                "loginPoints": [],
                # formulaires "contactez-nous" détectés lors du crawl — signal d'exposition
                # d'adresses/infos, pas de contenu soumis collecté
                "contactForms": [],        # ex: [{ "url": "...", "fieldsDetected": ["email","phone"] }]
            },

            "tls": {
                "issuer": None,
                "subject": None,
                "san": [],
                "validFrom": None,
                "validTo": None,
                "expired": None,
                "signatureAlgorithm": None,
                "selfSigned": None,
            },

            # ---- Détail spécifique : ÉQUIPEMENT RÉSEAU (routeur, etc.) ----
            # Peuplé si assetType == "network".
            "networkDevice": {
                "vendor": None,             # ex: "MikroTik", "Cisco", "pfSense"
                "sysDescr": None,           # description SNMP si communauté faible/accessible
                "adminInterfaceDetected": None,  # url ou null
                "snmpExposed": None,
            },

            # ---- Détail spécifique : API ----
            # Peuplé si assetType == "api".
            "api": {
                "specFound": None,         # url d'une spec OpenAPI/Swagger trouvée, si publique
                "authType": None,          # none | apikey | basic | oauth | unknown
                "endpointsDiscovered": [],
            },

            "detectedCapabilities": [],

            "services": [],

            "riskScore": {
                "value": 0,
                "cvssMax": None,
                "epssMax": None,
                "criticality": None,
                "humanVectorFactor": 0,
                "calculatedAt": None,
            },

            "status": "active",
            "firstSeenAt": now,
            "lastSeenAt": now,
            "isDeleted": False,
            "deletedAt": None,
            "createdAt": now,
            "updatedAt": now,
        }

    @staticmethod
    def _derive_exposure(ip_address):
        if not ip_address:
            return "unknown"
        import ipaddress
        try:
            return (
                "interne"
                if ipaddress.ip_address(ip_address).is_private
                else "externe"
            )
        except ValueError:
            return "unknown"

    @staticmethod
    def derive_asset_type(services):
        """
        Applique TYPE_PRIORITY sur les services détectés pour déterminer
        assetType. `services` : liste de noms de service normalisés
        (ex: ["http", "mysql"]).
        """
        service_to_type = {
            "vpn": "authentication",
            "sso": "authentication",
            "mysql": "database",
            "postgresql": "database",
            "mongodb": "database",
            "redis": "database",
            "elasticsearch": "database",
            "ssh": "remote-access",
            "rdp": "remote-access",
            "vnc": "remote-access",
            "telnet": "remote-access",
            "smtp": "mail",
            "imap": "mail",
            "pop3": "mail",
            "snmp": "network",
            "api": "api",
            "http": "web",
            "https": "web",
        }
        found_types = {
            service_to_type.get(s.lower()) for s in services if service_to_type.get(s.lower())
        }
        for t in Asset.TYPE_PRIORITY:
            if t in found_types:
                return t
        return "unknown"

    @staticmethod
    def build_service(data):
        return {
            "port": data["port"],
            "protocol": data["protocol"],
            "state": data["state"],
            "service": data.get("service"),
            "product": data.get("product"),
            "version": data.get("version"),
            "banner": data.get("banner"),
            "cves": data.get("cves", []),
        }