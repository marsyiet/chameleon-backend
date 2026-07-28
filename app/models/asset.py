from datetime import datetime
import ipaddress


class Asset:
    """
    Un Asset = un point sur une carte, identifiable par une icône déterminée
    par natureType. Chaque service détecté porte sa propre nature, son propre
    http/tls — un même actif peut avoir plusieurs natures (ex: VPN sur 500/udp
    et web générique sur 80/tcp) ; natureType au niveau de l'actif reflète la
    nature dominante (cf. nature_detection.derive_asset_nature).
    """

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
            "cidrBlock": data.get("cidrBlock"),
            "os": data.get("os"),

            # ---- Attribution ESTIMÉE (carte nationale, avant confirmation) ----
            "attribution": {
                "guessedOrganizationName": None,
                # certaine | probable | inconnue
                "confidence": "inconnue",
                # signaux ayant permis la déduction : rdns | certificate_cn | whois_org | declared
                "signals": [],
            },

            "exposure": Asset._derive_exposure(data.get("ipAddress")),

            # ---- Nature de l'actif (remplace l'ancien assetType) ----
            # vpn_gateway | firewall_router | database | remote_access | mail_server |
            # dns_server | file_transfer | industrial_control | authentication_portal |
            # api | web_application | network_device_generic | unknown
            "natureType": data.get("natureType", "unknown"),
            "natureConfidence": data.get("natureConfidence", "faible"),
            "natureSignals": data.get("natureSignals", []),
            "vendorGuess": data.get("vendorGuess"),

            "humanVector": {"exposed": False, "matchedAt": None, "source": None},
            "severity": "informational",
            "detectionConfidence": "probable",

            "geo": {
                "country": None, "city": None, "lat": None, "lon": None,
                "accuracyRadiusKm": None, "precise": None,
            },
            "asn": {"asn": None, "org": None, "isp": None},
            "bgp": {"prefix": None, "announcedBy": None},
            "tags": data.get("tags", []),

            # DNS — peuplé uniquement si target de type "domain"
            "dns": {
                "a": [], "aaaa": [], "mx": [], "ns": [], "txt": [],
                "spfValid": None, "dmarcPresent": None,
                "zoneTransferVulnerable": None,
            },
            "subdomainsDiscovered": [],

            # WHOIS — ipNetwork toujours tenté, domain uniquement si applicable
            "whois": {
                "ipNetwork": {"name": None, "country": None, "abuseEmail": None},
                "domain": None,
            },

            "threatIntel": {
                "mispMatch": False, "mispEventId": None,
                "reputationFlags": [],
                "typosquatCandidateOf": None,
            },

            "correlationKeys": {
                "certFingerprints": [],
                "faviconHashes": [],
                "sharedRdnsRoot": None,
            },

            # Chaque service porte désormais son propre http/tls/nature —
            # voir Asset.build_service.
            "services": [],

            "riskScore": {
                "value": 0,
                "cvssMax": None,
                "epssMax": None,
                "kevBonus": 0,
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
        try:
            return (
                "interne"
                if ipaddress.ip_address(ip_address).is_private
                else "externe"
            )
        except ValueError:
            return "unknown"

    @staticmethod
    def build_service(data):
        """
        `http`/`tls`/`snmp` sont désormais imbriqués ici (par service),
        plus au niveau racine de l'actif — corrige le cas où un actif avec
        HTTP sur plusieurs ports voyait un service écraser les données de
        l'autre.
        """
        return {
            "port": data["port"],
            "protocol": data["protocol"],
            "state": data["state"],
            "service": data.get("service"),
            "product": data.get("product"),
            "version": data.get("version"),
            "banner": data.get("banner"),
            "cves": data.get("cves", []),
            "productConfirmed": data.get("productConfirmed", False),

            "natureType": data.get("natureType", "unknown"),
            "vendorGuess": data.get("vendorGuess"),
            "natureConfidence": data.get("natureConfidence", "faible"),
            "natureSignals": data.get("natureSignals", []),

            "http": data.get("http"),
            "tls": data.get("tls"),
            "snmp": data.get("snmp"),
        }