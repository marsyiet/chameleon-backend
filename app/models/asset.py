from datetime import datetime
import ipaddress


class Asset:
    """
    Un Asset = un point sur une carte, identifiable par une icône déterminée
    par primaryRoleForDisplay. Chaque service détecté porte sa propre nature,
    son propre http/tls — un même actif peut avoir plusieurs rôles (ex: VPN
    sur 500/udp et web générique sur 80/tcp), reflétés dans natureRoles[]
    (voir nature_detection.derive_asset_roles pour le remplissage via scan).
    """

    @staticmethod
    def build(data):
        now = datetime.utcnow()

        # Rôles déclarés manuellement à la création (hors scan) — construits
        # au même format que ceux produits par le pipeline de scan, pour que
        # les deux chemins de création restent interchangeables.
        declared_roles = data.get("natureRoles", [])
        nature_roles = [
            {
                "role": role,
                "confidence": "certaine",
                "evidence": ["déclaration manuelle"],
            }
            for role in declared_roles
        ]
        primary_role = declared_roles[0] if declared_roles else "unknown"

        return {
            "organizationId": data.get("organizationId"),
            "scanId": data.get("scanId"),
            "lastScanId": data.get("scanId"),
            "siteId": data.get("siteId"),
            "cidrBlock": data.get("cidrBlock"),

            "ipAddress": data.get("ipAddress"),
            "hostname": data.get("hostname"),
            "rootDomain": data.get("rootDomain"),
            "rdns": data.get("rdns", ""),

            # ---- Identité résolue une seule fois, partagée par tous les services ----
            "identity": {
                "vendor": None, "vendorConfidence": "faible",
                "model": None, "firmwareVersion": None, "deviceLabel": None,
                "macAddress": None, "macVendor": None,
                "resolvedFrom": [],
            },

            # ---- Rôles multiples, non exclusifs ----
            "natureRoles": nature_roles,
            "primaryRoleForDisplay": primary_role,

            "exposure": Asset._derive_exposure(data.get("ipAddress")),
            "status": "active",
            "os": {"guess": None, "confidence": None, "excludedReason": None},
            "icmp": {"respondsToPing": None},

            "dns": {
                "a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "caa": [],
                "spfValid": None, "dmarcPresent": None, "dmarcPolicy": None,
                "zoneTransferVulnerable": None,
            },
            "passiveDns": {"historicalIps": []},       # nécessite API tierce — reste vide
            "relatedDomains": [],                        # nécessite API tierce — reste vide
            "subdomainsDiscovered": [],

            "whois": {
                "ipNetwork": {"name": None, "country": None, "abuse": None},
                "domain": None,
            },

            # ---- Attribution : estimée par défaut, confirmée via
            # AssetService.confirm_attribution ----
            "attribution": {
                "guessedOrganizationName": None,
                "confidence": "inconnue",
                "signals": [],
            },

            "services": [],

            "authenticationSurfaces": [],

            "cloudExposure": {
                "bucketsFound": [],
                "subdomainTakeoverRisk": [],
            },
            "hostingContext": {
                "sharedHostingNeighbors": [],
                "cdnProvider": None,
                "wafProvider": None,
            },

            "threatIntel": {
                "mispMatch": False, "mispEventId": None,
                "reputationFlags": [], "typosquatCandidateOf": None,
                "breachExposure": {"emailsFoundInBreaches": []},  # nécessite API tierce — reste vide
            },
            "codeExposure": {"leakedRepositoriesFound": []},      # nécessite API tierce — reste vide

            "correlationKeys": {
                "certFingerprints": [], "faviconHashes": [], "sharedRdnsRoot": None,
            },

            "geo": {
                "country": None, "city": None, "lat": None, "lon": None,
                "accuracyRadiusKm": None, "precise": None,
            },
            "asn": {"asn": None, "org": None, "isp": None},
            "bgp": {"prefix": None, "asn_name": None, "asn_country": None},

            "humanVector": {"exposed": False, "matchedAt": None, "source": None},

            "riskScore": {
                "value": 0, "cvssMax": None, "epssMax": None, "kevBonus": 0,
                "criticality": None, "humanVectorFactor": 0,
                "reasoning": None, "calculatedAt": None,
            },

            "tags": data.get("tags", []),
            "severity": "informational",
            "firstSeenAt": now, "lastSeenAt": now,
            "createdAt": now, "updatedAt": now,
            "isDeleted": False, "deletedAt": None,
        }

    @staticmethod
    def _derive_exposure(ip_address):
        if not ip_address:
            return "unknown"
        try:
            return "interne" if ipaddress.ip_address(ip_address).is_private else "externe"
        except ValueError:
            return "unknown"

    @staticmethod
    def build_service(data):
        """
        `http`/`tls`/`snmp`/`ftp`/`mail`/`dnsService`/`iot`/`ics`/`devopsTool`
        sont imbriqués ici (par service), plus au niveau racine de l'actif —
        évite qu'un actif avec plusieurs services HTTP voie un service
        écraser les données d'un autre.
        """
        return {
            "port": data["port"],
            "protocol": data["protocol"],
            "state": data["state"],
            "service": data.get("service"),
            "product": data.get("product"),
            "version": data.get("version"),
            "banner": data.get("banner"),
            "bannerParsed": data.get("bannerParsed") or {
                "vendor": None, "location": None, "version": None, "signature": None,
            },
            "cves": data.get("cves", []),
            "productConfirmed": data.get("productConfirmed", False),
            "defaultCredentialsFormPresent": data.get("defaultCredentialsFormPresent"),

            "http": data.get("http"),
            "tls": data.get("tls"),
            "snmp": data.get("snmp"),
            "ftp": data.get("ftp"),
            "mail": data.get("mail"),
            "dnsService": data.get("dnsService"),
            "iot": data.get("iot"),
            "ics": data.get("ics"),
            "devopsTool": data.get("devopsTool"),
        }