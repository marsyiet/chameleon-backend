"""
Détection multi-rôles : un actif porte tous les rôles que ses services
justifient, chacun avec sa preuve.

L'identité (vendeur/modèle/firmware) est résolue une seule fois pour
l'actif entier, à partir du meilleur signal trouvé sur N'IMPORTE LEQUEL de
ses services, puis partagée.
"""

KNOWN_FAVICON_HASHES = {
    -1653412201: {"vendor": "MikroTik", "role": "firewall_router"},
    116323821: {"vendor": "Fortinet", "role": "vpn_gateway"},
    -1220785474: {"vendor": "pfSense", "role": "firewall_router"},
    -395468399: {"vendor": "Cisco", "role": "vpn_gateway"},
    1768726119: {"vendor": "UniFi", "role": "network_device_generic"},
}

HTTP_TITLE_SIGNATURES = [
    (["routeros", "mikrotik"], "MikroTik", "firewall_router"),
    (["+cscoe+", "cisco adaptive security"], "Cisco", "vpn_gateway"),
    (["fortinet", "fortigate", "sslvpn"], "Fortinet", "vpn_gateway"),
    (["pfsense"], "pfSense", "firewall_router"),
    (["opnsense"], "OPNsense", "firewall_router"),
    (["unifi network"], "Ubiquiti", "network_device_generic"),
    (["synology"], "Synology", "network_device_generic"),
    (["grafana"], "Grafana Labs", "devops_tool"),
    (["jenkins"], "Jenkins", "devops_tool"),
]

PORT_ROLE_MAP = {
    3306: "database", 5432: "database", 27017: "database",
    6379: "database", 9200: "database", 1433: "database",
    22: "remote_access", 3389: "remote_access", 5900: "remote_access", 23: "remote_access",
    25: "mail_server", 110: "mail_server", 143: "mail_server", 993: "mail_server", 995: "mail_server",
    21: "file_transfer",
    53: "dns_server",
    161: "network_device_generic",
    500: "vpn_gateway", 4500: "vpn_gateway",
    502: "industrial_control", 102: "industrial_control", 47808: "industrial_control",
    8291: "firewall_router",
    8728: "firewall_router",
}

VENDOR_BY_PORT = {
    8291: "MikroTik",
    8728: "MikroTik",
}

SERVICE_NAME_ROLE_MAP = {
    "ssh": "remote_access", "rdp": "remote_access", "vnc": "remote_access", "telnet": "remote_access",
    "mysql": "database", "postgresql": "database", "mongodb": "database", "redis": "database",
    "elasticsearch": "database", "ms-sql-s": "database",
    "smtp": "mail_server", "pop3": "mail_server", "imap": "mail_server",
    "ftp": "file_transfer",
    "domain": "dns_server",
    "isakmp": "vpn_gateway",
}

ROLE_PRIORITY = [
    "vpn_gateway", "firewall_router", "industrial_control", "database",
    "remote_access", "mail_server", "dns_server", "file_transfer",
    "authentication_portal", "api", "devops_tool", "iot_device",
    "network_device_generic", "web_application", "unknown",
]


def derive_service_roles(svc: dict, service_name: str, port: int) -> list:
    """
    Retourne TOUS les rôles justifiés pour un service donné, pas un seul —
    chaque rôle porte sa propre confiance et sa propre preuve littérale.
    """
    roles = []

    http_data = svc.get("http")
    if http_data:
        favicon_entry = KNOWN_FAVICON_HASHES.get(http_data.get("faviconHash"))
        if favicon_entry:
            roles.append({
                "role": favicon_entry["role"], "confidence": "certaine",
                "evidence": [f"favicon connu correspondant à {favicon_entry['vendor']}"],
            })

        title = (http_data.get("title") or "").lower()
        body = (http_data.get("bodyPreview") or "").lower()
        for keywords, vendor, role in HTTP_TITLE_SIGNATURES:
            if any(kw in title or kw in body for kw in keywords):
                roles.append({
                    "role": role, "confidence": "probable",
                    "evidence": [f"titre/contenu de page correspond à la signature '{vendor}'"],
                })
                break

        login_forms = http_data.get("loginPoints") or http_data.get("loginFormsDetected") or []
        real_forms = [lp for lp in login_forms if lp.get("confidence") == "certaine"]
        if real_forms:
            literal_terms = []
            for lp in real_forms:
                literal_terms.extend(lp.get("literalTextFound", []))
            roles.append({
                "role": "authentication_portal", "confidence": "certaine",
                "evidence": [f"formulaire de connexion réel détecté" + (f" (champs visibles : {', '.join(literal_terms)})" if literal_terms else "")],
            })
        elif login_forms:
            roles.append({
                "role": "authentication_portal", "confidence": "probable",
                "evidence": ["page de vérification d'accès probable (mots-clés admin/vérification détectés)"],
            })

        # Fallback : pages de login connues par signature titre quand
        # le formulaire HTML n'est pas dans le body (ex: RouterOS)
        if not any(r["role"] == "authentication_portal" for r in roles):
            login_title_keywords = ["routeros router configuration", "login", "sign in", "connexion"]
            if any(kw in title for kw in login_title_keywords):
                login_body_keywords = ["password", "mot de passe", "login", "#login"]
                if any(kw in body for kw in login_body_keywords):
                    roles.append({
                        "role": "authentication_portal", "confidence": "probable",
                        "evidence": ["titre et contenu de page suggèrent un portail de connexion"],
                    })

        if http_data.get("isApi") or http_data.get("apiSignalsFound"):
            roles.append({
                "role": "api", "confidence": "certaine",
                "evidence": ["réponse structurée (JSON) ou endpoint API confirmé"],
            })

        if http_data.get("statusCode") and not any(r["role"] in ("firewall_router", "vpn_gateway", "authentication_portal", "api", "devops_tool") for r in roles):
            roles.append({
                "role": "web_application", "confidence": "probable",
                "evidence": [f"réponse HTTP confirmée (statut {http_data.get('statusCode')})"],
            })

    devops = svc.get("devopsTool")
    if devops and devops.get("toolType"):
        roles.append({
            "role": "devops_tool", "confidence": "certaine" if devops.get("authRequired") is False else "probable",
            "evidence": [f"outil DevOps identifié : {devops['toolType']}"],
        })

    snmp = svc.get("snmp")
    if snmp and snmp.get("sysDescr"):
        roles.append({
            "role": "network_device_generic", "confidence": "certaine",
            "evidence": [f"SNMP sysDescr : {snmp['sysDescr']}"],
        })

    iot = svc.get("iot")
    if iot and iot.get("protocol"):
        roles.append({
            "role": "iot_device", "confidence": "certaine",
            "evidence": [f"protocole IoT détecté : {iot['protocol']}"],
        })

    ics = svc.get("ics")
    if ics and ics.get("protocol"):
        roles.append({
            "role": "industrial_control", "confidence": "certaine",
            "evidence": [f"protocole industriel détecté : {ics['protocol']}"],
        })

    if not roles:
        mapped_role = PORT_ROLE_MAP.get(port)
        if mapped_role:
            roles.append({
                "role": mapped_role, "confidence": "certaine" if port in (8291, 8728) else "probable",
                "evidence": [f"port {port} associé de façon fiable à '{mapped_role}'"],
            })
        elif service_name in SERVICE_NAME_ROLE_MAP:
            roles.append({
                "role": SERVICE_NAME_ROLE_MAP[service_name], "confidence": "probable",
                "evidence": [f"service Nmap identifié : {service_name}"],
            })

    if not roles:
        roles.append({"role": "unknown", "confidence": "faible", "evidence": []})

    return roles


def resolve_asset_identity(services: list) -> dict:
    identity = {
        "vendor": None, "vendorConfidence": "faible",
        "model": None, "firmwareVersion": None, "deviceLabel": None,
        "macAddress": None, "macVendor": None,
        "resolvedFrom": [],
    }

    confidence_rank = {"certaine": 2, "probable": 1, "faible": 0}

    for svc in services:
        port = svc.get("port")

        # ── SNMP : signal le plus fiable ──
        snmp = svc.get("snmp")
        if snmp and snmp.get("sysDescr"):
            if confidence_rank["certaine"] > confidence_rank[identity["vendorConfidence"]]:
                identity["vendorConfidence"] = "certaine"
            if not identity["model"] and snmp.get("sysDescr"):
                identity["model"] = snmp["sysDescr"]
            if not identity["deviceLabel"] and snmp.get("sysName"):
                identity["deviceLabel"] = snmp["sysName"]
            if snmp.get("enterpriseName"):
                identity["vendor"] = identity["vendor"] or snmp["enterpriseName"]
                identity["resolvedFrom"].append({"source": "snmp.sysDescr", "value": snmp["sysDescr"]})

        # ── Bannières protocolaires ──
        banner_parsed = svc.get("bannerParsed") or {}
        if banner_parsed.get("vendor"):
            if not identity["vendor"] or confidence_rank["certaine"] > confidence_rank[identity["vendorConfidence"]]:
                identity["vendor"] = identity["vendor"] or banner_parsed["vendor"]
                identity["vendorConfidence"] = "certaine"
            if banner_parsed.get("version") and not identity["firmwareVersion"]:
                identity["firmwareVersion"] = banner_parsed["version"]
            if banner_parsed.get("location") and not identity["deviceLabel"]:
                identity["deviceLabel"] = banner_parsed["location"]
            identity["resolvedFrom"].append({
                "source": f"services[port={port}].banner", "value": svc.get("banner", ""),
            })

        # ── Ports propriétaires ──
        if port in VENDOR_BY_PORT:
            identity["vendor"] = identity["vendor"] or VENDOR_BY_PORT[port]
            identity["resolvedFrom"].append({
                "source": f"services[port={port}].presence", "value": f"port {port} ouvert (propriétaire)",
            })

        # ── Titre HTTP ──
        http = svc.get("http")
        if http and http.get("title"):
            title_lower = http["title"].lower()
            for keywords, vendor, _role in HTTP_TITLE_SIGNATURES:
                if any(kw in title_lower for kw in keywords):
                    identity["vendor"] = identity["vendor"] or vendor
                    if confidence_rank.get("probable", 1) > confidence_rank.get(identity["vendorConfidence"], 0):
                        identity["vendorConfidence"] = "probable"
                    identity["resolvedFrom"].append({
                        "source": f"services[port={port}].http.title", "value": http["title"],
                    })
                    break

    return identity


def derive_asset_roles(all_service_roles: list) -> tuple:
    merged = {}
    for role_entry in all_service_roles:
        role = role_entry["role"]
        if role == "unknown":
            continue
        if role not in merged or confidence_value(role_entry["confidence"]) > confidence_value(merged[role]["confidence"]):
            merged[role] = role_entry
        else:
            merged[role]["evidence"] = list(set(merged[role]["evidence"] + role_entry["evidence"]))

    nature_roles = list(merged.values())

    if not nature_roles:
        return [{"role": "unknown", "confidence": "faible", "evidence": []}], "unknown"

    def rank(entry):
        try:
            return ROLE_PRIORITY.index(entry["role"])
        except ValueError:
            return len(ROLE_PRIORITY)

    primary = min(nature_roles, key=rank)["role"]
    return nature_roles, primary


def confidence_value(c):
    return {"certaine": 2, "probable": 1, "faible": 0}.get(c, 0)