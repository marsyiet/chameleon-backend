"""
Extraction structurée depuis des bannières protocolaires brutes (FTP, SSH,
Telnet) — ces bannières contiennent souvent, en clair, le vendeur, parfois
la localisation et la version, sans qu'aucune authentification ne soit
nécessaire pour les obtenir.
"""

import re

# Signatures connues dans les bannières SSH pré-authentification.
SSH_SIGNATURES = [
    ("rossssh", "MikroTik"),
    ("dropbear", "Dropbear (embarqué générique)"),
    ("openssh", "OpenSSH"),
    ("cisco", "Cisco"),
]

# Mots-clés vendeur repérables dans une bannière FTP/Telnet.
BANNER_VENDOR_KEYWORDS = [
    ("mikrotik", "MikroTik"),
    ("huawei", "Huawei"),
    ("cisco", "Cisco"),
    ("fortinet", "Fortinet"),
    ("pfsense", "pfSense"),
    ("d-link", "D-Link"),
    ("tp-link", "TP-Link"),
    ("zte", "ZTE"),
    ("actiontec", "Actiontec"),
]


def parse_banner(banner: str, protocol_hint: str = "") -> dict:
    """
    Retourne un dict bannerParsed {vendor, location, version, signature}.
    Ne devine jamais silencieusement : un champ reste None si rien n'est
    trouvé, plutôt que d'inventer une valeur approximative.
    """
    result = {"vendor": None, "location": None, "version": None, "signature": None}
    if not banner:
        return result

    lowered = banner.lower()

    if protocol_hint == "ssh" or banner.startswith("SSH-"):
        for sig, vendor in SSH_SIGNATURES:
            if sig in lowered:
                result["vendor"] = vendor
                result["signature"] = banner.strip()
                break

    for kw, vendor in BANNER_VENDOR_KEYWORDS:
        if kw in lowered and not result["vendor"]:
            result["vendor"] = vendor

    # Version : cherche un motif type "x.y.z" ou "x.y" dans la bannière
    version_match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", banner)
    if version_match:
        result["version"] = version_match.group(1)

    # Localisation : heuristique simple — mot en majuscules de 3+ lettres
    # qui n'est ni le vendeur ni un mot protocolaire courant. Volontairement
    # prudent : ne remplit que si un candidat clair se dégage.
    protocol_words = {"FTP", "SSH", "SERVER", "READY", "ROUTER", "OS"}
    caps_words = re.findall(r"\b[A-Z]{3,}\b", banner)
    location_candidates = [
        w for w in caps_words
        if w not in protocol_words and (not result["vendor"] or w.lower() not in result["vendor"].lower())
    ]
    if location_candidates:
        result["location"] = location_candidates[-1]

    return result