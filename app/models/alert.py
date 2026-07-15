from datetime import datetime


class Alert:
    """
    Unifie tous les signaux de surveillance décrits au chapitre 2 (§2.2) :
    - changements structurels/configuration/état (diff T0/T1)
    - corrélation MISP
    - corrélation vecteur humain (fuite d'identifiants)
    - domaine usurpé détecté (typosquatting)

    Une seule collection, discriminée par "type", plutôt qu'une collection par
    type de signal — ils partagent tous la même forme (actif concerné, gravité,
    statut de traitement, horodatage).
    """

    TYPES = (
        "change_structural",
        "change_configuration",
        "change_state",
        "misp_match",
        "leak_match",       # vecteur humain
        "typosquat_match",
    )

    @staticmethod
    def build(data):
        now = datetime.utcnow()
        return {
            "organizationId": data["organizationId"],
            "assetId": data.get("assetId"),

            # cf. Alert.TYPES
            "type": data["type"],
            "severity": data.get("severity", "informational"),

            "title": data["title"],
            "description": data.get("description"),
            # payload libre selon le type : { port } pour un changement, { iocId, iocValue }
            # pour MISP, { leakedEmail, source } pour vecteur humain, { squattedDomain } pour typosquat
            "details": data.get("details", {}),

            # nouvelle | acquittee | ignoree
            "status": "nouvelle",
            "acknowledgedBy": None,
            "acknowledgedAt": None,

            "createdAt": now,
            "updatedAt": now,
        }