from datetime import datetime


class RemediationAction:
    """
    Généralise ce qui aurait pu devenir une collection "FirewallRule" isolée :
    toute action de remédiation (blocage pare-feu, notification, recommandation
    organisationnelle pour le vecteur humain) partage le même cycle de vie
    (proposée -> validée -> appliquée -> journalisée), donc la même collection,
    discriminée par "actionType".
    """

    ACTION_TYPES = (
        "firewall_block",
        "notification",
        "organizational_recommendation",
    )

    @staticmethod
    def build(data):
        now = datetime.utcnow()
        return {
            "organizationId": data["organizationId"],
            "assetId": data.get("assetId"),
            "alertId": data.get("alertId"),  # remédiation déclenchée depuis quelle alerte

            # cf. RemediationAction.ACTION_TYPES
            "actionType": data["actionType"],

            # pour actionType == "firewall_block"
            "target": data.get("target"),          # IP ou domaine à bloquer
            "equipment": data.get("equipment"),     # ex: "pfsense"

            # proposee | validee | appliquee | rejetee | annulee
            "status": "proposee",

            # Traçabilité (ENF-03 du cahier des charges)
            "requestedBy": data.get("requestedBy"),
            "validatedBy": None,
            "validatedAt": None,
            "appliedAt": None,
            "justification": data.get("justification"),

            "createdAt": now,
            "updatedAt": now,
        }