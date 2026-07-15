from marshmallow import (
    Schema,
    fields,
    validate,
)

ACTION_TYPES = [
    "firewall_block",
    "notification",
    "organizational_recommendation",
]

# Payload création (un analyste propose une action de remédiation)
#
# {
#     "actionType": "firewall_block",
#     "assetId": "665f1a2b9c1e4a0012345678",
#     "alertId": "665f1a2b9c1e4a0012345699",   # optionnel — action déclenchée depuis une alerte
#     "target": "203.0.113.42",
#     "equipment": "pfsense",
#     "justification": "Service FTP vulnérable (CVE-2011-2523) détecté, score critique"
# }
class CreateRemediationActionSchema(
    Schema
):
    actionType = fields.String(
        required=True,
        validate=validate.OneOf(
            ACTION_TYPES
        )
    )
    assetId = fields.String(
        required=True
    )
    alertId = fields.String(
        allow_none=True
    )
    # requis uniquement pour actionType == "firewall_block", vérifié en service
    target = fields.String(
        allow_none=True
    )
    equipment = fields.String(
        allow_none=True
    )
    justification = fields.String(
        required=True,
        validate=validate.Length(
            min=5,
            max=500
        )
    )


# Payload de rejet — justification obligatoire (traçabilité, ENF-03)
#
# {
#     "justification": "Faux positif confirmé après vérification manuelle"
# }
class RejectRemediationActionSchema(
    Schema
):
    justification = fields.String(
        required=True,
        validate=validate.Length(
            min=5,
            max=500
        )
    )