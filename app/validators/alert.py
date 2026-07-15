from marshmallow import (
    Schema,
    fields,
    validate,
)

# Payload d'acquittement (optionnel — juste alert_id dans l'URL suffit techniquement,
# mais permettre une note aide l'équipe de sécurité à documenter pourquoi une alerte
# a été traitée sans action de remédiation, ex: faux positif, risque accepté)
#
# {
#     "note": "Faux positif — CDN mutualisé, actif non rattaché à l'organisation"
# }
class AcknowledgeAlertSchema(
    Schema
):
    note = fields.String(
        allow_none=True,
        validate=validate.Length(
            max=500
        )
    )