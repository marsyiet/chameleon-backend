from marshmallow import (
    Schema,
    fields,
    validate,
    validates_schema,
    ValidationError,
)

ASSET_TYPES = [
    "web",
    "database",
    "api",
    "remote-access",
    "mail",
    "authentication",
    "network",
    "unknown",
]

# Payload création (enregistrement manuel d'un actif connu, hors scan)
#
# {
#     "ipAddress": "8.8.8.8",
#     "hostname": "dns.google.com",
#     "assetType": "web",
#     "organizationId": "665f1a2b9c1e4a0012345678",   # optionnel — propriétaire confirmé
#     "siteId": "665f1a2b9c1e4a0012345699",            # optionnel — rattachement manuel de site
#     "tags": ["production"]
# }
class CreateAssetSchema(
    Schema
):
    ipAddress = fields.String(
        allow_none=True
    )
    hostname = fields.String(
        allow_none=True
    )
    # classification de l'actif (web/database/api/...), PAS le type de seed
    # (renommé pour éviter toute confusion avec l'ancien schéma)
    assetType = fields.String(
        load_default="unknown",
        validate=validate.OneOf(
            ASSET_TYPES
        )
    )
    organizationId = fields.String(
        allow_none=True
    )
    siteId = fields.String(
        allow_none=True
    )
    tags = fields.List(
        fields.String(),
        load_default=list
    )

    @validates_schema
    def validate_identifier(self, data, **kwargs):
        if not data.get("ipAddress") and not data.get("hostname"):
            raise ValidationError(
                "ipAddress ou hostname requis",
                field_name="ipAddress",
            )


# Payload mise à jour
#
# {
#     "status": "inactive",
#     "assetType": "database",
#     "siteId": "665f1a2b9c1e4a0012345699",
#     "tags": ["production", "critical"]
# }
class UpdateAssetSchema(
    Schema
):
    status = fields.String(
        validate=validate.OneOf(
            [
                "active",
                "inactive",
            ]
        )
    )
    # correction manuelle de la classification automatique, si besoin
    assetType = fields.String(
        validate=validate.OneOf(
            ASSET_TYPES
        )
    )
    # rattachement manuel de site (IP privée non géolocalisable, chapitre 2 §2.1.4,
    # ou correction d'un rattachement automatique)
    siteId = fields.String(
        allow_none=True
    )
    tags = fields.List(
        fields.String()
    )


# Payload de confirmation d'attribution — distinct d'une mise à jour générique
# car cette action a une portée précise : faire passer un actif de "attribution
# estimée" (carte nationale) à "propriétaire confirmé" (carte organisationnelle).
#
# {
#     "organizationId": "665f1a2b9c1e4a0012345678"
# }
class ConfirmAttributionSchema(
    Schema
):
    organizationId = fields.String(
        required=True
    )