from marshmallow import (
    Schema,
    fields,
    validate,
    validates_schema,
    ValidationError,
)

# Aligné sur ROLE_PRIORITY (nature_detection.py) — un actif créé manuellement
# peut déclarer un ou plusieurs rôles dès la création, cohérent avec
# natureRoles[] désormais non exclusif.
NATURE_ROLES = [
    "web_application", "api", "database", "remote_access", "mail_server",
    "dns_server", "file_transfer", "vpn_gateway", "firewall_router",
    "industrial_control", "authentication_portal", "network_device_generic",
    "iot_device", "devops_tool", "unknown",
]


# Payload création (enregistrement manuel d'un actif connu, hors scan)
#
# {
#     "ipAddress": "8.8.8.8",
#     "hostname": "dns.google.com",
#     "natureRoles": ["web_application"],
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
    # Rôles déclarés manuellement à la création — un actif peut en avoir
    # plusieurs simultanément (ex: routeur ET portail d'authentification).
    natureRoles = fields.List(
        fields.String(
            validate=validate.OneOf(NATURE_ROLES)
        ),
        load_default=list
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
#     "natureRoles": ["database"],
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
    # Correction manuelle des rôles détectés automatiquement, si besoin.
    natureRoles = fields.List(
        fields.String(
            validate=validate.OneOf(NATURE_ROLES)
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