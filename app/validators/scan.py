from marshmallow import (
    Schema,
    fields,
    validate,
)
class ScanTargetSchema(
    Schema
):
    target = fields.String(
        required=True,
        validate=validate.Length(
            min=1,
            max=255
        )
    )
    targetType = fields.String(
        required=True,
        validate=validate.OneOf(
            [
                "ip",
                "cidr",
                "domain",
            ]
        )
    )
    # Rattachement manuel de site (chapitre 2, §2.1.4) — pertinent surtout
    # pour une cible de type IP/CIDR privée, non géolocalisable automatiquement.
    siteId = fields.String(
        required=False,
        allow_none=True,
    )
class CreateScanSchema(
    Schema
):
    name = fields.String(
        required=True,
        validate=validate.Length(
            min=3,
            max=100
        )
    )
    description = fields.String(
        allow_none=True,
        validate=validate.Length(
            max=500
        )
    )
    scanType = fields.String(
        required=True,
        validate=validate.OneOf(
            [
                "network",
                "web",
                "full",
            ]
        )
    )
    scheduledAt = fields.DateTime(
        required=False,
        allow_none=True,
        format="iso",
    )
    # Structure auditée par ce scan (ex: "MINFI") — simple texte, pas de
    # référence à une collection Organization pour l'instant.
    targetOrganization = fields.String(
        required=False,
        allow_none=True,
        validate=validate.Length(max=100),
    )
    targets = fields.List(
        fields.Nested(
            ScanTargetSchema
        ),
        required=True,
        validate=validate.Length(
            min=1
        )
    )
class UpdateScanSchema(
    Schema
):
    name = fields.String(
        validate=validate.Length(
            min=3,
            max=100
        )
    )
    description = fields.String(
        allow_none=True,
        validate=validate.Length(
            max=500
        )
    )
    scanType = fields.String(
        validate=validate.OneOf(
            [
                "network",
                "web",
                "full",
            ]
        )
    )
class UpdateScanStatusSchema(
    Schema
):
    status = fields.String(
        required=True,
        validate=validate.OneOf(
            [
                "pending",
                "scheduled",
                "running",
                "completed",
                "failed",
                "cancelled",
            ]
        )
    )