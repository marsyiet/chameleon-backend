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

    targets = fields.List(
        fields.Nested(
            ScanTargetSchema
        ),
        required=True,
        validate=validate.Length(
            min=1
        )
    )

    # Désormais un ObjectId (chaîne) d'organisation existante, plus un nom
    # libre tapé à la main — sélectionné parmi les organisations réelles
    # côté frontend (Select alimenté par GET /organizations).
    targetOrganization = fields.String(
        allow_none=True,
        validate=validate.Length(
            min=1,
            max=100
        )
    )

    scheduledAt = fields.DateTime(
        allow_none=True,
        format="iso"
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
                "running",
                "completed",
                "failed",
                "cancelled",
            ]
        )
    )