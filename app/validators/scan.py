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
    

# ============================================================
# CREATE SCAN PAYLOAD
# ============================================================
#
# {
#   "name": "External Attack Surface",
#   "description": "Production infrastructure",
#   "scanType": "network",
#   "targets": [
#     {
#       "target": "192.168.1.0/24",
#       "targetType": "cidr"
#     },
#     {
#       "target": "10.0.0.0/24",
#       "targetType": "cidr"
#     },
#     {
#       "target": "8.8.8.8",
#       "targetType": "ip"
#     },
#     {
#       "target": "example.com",
#       "targetType": "domain"
#     }
#   ]
# }
#
# ============================================================
# UPDATE SCAN PAYLOAD
# ============================================================
#
# {
#   "name": "Updated Scan Name",
#   "description": "Updated description",
#   "scanType": "full"
# }
#
# ============================================================
# UPDATE SCAN STATUS PAYLOAD
# ============================================================
#
# {
#   "status": "running"
# }
#
# Status:
# pending | running | completed | failed | cancelled
# ============================================================