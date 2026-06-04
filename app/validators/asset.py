from marshmallow import (
    Schema,
    fields,
    validate,
)


# Payload création
#
# {
#     "assetType": "ip",
#     "value": "8.8.8.8"
# }
#
# ou
#
# {
#     "assetType": "domain",
#     "value": "google.com"
# }


class CreateAssetSchema(
    Schema
):

    assetType = fields.String(
        required=True,
        validate=validate.OneOf(
            [
                "ip",
                "domain",
                "host",
            ]
        )
    )

    value = fields.String(
        required=True
    )


# Payload mise à jour
#
# {
#     "status": "inactive",
#     "tags": [
#         "production",
#         "critical"
#     ]
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

    tags = fields.List(
        fields.String()
    )