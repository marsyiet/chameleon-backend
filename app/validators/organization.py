from marshmallow import (
    Schema,
    fields,
)


class OrganizationSchema(
    Schema
):

    name = fields.String(
        required=True
    )

    description = fields.String()

    sector = fields.String()