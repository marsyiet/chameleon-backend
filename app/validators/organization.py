from marshmallow import (
    Schema,
    fields,
    validate,
)


class OrganizationSchema(Schema):

    name = fields.String(required=True)

    description = fields.String(allow_none=True)

    sector = fields.String(allow_none=True)

    city = fields.String(allow_none=True)

    lat = fields.Float(
        allow_none=True,
        validate=validate.Range(min=-90, max=90),
    )

    lon = fields.Float(
        allow_none=True,
        validate=validate.Range(min=-180, max=180),
    )

    declaredDomains = fields.List(fields.String(), load_default=[])
    declaredInternalRanges = fields.List(fields.String(), load_default=[])
    declaredProviders = fields.List(fields.String(), load_default=[])
    declaredApps = fields.List(fields.Dict(), load_default=[])