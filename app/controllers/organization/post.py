from flask import request

from marshmallow import ValidationError

from app.services.organization import (
    OrganizationService,
)

from app.validators.organization import (
    OrganizationSchema,
)

from app.utils.api_response import (
    success_response,
    error_response,
)

from app.middlewares.auth import (
    auth_required,
)

from app.middlewares.permissions import (
    permission_required,
)

@auth_required
@permission_required(
    "organization.create"
)
def create():

    schema = OrganizationSchema()

    try:

        data = schema.load(
            request.json
        )

    except ValidationError as e:

        return error_response(
            "Validation error",
            e.messages,
            422,
        )

    organization_id = (
        OrganizationService.create(
            data
        )
    )

    return success_response(
        "Organization created successfully",
        {
            "organizationId": organization_id
        },
        201,
    )