from flask import request

from app.services.organization import (
    OrganizationService,
)

from app.middlewares.auth import (
    auth_required,
)

from app.middlewares.permissions import (
    permission_required,
)

from app.utils.api_response import (
    success_response,
)


@auth_required
@permission_required(
    "organization.update"
)
def update(
    organization_id
):

    data = request.json

    OrganizationService.update(
        organization_id,
        data,
    )

    return success_response(
        "Organization updated successfully"
    )