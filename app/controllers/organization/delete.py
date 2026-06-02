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
    "organization.delete"
)
def delete(
    organization_id
):

    OrganizationService.delete(
        organization_id
    )

    return success_response(
        "Organization deleted successfully"
    )