from flask import g

from app.services.user import (
    UserService
)

from app.middlewares.auth import (
    auth_required
)

from app.middlewares.permissions import (
    permission_required
)

from app.utils.api_response import (
    success_response
)


@auth_required
@permission_required(
    "user.disable"
)
def disable(
    user_id
):

    UserService.disable(
        user_id,
        g.user["organizationId"]
    )

    return success_response(
        "User disabled"
    )