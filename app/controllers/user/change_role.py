from flask import (
    request,
    g,
)

from marshmallow import (
    ValidationError
)

from app.validators.user import (
    ChangeRoleSchema
)

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
    success_response,
    error_response,
)


@auth_required
@permission_required(
    "user.change_role"
)
def change_role(
    user_id
):

    try:

        data = (
            ChangeRoleSchema()
            .load(
                request.json
            )
        )

    except ValidationError as e:

        return error_response(
            "Validation error",
            e.messages,
            422
        )

    UserService.change_role(
        user_id,
        data["role"],
        g.user
    )

    return success_response(
        "Role updated"
    )