from flask import (
    request,
    g,
)

from marshmallow import (
    ValidationError
)

from app.validators.user import (
    UpdateUserSchema,
)

from app.services.user import (
    UserService,
)

from app.middlewares.auth import (
    auth_required,
)

from app.middlewares.permissions import (
    permission_required,
)

from app.utils.api_response import (
    success_response,
    error_response,
)


@auth_required
@permission_required(
    "user.update"
)
def update(
    user_id
):

    try:

        data = (
            UpdateUserSchema()
            .load(
                request.json
            )
        )

    except ValidationError as e:

        return error_response(
            "Validation error",
            e.messages,
            422,
        )

    UserService.update(
        user_id,
        g.user[
            "organizationId"
        ],
        data,
    )

    return success_response(
        "User updated"
    )