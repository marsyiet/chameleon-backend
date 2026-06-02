from flask import (
    request,
    g,
)

from marshmallow import (
    ValidationError
)

from app.validators.user import (
    CreateUserSchema,
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

from app.validators.user import (
    CreateUserSchema,
    ResetPasswordSchema,
)


@auth_required
@permission_required(
    "user.create"
)
def create():

    try:

        data = (
            CreateUserSchema()
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

    user_id = (
        UserService.create(
            data,
            g.user[
                "organizationId"
            ]
        )
    )

    return success_response(
        "User created",
        {
            "userId":
                user_id
        },
        201,
    )
    
    
@auth_required
@permission_required(
    "user.reset_password"
)
def reset_password(
    user_id
):

    try:

        data = (
            ResetPasswordSchema()
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

    UserService.reset_password(
        user_id,
        g.user[
            "organizationId"
        ],
        data[
            "password"
        ]
    )

    return success_response(
        "Password reset successfully"
    )