from flask import request

from marshmallow import (
    ValidationError
)

from app.services.auth import (
    AuthService
)

from app.validators.auth import (
    BootstrapSchema,
    LoginSchema,
    LogoutSchema,
)

from app.utils.api_response import (
    success_response,
    error_response,
)

from flask import (
    request,
    g,
)

from app.middlewares.auth import (
    auth_required,
)

from app.validators.auth import (
    BootstrapSchema,
    LoginSchema,
    LogoutSchema,
    ChangePasswordSchema,
)

def bootstrap():

    try:

        data = (
            BootstrapSchema()
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

    result = (
        AuthService.bootstrap(
            data
        )
    )

    return success_response(
        "Platform initialized",
        result,
        201,
    )
    
def login():

    try:

        data = (
            LoginSchema()
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

    result = (
        AuthService.login(
            data["email"],
            data["password"]
        )
    )

    return success_response(
        "Login successful",
        result
    )
    
def logout():

    try:

        data = (
            LogoutSchema()
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

    AuthService.logout(
        data["refreshToken"]
    )

    return success_response(
        "Logout successful"
    )
    
    
@auth_required
def change_password():

    try:

        data = (
            ChangePasswordSchema()
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

    AuthService.change_password(
        user_id=g.user["userId"],
        current_password=data[
            "currentPassword"
        ],
        new_password=data[
            "newPassword"
        ]
    )

    return success_response(
        "Password changed successfully"
    )