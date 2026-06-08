from flask import (
    request,
    g,
    make_response,
)

from marshmallow import (
    ValidationError
)

from app.services.auth import (
    AuthService
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

from app.utils.api_response import (
    success_response,
    error_response,
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

    response = make_response(
        success_response(
            "Login successful",
            result
        )
    )

    response.set_cookie(
        "access_token",
        result["accessToken"],
        httponly=True,
        secure=False,  # True en production HTTPS
        samesite="Lax",
        path="/",
    )

    response.set_cookie(
        "refresh_token",
        result["refreshToken"],
        httponly=True,
        secure=False,  # True en production HTTPS
        samesite="Lax",
        path="/",
    )

    return response


def logout():

    refresh_token = (
        request.cookies.get(
            "refresh_token"
        )
    )

    if refresh_token:

        try:

            AuthService.logout(
                refresh_token
            )

        except Exception:
            pass

    response = make_response(
        success_response(
            "Logout successful"
        )
    )

    response.delete_cookie(
        "access_token",
        path="/",
    )

    response.delete_cookie(
        "refresh_token",
        path="/",
    )

    return response


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