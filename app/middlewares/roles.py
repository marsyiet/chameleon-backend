from flask import g

from app.utils.exceptions import (
    UnauthorizedException,
)


def role_required(
    allowed_roles,
):

    def decorator():

        user = g.user

        if (
            user["role"]
            not in allowed_roles
        ):
            raise UnauthorizedException(
                "Access denied",
                403,
            )

    return decorator