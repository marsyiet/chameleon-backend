from functools import wraps

from flask import (
    request,
    g,
)

from app.utils.jwt import (
    verify_token,
)

from app.utils.exceptions import (
    UnauthorizedException,
)

from app.repositories.user import (
    UserRepository,
)


def auth_required(func):

    @wraps(func)
    def wrapper(
        *args,
        **kwargs
    ):

        token = request.cookies.get(
            "access_token"
        )

        if not token:

            raise UnauthorizedException(
                "Missing token",
                401,
            )

        payload = verify_token(
            token
        )

        user = (
            UserRepository.find_by_id(
                payload["userId"]
            )
        )

        if not user:

            raise UnauthorizedException(
                "User not found",
                401,
            )

        if (
            user.get("status")
            != "active"
        ):

            raise UnauthorizedException(
                "Account disabled",
                403,
            )

        g.user = payload

        return func(
            *args,
            **kwargs
        )

    return wrapper