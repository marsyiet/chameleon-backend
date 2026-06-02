from functools import wraps

from flask import g

from app.config.permissions import (
    PERMISSIONS,
)

from app.utils.exceptions import (
    UnauthorizedException,
)


def permission_required(
    permission
):

    def decorator(func):

        @wraps(func)
        def wrapper(
            *args,
            **kwargs
        ):

            role = g.user["role"]

            permissions = (
                PERMISSIONS.get(
                    role,
                    []
                )
            )

            if "*" in permissions:

                return func(
                    *args,
                    **kwargs
                )

            if permission not in permissions:

                raise UnauthorizedException(
                    "Permission denied",
                    403,
                )

            return func(
                *args,
                **kwargs
            )

        return wrapper

    return decorator