from flask import g

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
)


@auth_required
@permission_required(
    "user.read"
)
def get_all():

    users = (
        UserService.get_all(
            g.user[
                "organizationId"
            ]
        )
    )

    for user in users:

        user["_id"] = str(
            user["_id"]
        )

        user.pop(
            "password",
            None
        )

    return success_response(
        "Users retrieved",
        users,
    )


@auth_required
@permission_required(
    "user.read"
)
def get_by_id(
    user_id
):

    user = (
        UserService.get_by_id(
            user_id,
            g.user[
                "organizationId"
            ]
        )
    )

    if user:

        user["_id"] = str(
            user["_id"]
        )

        user.pop(
            "password",
            None
        )

    return success_response(
        "User retrieved",
        user,
    )