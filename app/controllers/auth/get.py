from flask import g

from app.middlewares.auth import (
    auth_required,
)

from app.utils.api_response import (
    success_response,
)


@auth_required
def me():

    return success_response(
        "Authenticated",
        g.user,
    )