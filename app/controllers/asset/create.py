from flask import (
    request,
)

from app.services.asset import (
    AssetService,
)

from app.middlewares.auth import (
    auth_required,
)

from app.middlewares.permissions import (
    permission_required,
)

from app.validators.asset import (
    CreateAssetSchema,
)

from app.utils.api_response import (
    success_response,
)


@auth_required
@permission_required(
    "asset.create"
)
def create():

    data = (
        CreateAssetSchema()
        .load(
            request.json
        )
    )

    asset_id = (
        AssetService.create(
            data
        )
    )

    return success_response(
        "Asset created",
        {
            "id": asset_id,
        },
        201,
    )