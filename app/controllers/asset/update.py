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
    UpdateAssetSchema,
)

from app.utils.api_response import (
    success_response,
)


@auth_required
@permission_required(
    "asset.update"
)
def update(
    asset_id
):

    data = (
        UpdateAssetSchema()
        .load(
            request.json
        )
    )

    AssetService.update(
        asset_id,
        data,
    )

    return success_response(
        "Asset updated"
    )