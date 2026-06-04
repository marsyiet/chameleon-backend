from app.services.asset import (
    AssetService,
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
    "asset.delete"
)
def delete(
    asset_id
):

    AssetService.delete(
        asset_id
    )

    return success_response(
        "Asset deleted"
    )