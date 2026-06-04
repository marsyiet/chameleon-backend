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

from app.utils.api_response import (
    success_response,
)

from app.utils.mongo import (
    serialize_document,
    serialize_documents,
)


@auth_required
@permission_required(
    "asset.read"
)
def get_all():

    page = int(
        request.args.get(
            "page",
            1
        )
    )

    limit = int(
        request.args.get(
            "limit",
            10
        )
    )

    search = request.args.get(
        "search"
    )

    result = (
        AssetService.get_all(
            page,
            limit,
            search,
        )
    )

    result[
        "assets"
    ] = serialize_documents(
        result[
            "assets"
        ]
    )

    return success_response(
        "Assets retrieved",
        result,
    )


@auth_required
@permission_required(
    "asset.read"
)
def get_by_id(
    asset_id
):

    asset = (
        AssetService.get_by_id(
            asset_id
        )
    )

    return success_response(
        "Asset retrieved",
        serialize_document(
            asset
        ),
    )