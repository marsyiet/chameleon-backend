from flask import (
    request,
)

from app.services.scan import (
    ScanService,
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
    "scan.read"
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

    result = (
        ScanService.get_all(
            page,
            limit,
        )
    )

    result["scans"] = (
        serialize_documents(
            result["scans"]
        )
    )

    return success_response(
        "Scans retrieved",
        result,
    )


@auth_required
@permission_required(
    "scan.read"
)
def get_by_id(
    scan_id
):

    scan = (
        ScanService.get_by_id(
            scan_id
        )
    )

    return success_response(
        "Scan retrieved",
        serialize_document(
            scan
        ),
    )