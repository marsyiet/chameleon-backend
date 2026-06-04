from flask import (
    request,
)

from app.services.scan import (
    ScanService,
)

from app.validators.scan import (
    CreateScanSchema,
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
    "scan.create"
)
def create():

    data = (
        CreateScanSchema()
        .load(
            request.get_json()
        )
    )

    scan_id = (
        ScanService.create(
            data
        )
    )

    return success_response(
        "Scan created",
        {
            "id": scan_id
        },
        201,
    )