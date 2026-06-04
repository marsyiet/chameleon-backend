from flask import (
    request,
)

from app.services.scan import (
    ScanService,
)

from app.validators.scan import (
    UpdateScanSchema,
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
    "scan.update"
)
def update(
    scan_id
):

    data = (
        UpdateScanSchema()
        .load(
            request.get_json()
        )
    )

    ScanService.update(
        scan_id,
        data,
    )

    return success_response(
        "Scan updated"
    )