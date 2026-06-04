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


@auth_required
@permission_required(
    "scan.delete"
)
def delete(
    scan_id
):

    ScanService.delete(
        scan_id
    )

    return success_response(
        "Scan deleted"
    )