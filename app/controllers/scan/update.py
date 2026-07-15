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
    error_response,
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
@auth_required
@permission_required(
    "scan.update"
)
def reorder():
    body = (
        request.get_json()
        or {}
    )
    scan_ids = body.get(
        "scanIds",
        []
    )
    if (
        not scan_ids
        or not isinstance(
            scan_ids, list
        )
    ):
        return error_response(
            "scanIds requis (liste)",
            400,
        )
    ScanService.reorder_scheduled(
        scan_ids
    )
    return success_response(
        "Ordre mis à jour"
    )