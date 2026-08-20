from flask import request
from app.services.change import ChangeService
from app.middlewares.auth import auth_required
from app.middlewares.permissions import permission_required
from app.utils.api_response import success_response
from app.utils.mongo import serialize_documents


@auth_required
@permission_required("scan.read")
def get_all():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    organization_id = request.args.get("organizationId")
    asset_id = request.args.get("assetId")
    scan_id = request.args.get("scanId")
    change_type = request.args.get("type")

    result = ChangeService.get_all(
        page, limit,
        organization_id=organization_id,
        asset_id=asset_id,
        scan_id=scan_id,
        change_type=change_type,
    )
    result["changes"] = serialize_documents(result["changes"])
    return success_response("Changes retrieved", result)