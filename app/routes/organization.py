from flask import Blueprint
from app.controllers.organization import (
    create,
    get_all,
    get_by_id,
    get_map_points,
    get_assets,
    get_scans,
    get_stats,
    update,
    patch,
    delete,
)

organization_bp = Blueprint(
    "organizations",
    __name__,
)

organization_bp.post("/")(
    create
)
organization_bp.get("/")(
    get_all
)
# Doit être déclarée AVANT "/<organization_id>", sinon Flask route
# "/map" vers get_by_id en traitant "map" comme un organization_id.
organization_bp.get("/map")(
    get_map_points
)
organization_bp.get(
    "/<organization_id>"
)(
    get_by_id
)
organization_bp.get(
    "/<organization_id>/assets"
)(
    get_assets
)
organization_bp.get(
    "/<organization_id>/scans"
)(
    get_scans
)
organization_bp.get(
    "/<organization_id>/stats"
)(
    get_stats
)
organization_bp.put(
    "/<organization_id>"
)(
    update
)
organization_bp.patch(
    "/<organization_id>"
)(
    patch
)
organization_bp.delete(
    "/<organization_id>"
)(
    delete
)