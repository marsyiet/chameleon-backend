from flask import Blueprint
from app.controllers.scan import (
    create,
    get_all,
    get_by_id,
    update,
    delete,
    start,
    get_scheduled,
    reorder,
)
scan_bp = Blueprint(
    "scans",
    __name__,
)
scan_bp.post("/")(
    create
)
scan_bp.get("/")(
    get_all
)

# Routes statiques : DOIVENT être déclarées avant "/<scan_id>",
# sinon Flask/Werkzeug peut matcher "scheduled" ou "reorder" comme un scan_id.
scan_bp.get("/scheduled")(
    get_scheduled
)
scan_bp.patch("/reorder")(
    reorder
)

scan_bp.get(
    "/<scan_id>"
)(
    get_by_id
)
scan_bp.patch(
    "/<scan_id>"
)(
    update
)
scan_bp.delete(
    "/<scan_id>"
)(
    delete
)
scan_bp.post("/<scan_id>/start")(start)