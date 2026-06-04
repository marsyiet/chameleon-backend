from flask import Blueprint

from app.controllers.scan import (
    create,
    get_all,
    get_by_id,
    update,
    delete,
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