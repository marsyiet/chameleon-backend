from flask import Blueprint

from app.controllers.asset import (
    create,
    get_all,
    get_by_id,
    update,
    delete,
)

asset_bp = Blueprint(
    "assets",
    __name__,
)

asset_bp.post("/")(
    create
)

asset_bp.get("/")(
    get_all
)

asset_bp.get(
    "/<asset_id>"
)(
    get_by_id
)

asset_bp.patch(
    "/<asset_id>"
)(
    update
)

asset_bp.delete(
    "/<asset_id>"
)(
    delete
)