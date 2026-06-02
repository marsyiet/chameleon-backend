from flask import Blueprint

from app.controllers.user import (
    create,
    get_all,
    get_by_id,
    unlock,
    update,
    delete,
    disable,
    enable,
    change_role,
    reset_password,
)


user_bp = Blueprint(
    "users",
    __name__,
)

user_bp.post(
    "/"
)(
    create
)

user_bp.get(
    "/"
)(
    get_all
)

user_bp.get(
    "/<user_id>"
)(
    get_by_id
)

user_bp.put(
    "/<user_id>"
)(
    update
)

user_bp.delete(
    "/<user_id>"
)(
    delete
)

user_bp.patch(
    "/<user_id>/disable"
)(
    disable
)

user_bp.patch(
    "/<user_id>/enable"
)(
    enable
)

user_bp.patch(
    "/<user_id>/role"
)(
    change_role
)

user_bp.post(
    "/<user_id>/reset-password"
)(
    reset_password
)

user_bp.post(
    "/<user_id>/unlock"
)(
    unlock
)