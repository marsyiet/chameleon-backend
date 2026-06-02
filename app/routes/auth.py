from flask import Blueprint

from app.controllers.auth import (
    bootstrap,
    login,
    me,
    logout,
    change_password,
)

auth_bp = Blueprint(
    "auth",
    __name__,
)

auth_bp.post(
    "/bootstrap"
)(
    bootstrap
)

auth_bp.post(
    "/login"
)(
    login
)

auth_bp.get(
    "/me"
)(
    me
)

auth_bp.post(
    "/logout"
)(
    logout
)

auth_bp.post(
    "/change-password"
)(
    change_password
)