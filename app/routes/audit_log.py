from flask import Blueprint

from app.controllers.audit_log import (
    get_all
)

audit_log_bp = Blueprint(
    "audit_logs",
    __name__,
)

audit_log_bp.get(
    "/"
)(
    get_all
)