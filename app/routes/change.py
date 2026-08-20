from flask import Blueprint
from app.controllers.change import get_all

change_bp = Blueprint(
    "changes",
    __name__,
)

change_bp.get("/")(get_all)