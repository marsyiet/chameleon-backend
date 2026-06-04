from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
import os

from app.middlewares.error_handler import (
    register_error_handlers,
)

from app.routes.organization import (
    organization_bp,
)

from app.routes.auth import (
    auth_bp,
)

from app.routes.user import (
    user_bp,
)

from app.routes.audit_log import (
    audit_log_bp,
)

from app.routes.scan import (
    scan_bp,
)

from app.routes.asset import (
    asset_bp,
)

load_dotenv()


def create_app():

    app = Flask(__name__)

    allowed_origins = [
        origin.strip()
        for origin in os.getenv(
            "FRONTEND_URLS",
            ""
        ).split(",")
        if origin.strip()
    ]
    
    print(allowed_origins)

    CORS(
    app,
        supports_credentials=True,
        origins=[
            "http://localhost:3005",
            "http://localhost:3006",
        ],
    )

    register_error_handlers(app)

    app.register_blueprint(
        organization_bp,
        url_prefix="/api/organizations",
    )

    app.register_blueprint(
        auth_bp,
        url_prefix="/api/auth",
    )

    app.register_blueprint(
        user_bp,
        url_prefix="/api/users",
    )

    app.register_blueprint(
        audit_log_bp,
        url_prefix="/api/audit-logs",
    )
    
    app.register_blueprint(
        scan_bp,
        url_prefix="/api/scans",
    )
    
    app.register_blueprint(
        asset_bp,
        url_prefix="/api/assets",
    )
            

    return app