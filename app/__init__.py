from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

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
    user_bp
)

from app.routes.audit_log import (
    audit_log_bp
)

from app.routes.audit_log import (
    audit_log_bp
)


load_dotenv()


def create_app():

    app = Flask(__name__)

    CORS(app)

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
        url_prefix="/api/users"
    )
    
    app.register_blueprint(
        audit_log_bp,
        url_prefix="/api/audit-logs"
    )
        
    return app