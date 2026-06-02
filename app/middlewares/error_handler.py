import traceback

from app.utils.api_response import (
    error_response,
)

from app.utils.exceptions import (
    AppException,
)


def register_error_handlers(app):

    @app.errorhandler(
        AppException
    )
    def handle_app_exception(error):

        return error_response(
            error.message,
            status_code=error.status_code,
        )

    @app.errorhandler(Exception)
    def handle_exception(error):

        traceback.print_exc()

        return error_response(
            "Internal Server Error",
            status_code=500,
        )