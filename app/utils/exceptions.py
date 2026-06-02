class AppException(Exception):

    def __init__(
        self,
        message,
        status_code=400,
    ):
        self.message = message
        self.status_code = status_code

        super().__init__(message)


class ValidationException(
    AppException
):
    pass


class NotFoundException(
    AppException
):
    pass


class UnauthorizedException(
    AppException
):
    pass