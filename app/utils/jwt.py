import jwt

from datetime import (
    datetime,
    timedelta,
)

from os import getenv


def generate_access_token(
    payload
):

    payload["type"] = "access"

    payload["iat"] = datetime.utcnow()

    payload["exp"] = (
        datetime.utcnow()
        + timedelta(
            minutes=int(
                getenv(
                    "JWT_ACCESS_EXPIRE"
                )
            )
        )
    )

    return jwt.encode(
        payload,
        getenv(
            "JWT_SECRET"
        ),
        algorithm="HS256"
    )


def generate_refresh_token(
    payload
):

    payload["type"] = "refresh"

    payload["iat"] = datetime.utcnow()

    payload["exp"] = (
        datetime.utcnow()
        + timedelta(
            days=int(
                getenv(
                    "JWT_REFRESH_EXPIRE"
                )
            )
        )
    )

    return jwt.encode(
        payload,
        getenv(
            "JWT_SECRET"
        ),
        algorithm="HS256"
    )


def verify_token(
    token
):

    return jwt.decode(
        token,
        getenv(
            "JWT_SECRET"
        ),
        algorithms=[
            "HS256"
        ]
    )