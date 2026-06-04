import bcrypt

from app.models.user import User
from app.models.organization import Organization

from app.repositories.user import (
    UserRepository
)

from app.repositories.organization import (
    OrganizationRepository
)

from app.utils.jwt import (
    generate_access_token,
    generate_refresh_token,
    verify_token,
)

from app.utils.exceptions import (
    ValidationException,
    UnauthorizedException,
)

from app.services.audit_log import (
    AuditLogService
)

from datetime import (
    datetime,
    timedelta,
)


class AuthService:

    @staticmethod
    def bootstrap(data):

        if UserRepository.count() > 0:

            raise ValidationException(
                "Platform already initialized",
                409,
            )

        organization = Organization.build(
            {
                "name": data[
                    "organizationName"
                ]
            }
        )

        organization_id = (
            OrganizationRepository.create(
                organization
            )
        )

        password = bcrypt.hashpw(
            data["password"].encode(),
            bcrypt.gensalt()
        )

        user = User.build(
            {
                "organizationId":
                    organization_id,

                "firstName":
                    data["firstName"],

                "lastName":
                    data["lastName"],

                "email":
                    data["email"],

                "password":
                    password.decode(),

                "role":
                    "super_admin",
            }
        )

        user_id = (
            UserRepository.create(
                user
            )
        )
        
        AuditLogService.create(
            action="PLATFORM_INITIALIZED",
            resource="auth",
            user_id=user_id,
            organization_id=organization_id
        )

        return {
            "organizationId":
                organization_id,

            "userId":
                user_id,
        }

    @staticmethod
    def login(
        email,
        password,
    ):

        user = (
            UserRepository.find_by_email(
                email.lower()
            )
        )

        if not user:

            raise UnauthorizedException(
                "Invalid credentials",
                401,
            )

        # Déverrouillage automatique si la durée est expirée
        if user.get("lockedUntil"):

            if (
                user["lockedUntil"]
                <= datetime.utcnow()
            ):
                UserRepository.update(
                    str(user["_id"]),
                    {
                        "lockedUntil": None,
                        "failedLoginAttempts": 0,
                    },
                )

                user = (
                    UserRepository.find_by_id(
                        str(user["_id"])
                    )
                )

            else:

                raise UnauthorizedException(
                    f"Account locked until: {user['lockedUntil'].isoformat()}",
                    423,
                )

        valid = bcrypt.checkpw(
            password.encode(),
            user["password"].encode()
        )

        if not valid:

            UserRepository.increment_failed_login(
                str(user["_id"])
            )

            refreshed_user = (
                UserRepository.find_by_id(
                    str(user["_id"])
                )
            )

            if (
                refreshed_user[
                    "failedLoginAttempts"
                ]
                >= 5
            ):

                lock_until = (
                    datetime.utcnow()
                    + timedelta(minutes=1)
                )

                UserRepository.lock_account(
                    str(user["_id"]),
                    lock_until
                )

                AuditLogService.create(
                    action="ACCOUNT_LOCKED",
                    resource="auth",
                    user_id=str(
                        user["_id"]
                    ),
                    organization_id=user[
                        "organizationId"
                    ]
                )

                raise UnauthorizedException(
                    f"Account locked until: {lock_until.isoformat()}",
                    423,
                )

            raise UnauthorizedException(
                "Invalid credentials",
                401,
            )

        UserRepository.reset_failed_login(
            str(user["_id"])
        )

        access_token = (
            generate_access_token(
                {
                    "userId":
                        str(user["_id"]),
                    "organizationId":
                        user["organizationId"],
                    "role":
                        user["role"],
                }
            )
        )

        refresh_token = (
            generate_refresh_token(
                {
                    "userId":
                        str(user["_id"])
                }
            )
        )

        UserRepository.add_refresh_token(
            str(user["_id"]),
            refresh_token,
        )

        AuditLogService.create(
            action="LOGIN",
            resource="auth",
            user_id=str(
                user["_id"]
            ),
            organization_id=user[
                "organizationId"
            ]
        )

        return {
            "accessToken":
                access_token,
            "refreshToken":
                refresh_token,
        }

    @staticmethod
    def refresh(
        refresh_token
    ):

        payload = verify_token(
            refresh_token
        )

        if payload[
            "type"
        ] != "refresh":

            raise UnauthorizedException(
                "Invalid token",
                401,
            )

        user = (
            UserRepository.find_by_id(
                payload[
                    "userId"
                ]
            )
        )

        if not user:

            raise UnauthorizedException(
                "User not found",
                401,
            )

        if refresh_token not in user.get(
            "refreshTokens",
            [],
        ):

            raise UnauthorizedException(
                "Invalid refresh token",
                401,
            )

        access_token = (
            generate_access_token(
                {
                    "userId":
                        str(
                            user["_id"]
                        ),

                    "organizationId":
                        user[
                            "organizationId"
                        ],

                    "role":
                        user[
                            "role"
                        ]
                }
            )
        )

        return {
            "accessToken":
                access_token
        }
        
    @staticmethod
    def logout(
        refresh_token
    ):

        payload = verify_token(
            refresh_token
        )

        if payload["type"] != "refresh":

            raise UnauthorizedException(
                "Invalid token",
                401,
            )

        UserRepository.remove_refresh_token(
            payload["userId"],
            refresh_token
        )

        return True
    
    @staticmethod
    def change_password(
        user_id,
        current_password,
        new_password
    ):

        user = (
            UserRepository.find_by_id(
                user_id
            )
        )

        if not user:

            raise UnauthorizedException(
                "User not found",
                404,
            )

        valid = bcrypt.checkpw(
            current_password.encode(),
            user[
                "password"
            ].encode()
        )

        if not valid:

            raise UnauthorizedException(
                "Invalid credentials",
                401,
            )

        if user["status"] != "active":

            raise UnauthorizedException(
                "Account disabled",
                403,
            )

        hashed_password = bcrypt.hashpw(
            new_password.encode(),
            bcrypt.gensalt()
        )

        UserRepository.update(
            user_id,
            {
                "password":
                    hashed_password.decode(),

                "passwordChangedAt":
                    datetime.utcnow(),

                "refreshTokens":
                    []
            }
        )

        AuditLogService.create(
            action="PASSWORD_CHANGED",
            resource="auth",
            user_id=user_id,
            organization_id=user[
                "organizationId"
            ]
        )

        return True