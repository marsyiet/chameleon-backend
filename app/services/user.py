import bcrypt

from app.models.user import User

from app.repositories.user import (
    UserRepository,
)

from app.services.audit_log import (
    AuditLogService,
)

from app.utils.exceptions import (
    ValidationException,
)


class UserService:

    @staticmethod
    def create(
        data,
        organization_id,
    ):

        existing_user = (
            UserRepository.find_by_email(
                data["email"].lower()
            )
        )

        if existing_user:

            raise ValidationException(
                "Email already exists",
                409,
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
                    data["role"]
            }
        )

        user_id = (
            UserRepository.create(
                user
            )
        )

        AuditLogService.create(
            action="USER_CREATED",
            resource="user",
            organization_id=organization_id,
            resource_id=user_id,
            details={
                "email":
                    data["email"],

                "role":
                    data["role"]
            }
        )

        return user_id

    @staticmethod
    def get_all(
        organization_id
    ):

        return (
            UserRepository.find_all(
                {
                    "organizationId":
                        organization_id,

                    "isDeleted":
                        False,
                }
            )
        )

    @staticmethod
    def get_by_id(
        user_id,
        organization_id
    ):

        return (
            UserRepository
            .find_by_id_and_organization(
                user_id,
                organization_id
            )
        )

    @staticmethod
    def update(
        user_id,
        organization_id,
        data
    ):

        user = (
            UserRepository
            .find_by_id_and_organization(
                user_id,
                organization_id
            )
        )

        if not user:

            raise ValidationException(
                "User not found",
                404,
            )

        UserRepository.update(
            user_id,
            data
        )

        AuditLogService.create(
            action="USER_UPDATED",
            resource="user",
            organization_id=organization_id,
            resource_id=user_id,
            details=data
        )

    @staticmethod
    def delete(
        user_id,
        organization_id
    ):

        user = (
            UserRepository
            .find_by_id_and_organization(
                user_id,
                organization_id
            )
        )

        if not user:

            raise ValidationException(
                "User not found",
                404,
            )

        UserRepository.update(
            user_id,
            {
                "isDeleted": True
            }
        )

        AuditLogService.create(
            action="USER_DELETED",
            resource="user",
            organization_id=organization_id,
            resource_id=user_id,
        )
        
    @staticmethod
    def disable(
        user_id,
        organization_id
    ):

        user = (
            UserRepository
            .find_by_id_and_organization(
                user_id,
                organization_id
            )
        )

        if not user:

            raise ValidationException(
                "User not found",
                404
            )

        UserRepository.disable(
            user_id
        )

        AuditLogService.create(
            action="USER_DISABLED",
            resource="user",
            organization_id=organization_id,
            resource_id=user_id
        )


    @staticmethod
    def enable(
        user_id,
        organization_id
    ):

        user = (
            UserRepository
            .find_by_id_and_organization(
                user_id,
                organization_id
            )
        )

        if not user:

            raise ValidationException(
                "User not found",
                404
            )

        UserRepository.enable(
            user_id
        )

        AuditLogService.create(
            action="USER_ENABLED",
            resource="user",
            organization_id=organization_id,
            resource_id=user_id
        )
        
    @staticmethod
    def change_role(
        user_id,
        role,
        current_user
    ):

        user = (
            UserRepository
            .find_by_id_and_organization(
                user_id,
                current_user[
                    "organizationId"
                ]
            )
        )

        if not user:

            raise ValidationException(
                "User not found",
                404,
            )

        if str(user["_id"]) == current_user["userId"]:

            raise ValidationException(
                "You cannot change your own role",
                400,
            )

        if user["role"] == "super_admin":

            raise ValidationException(
                "Cannot modify super admin",
                403,
            )

        UserRepository.update(
            user_id,
            {
                "role": role
            }
        )

        AuditLogService.create(
            action="ROLE_CHANGED",
            resource="user",
            organization_id=current_user[
                "organizationId"
            ],
            resource_id=user_id,
            details={
                "oldRole":
                    user["role"],
                "newRole":
                    role
            }
        )
        
    @staticmethod
    def reset_password(
        user_id,
        organization_id,
        password
    ):

        user = (
            UserRepository
            .find_by_id_and_organization(
                user_id,
                organization_id
            )
        )

        if not user:

            raise ValidationException(
                "User not found",
                404,
            )

        hashed_password = bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        )

        UserRepository.reset_password(
            user_id,
            hashed_password.decode()
        )

        AuditLogService.create(
            action="PASSWORD_RESET",
            resource="user",
            organization_id=organization_id,
            resource_id=user_id,
        )
        
    @staticmethod
    def unlock(
        user_id,
        organization_id
    ):

        user = (
            UserRepository
            .find_by_id_and_organization(
                user_id,
                organization_id
            )
        )

        if not user:

            raise ValidationException(
                "User not found",
                404,
            )

        UserRepository.unlock_account(
            user_id
        )

        AuditLogService.create(
            action="USER_UNLOCKED",
            resource="user",
            organization_id=organization_id,
            resource_id=user_id,
        )