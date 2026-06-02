from marshmallow import (
    Schema,
    fields,
    validate,
)


class CreateUserSchema(
    Schema
):

    firstName = fields.String(
        required=True
    )

    lastName = fields.String(
        required=True
    )

    email = fields.Email(
        required=True
    )

    password = fields.String(
        required=True,
        validate=validate.Length(
            min=8
        )
    )

    role = fields.String(
        required=True,
        validate=validate.OneOf(
            [
                "admin",
                "analyst",
                "viewer",
            ]
        )
    )


class UpdateUserSchema(
    Schema
):

    firstName = fields.String()

    lastName = fields.String()

    role = fields.String(
        validate=validate.OneOf(
            [
                "admin",
                "analyst",
                "viewer",
            ]
        )
    )

    status = fields.String(
        validate=validate.OneOf(
            [
                "active",
                "disabled",
            ]
        )
    )
    
class ChangeRoleSchema(
    Schema
):

    role = fields.String(
        required=True,
        validate=validate.OneOf(
            [
                "admin",
                "analyst",
                "viewer",
            ]
        )
    )
    
class ResetPasswordSchema(
    Schema
):

    password = fields.String(
        required=True,
        validate=validate.Length(
            min=8
        )
    )