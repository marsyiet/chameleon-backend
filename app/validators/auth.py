from marshmallow import (
    Schema,
    fields,
    validate,
)


class BootstrapSchema(
    Schema
):

    organizationName = (
        fields.String(
            required=True
        )
    )

    firstName = (
        fields.String(
            required=True
        )
    )

    lastName = (
        fields.String(
            required=True
        )
    )

    email = (
        fields.Email(
            required=True
        )
    )

    password = (
        fields.String(
            required=True,
            validate=validate.Length(
                min=8
            ),
        )
    )


class LoginSchema(
    Schema
):

    email = fields.Email(
        required=True
    )

    password = fields.String(
        required=True
    )
    

class RefreshSchema(
    Schema
):

    refreshToken = (
        fields.String(
            required=True
        )
    )
    
    
class LogoutSchema(
    Schema
):

    refreshToken = (
        fields.String(
            required=True
        )
    )
    
class ChangePasswordSchema(
    Schema
):

    currentPassword = (
        fields.String(
            required=True
        )
    )

    newPassword = (
        fields.String(
            required=True,
            validate=validate.Length(
                min=8
            )
        )
    )