from datetime import datetime


class User:

    @staticmethod
    def build(data):

        now = datetime.utcnow()

        return {
            "organizationId": data["organizationId"],

            "firstName": data["firstName"].strip(),
            "lastName": data["lastName"].strip(),

            "email": data["email"].lower().strip(),

            "password": data["password"],

            "role": data["role"],

            "status": "active",

            "twoFactorEnabled": False,
            "twoFactorSecret": None,

            "lastLoginAt": None,

            "failedLoginAttempts": 0,

            "lockedUntil": None,

            "passwordChangedAt": None,

            "passwordChangedAt": None,
            
            "refreshTokens": [],

            "isDeleted": False,
            "deletedAt": None,

            "createdAt": now,
            "updatedAt": now,
        }