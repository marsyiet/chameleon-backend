from bson import ObjectId

from app.config.database import db


class UserRepository:

    collection = db.users

    @classmethod
    def create(
        cls,
        user
    ):
        result = cls.collection.insert_one(
            user
        )

        return str(
            result.inserted_id
        )

    @classmethod
    def find_by_email(
        cls,
        email
    ):
        return cls.collection.find_one(
            {
                "email": email
            }
        )

    @classmethod
    def find_by_id(
        cls,
        user_id
    ):
        return cls.collection.find_one(
            {
                "_id": ObjectId(
                    user_id
                ),
                "isDeleted": False,
            }
        )

    @classmethod
    def find_all(
        cls,
        filters
    ):
        return list(
            cls.collection.find(
                filters
            )
        )

    @classmethod
    def count(
        cls
    ):
        return cls.collection.count_documents(
            {
                "isDeleted": False
            }
        )

    @classmethod
    def update(
        cls,
        user_id,
        data
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$set": data
            }
        )
        
    @classmethod
    def add_refresh_token(
        cls,
        user_id,
        token
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$push": {
                    "refreshTokens": token
                }
            }
        )
        
    @classmethod
    def remove_refresh_token(
        cls,
        user_id,
        token
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$pull": {
                    "refreshTokens": token
                }
            }
        )
        
    @classmethod
    def find_by_id_and_organization(
        cls,
        user_id,
        organization_id
    ):

        return cls.collection.find_one(
            {
                "_id": ObjectId(
                    user_id
                ),
                "organizationId":
                    organization_id,
                "isDeleted":
                    False,
            }
        )
        
    @classmethod
    def increment_failed_login(
        cls,
        user_id
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$inc": {
                    "failedLoginAttempts": 1
                }
            }
        )


    @classmethod
    def reset_failed_login(
        cls,
        user_id
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$set": {
                    "failedLoginAttempts": 0,
                    "lockedUntil": None
                }
            }
        )


    @classmethod
    def lock_account(
        cls,
        user_id,
        locked_until
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$set": {
                    "lockedUntil":
                        locked_until
                }
            }
        )
        
    @classmethod
    def disable(
        cls,
        user_id
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$set": {
                    "status":
                        "disabled"
                }
            }
        )


    @classmethod
    def enable(
        cls,
        user_id
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$set": {
                    "status":
                        "active"
                }
            }
        )
        
    @classmethod
    def reset_password(
        cls,
        user_id,
        password
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$set": {
                    "password":
                        password,

                    "refreshTokens":
                        []
                }
            }
        )
        
    @classmethod
    def unlock_account(
        cls,
        user_id
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    user_id
                )
            },
            {
                "$set": {
                    "failedLoginAttempts": 0,
                    "lockedUntil": None
                }
            }
        )