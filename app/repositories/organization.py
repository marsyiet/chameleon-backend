from bson import ObjectId

from app.config.database import db


class OrganizationRepository:

    collection = db.organizations

    @classmethod
    def create(
        cls,
        organization
    ):
        result = (
            cls.collection.insert_one(
                organization
            )
        )

        return str(
            result.inserted_id
        )

    @classmethod
    def find_all(
        cls,
        filters,
        page,
        limit
    ):

        skip = (
            page - 1
        ) * limit

        cursor = (
            cls.collection
            .find(filters)
            .skip(skip)
            .limit(limit)
        )

        return list(cursor)

    @classmethod
    def count(
        cls,
        filters
    ):
        return (
            cls.collection.count_documents(
                filters
            )
        )

    @classmethod
    def find_by_id(
        cls,
        organization_id
    ):
        return (
            cls.collection.find_one(
                {
                    "_id": ObjectId(
                        organization_id
                    ),
                    "isDeleted": False,
                }
            )
        )

    @classmethod
    def update(
        cls,
        organization_id,
        data
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    organization_id
                )
            },
            {
                "$set": data
            }
        )

    @classmethod
    def soft_delete(
        cls,
        organization_id,
        data
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    organization_id
                )
            },
            {
                "$set": data
            }
        )