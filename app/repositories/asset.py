from bson import ObjectId

from app.config.database import db


class AssetRepository:

    collection = db.assets

    @classmethod
    def create(
        cls,
        asset
    ):

        result = (
            cls.collection.insert_one(
                asset
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
            .sort(
                "createdAt",
                -1
            )
        )

        return list(
            cursor
        )

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
        asset_id
    ):

        return (
            cls.collection.find_one(
                {
                    "_id": ObjectId(
                        asset_id
                    ),
                    "isDeleted": False,
                }
            )
        )

    @classmethod
    def update(
        cls,
        asset_id,
        data
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    asset_id
                )
            },
            {
                "$set": data
            }
        )

    @classmethod
    def soft_delete(
        cls,
        asset_id,
        data
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    asset_id
                )
            },
            {
                "$set": data
            }
        )