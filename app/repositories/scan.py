from bson import ObjectId

from app.config.database import db


class ScanRepository:

    collection = db.scans

    @classmethod
    def create(
        cls,
        scan
    ):
        result = (
            cls.collection.insert_one(
                scan
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
        scan_id
    ):
        return (
            cls.collection.find_one(
                {
                    "_id": ObjectId(
                        scan_id
                    ),
                    "isDeleted": False,
                }
            )
        )
        
    @classmethod
    def update(
        cls,
        scan_id,
        data
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    scan_id
                )
            },
            {
                "$set": data
            }
        )

    @classmethod
    def soft_delete(
        cls,
        scan_id,
        data
    ):

        cls.collection.update_one(
            {
                "_id": ObjectId(
                    scan_id
                )
            },
            {
                "$set": data
            }
        )