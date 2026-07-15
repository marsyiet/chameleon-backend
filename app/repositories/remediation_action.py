from bson import ObjectId
from datetime import datetime
from app.config.database import db
class RemediationActionRepository:
    collection = db.remediation_actions

    @classmethod
    def create(
        cls,
        action
    ):
        result = (
            cls.collection.insert_one(
                action
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
        action_id
    ):
        return (
            cls.collection.find_one(
                {
                    "_id": ObjectId(
                        action_id
                    )
                }
            )
        )

    # ================================================================
    # Workflow de traçabilité (ENF-03) : proposee -> validee -> appliquee
    # ================================================================
    @classmethod
    def validate(
        cls,
        action_id,
        validated_by
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(action_id)
            },
            {
                "$set": {
                    "status": "validee",
                    "validatedBy": validated_by,
                    "validatedAt": datetime.utcnow(),
                    "updatedAt": datetime.utcnow(),
                }
            }
        )

    @classmethod
    def mark_applied(
        cls,
        action_id
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(action_id)
            },
            {
                "$set": {
                    "status": "appliquee",
                    "appliedAt": datetime.utcnow(),
                    "updatedAt": datetime.utcnow(),
                }
            }
        )

    @classmethod
    def reject(
        cls,
        action_id,
        justification
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(action_id)
            },
            {
                "$set": {
                    "status": "rejetee",
                    "justification": justification,
                    "updatedAt": datetime.utcnow(),
                }
            }
        )

    @classmethod
    def find_pending(
        cls,
        organization_id
    ):
        return list(
            cls.collection.find(
                {
                    "organizationId": organization_id,
                    "status": "proposee",
                }
            )
        )