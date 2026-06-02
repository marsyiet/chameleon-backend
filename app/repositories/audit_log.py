from app.config.database import db


class AuditLogRepository:

    collection = (
        db.audit_logs
    )

    @classmethod
    def create(
        cls,
        audit_log
    ):

        result = (
            cls.collection.insert_one(
                audit_log
            )
        )

        return str(
            result.inserted_id
        )
        
    @classmethod
    def find_paginated(
        cls,
        filters,
        page,
        limit,
    ):

        skip = (
            (page - 1)
            * limit
        )

        logs = list(
            cls.collection
            .find(filters)
            .sort(
                "createdAt",
                -1
            )
            .skip(skip)
            .limit(limit)
        )

        total = (
            cls.collection.count_documents(
                filters
            )
        )

        return {
            "logs": logs,
            "page": page,
            "limit": limit,
            "total": total
        }
        
    @classmethod
    def count_by_action(
        cls,
        organization_id
    ):

        return list(
            cls.collection.aggregate(
                [
                    {
                        "$match": {
                            "organizationId":
                                organization_id
                        }
                    },
                    {
                        "$group": {
                            "_id":
                                "$action",

                            "count": {
                                "$sum": 1
                            }
                        }
                    }
                ]
            )
        )