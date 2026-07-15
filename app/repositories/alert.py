from bson import ObjectId
from datetime import datetime
from app.config.database import db
class AlertRepository:
    collection = db.alerts

    @classmethod
    def create(
        cls,
        alert
    ):
        result = (
            cls.collection.insert_one(
                alert
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
        alert_id
    ):
        return (
            cls.collection.find_one(
                {
                    "_id": ObjectId(
                        alert_id
                    )
                }
            )
        )

    # ================================================================
    # Filtre par type — utilisé pour distinguer les vues "Threat Intelligence"
    # (misp_match) et "Alertes & Changements" (le reste) de la sidebar,
    # sans avoir besoin de collections séparées.
    # ================================================================
    @classmethod
    def find_by_type(
        cls,
        organization_id,
        alert_type,
        page,
        limit
    ):
        skip = (
            page - 1
        ) * limit
        cursor = (
            cls.collection.find(
                {
                    "organizationId": organization_id,
                    "type": alert_type,
                }
            )
            .skip(skip)
            .limit(limit)
            .sort("createdAt", -1)
        )
        return list(
            cursor
        )

    @classmethod
    def find_new(
        cls,
        organization_id
    ):
        return list(
            cls.collection.find(
                {
                    "organizationId": organization_id,
                    "status": "nouvelle",
                }
            )
        )

    @classmethod
    def acknowledge(
        cls,
        alert_id,
        acknowledged_by
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(alert_id)
            },
            {
                "$set": {
                    "status": "acquittee",
                    "acknowledgedBy": acknowledged_by,
                    "acknowledgedAt": datetime.utcnow(),
                    "updatedAt": datetime.utcnow(),
                }
            }
        )