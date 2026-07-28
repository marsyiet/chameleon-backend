from app.models.db import get_db


class CorrelationRepository:
    @staticmethod
    def find_by_asset(asset_id: str):
        db = get_db()
        return list(db.correlations.find({
            "$or": [{"fromAssetId": asset_id}, {"toAssetId": asset_id}]
        }))

    @staticmethod
    def find_by_organization(organization_id: str):
        db = get_db()
        return list(db.correlations.find({"organizationId": organization_id}))