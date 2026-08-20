from app.models.db import get_db


class ChangeService:
    @staticmethod
    def get_all(page, limit, organization_id=None, asset_id=None, scan_id=None, change_type=None):
        db = get_db()
        query = {}
        if organization_id:
            query["organizationId"] = organization_id
        if asset_id:
            query["assetId"] = asset_id
        if scan_id:
            query["scanId"] = scan_id
        if change_type:
            query["type"] = change_type

        total = db.asset_changes.count_documents(query)
        changes = list(
            db.asset_changes.find(query)
            .sort("detectedAt", -1)
            .skip((page - 1) * limit)
            .limit(limit)
        )
        return {"changes": changes, "total": total, "page": page, "limit": limit}