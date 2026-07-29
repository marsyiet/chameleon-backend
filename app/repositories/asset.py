from bson import ObjectId

from app.config.database import db


class AssetRepository:

    collection = db.assets

    @classmethod
    def create(cls, asset):
        result = cls.collection.insert_one(asset)
        return str(result.inserted_id)

    @classmethod
    def find_all(cls, filters, page, limit):
        skip = (page - 1) * limit
        cursor = (
            cls.collection
            .find(filters)
            .skip(skip)
            .limit(limit)
        )
        return list(cursor)

    @classmethod
    def count(cls, filters):
        return cls.collection.count_documents(filters)

    @classmethod
    def find_by_id(cls, asset_id):
        return cls.collection.find_one({
            "_id": ObjectId(asset_id),
            "isDeleted": False,
        })

    @classmethod
    def find_by_ip_and_organization(cls, ip_address, organization_id):
        """
        Lookup par identité stable de l'actif — (ipAddress, organizationId) —
        cohérent avec la clé d'upsert utilisée par le pipeline de scan
        (masscan_task._save_asset). Utile pour toute logique qui doit
        retrouver un actif sans passer par son _id.
        """
        return cls.collection.find_one({
            "ipAddress": ip_address,
            "organizationId": organization_id,
            "isDeleted": False,
        })

    @classmethod
    def update(cls, asset_id, data):
        cls.collection.update_one(
            {"_id": ObjectId(asset_id)},
            {"$set": data}
        )

    @classmethod
    def soft_delete(cls, asset_id, data):
        cls.collection.update_one(
            {"_id": ObjectId(asset_id)},
            {"$set": data}
        )