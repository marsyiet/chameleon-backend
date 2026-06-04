from datetime import datetime
from bson import ObjectId



class Scan:

    @staticmethod
    def build(data):

        now = datetime.utcnow()

        return {
            "organizationId": data["organizationId"],

            "name": data["name"].strip(),

            "description": data.get(
                "description"
            ),

            # network | web | full
            "scanType": data["scanType"],

            "targets": [
                {
                    "id": str(ObjectId()),
                    "target": target["target"],
                    "targetType": target["targetType"],
                    "status": "pending",
                    "startedAt": None,
                    "completedAt": None,
                }
                for target in data["targets"]
            ],

            # pending | running | completed | failed | cancelled
            "status": "pending",

            # 0 -> 100
            "progress": 0,
            
            "assetsDiscovered": 0,

            "error": None,

            "startedAt": None,

            "completedAt": None,

            "createdBy": data["createdBy"],

            "isDeleted": False,

            "deletedAt": None,

            "createdAt": now,

            "updatedAt": now,
        }