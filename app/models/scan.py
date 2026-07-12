from datetime import datetime
from bson import ObjectId


class Scan:
    @staticmethod
    def build(data):
        now = datetime.utcnow()

        scheduled_at = data.get("scheduledAt")
        if isinstance(scheduled_at, str):
            # ex: "2026-07-10T09:00:00.000Z" -> fromisoformat n'accepte pas le "Z"
            scheduled_at = datetime.fromisoformat(
                scheduled_at.replace("Z", "+00:00")
            ).replace(tzinfo=None)

        is_scheduled = bool(scheduled_at) and scheduled_at > now

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
            # pending | scheduled | running | completed | failed | cancelled
            "status": "scheduled" if is_scheduled else "pending",
            "scheduledAt": scheduled_at if is_scheduled else None,
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