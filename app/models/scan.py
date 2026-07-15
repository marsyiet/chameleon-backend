from datetime import datetime, timezone
from bson import ObjectId


class Scan:
    @staticmethod
    def build(data):
        now = datetime.utcnow()

        scheduled_at = data.get("scheduledAt")

        # Cas 1 : marshmallow a déjà converti en datetime (timezone-aware si "Z"/offset présent)
        if isinstance(scheduled_at, str):
            scheduled_at = datetime.fromisoformat(
                scheduled_at.replace("Z", "+00:00")
            )

        if scheduled_at is not None and scheduled_at.tzinfo is not None:
            # On uniformise en UTC naive pour rester comparable à datetime.utcnow()
            # et cohérent avec le reste du document (createdAt, updatedAt en naive UTC).
            scheduled_at = scheduled_at.astimezone(timezone.utc).replace(tzinfo=None)

        is_scheduled = bool(scheduled_at) and scheduled_at > now

        return {
            "organizationId": data["organizationId"],
            # Structure auditée par ce scan (ex: "MINFI") — distincte de
            # organizationId ci-dessus, qui reste le compte ANTIC/CIRT créateur
            # du scan. C'est CE champ qui se propage aux actifs découverts,
            # pas organizationId (chapitre 2, §2.1.4 — carte organisationnelle).
            "targetOrganization": data.get("targetOrganization"),
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
                    "siteId": target.get("siteId"),
                    "status": "pending",
                    "startedAt": None,
                    "completedAt": None,
                }
                for target in data["targets"]
            ],
            # pending | scheduled | running | completed | failed | cancelled
            "status": "scheduled" if is_scheduled else "pending",
            "scheduledAt": scheduled_at if is_scheduled else None,
            "priority": 0,
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