from datetime import datetime, timedelta
from bson import ObjectId
from app.models.db import get_db

# Intervalle de relance automatique fixe — pas de configuration par
# utilisateur pour l'instant, un seul comportement pour tous les scans.
RESCAN_INTERVAL_DAYS = 60  # ~2 mois


class Scan:
    @staticmethod
    def build(data):
        now = datetime.utcnow()
        scheduled_at = data.get("scheduledAt")
        if isinstance(scheduled_at, str):
            scheduled_at = datetime.fromisoformat(
                scheduled_at.replace("Z", "+00:00")
            )
        if isinstance(scheduled_at, datetime) and scheduled_at.tzinfo is not None:
            from datetime import timezone
            scheduled_at = scheduled_at.astimezone(timezone.utc).replace(tzinfo=None)
        is_scheduled = bool(scheduled_at) and scheduled_at > now
        # targetOrganization est désormais un vrai organizationId (sélectionné
        # parmi les organisations existantes) — on résout son nom une seule
        # fois ici, à la création du scan, plutôt que de le refaire à chaque
        # actif découvert dans masscan_task.py.
        target_organization_id = data.get("targetOrganization")
        target_organization_name = None
        if target_organization_id:
            db = get_db()
            org = db.organizations.find_one({"_id": ObjectId(target_organization_id)})
            target_organization_name = org["name"] if org else None
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
            # Organisation-cible du scan (structure auditée) — id + nom
            # résolu. Distinct de "organizationId" ci-dessus (l'organisation
            # ANTIC/utilisateur propriétaire du scan).
            "targetOrganizationId": target_organization_id,
            "targetOrganizationName": target_organization_name,

            # ---- Relance automatique ----
            # Tout scan se relance automatiquement 2 mois après sa création,
            # sans configuration possible pour l'instant. rescanTriggered
            # évite qu'un même scan ne déclenche sa relance plusieurs fois
            # (la tâche périodique tourne toutes les heures, bien plus
            # souvent que l'échéance elle-même).
            "nextScanAt": now + timedelta(days=RESCAN_INTERVAL_DAYS),
            "rescanTriggered": False,

            "isDeleted": False,
            "deletedAt": None,
            "createdAt": now,
            "updatedAt": now,
        }