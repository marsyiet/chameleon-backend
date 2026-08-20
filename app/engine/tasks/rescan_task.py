"""
Tâche périodique (Celery Beat) : vérifie les scans dont l'échéance de
relance (2 mois après création) est passée, engendre un nouveau Scan
indépendant avec les mêmes cibles, le lance, et marque l'original comme
déjà relancé pour ne pas le redéclencher au prochain passage.

Le nouveau scan porte lui-même sa propre échéance à 2 mois (posée par
Scan.build), ce qui fait que la chaîne se poursuit indéfiniment sans
intervention supplémentaire.
"""

from datetime import datetime

from app.engine.celery_app import celery_app
from app.engine.tasks.orchestrator import dispatch_scan
from app.models.db import get_db
from app.models.scan import Scan


@celery_app.task(name="engine.tasks.rescan_task.check_due_rescans")
def check_due_rescans():
    db = get_db()
    now = datetime.utcnow()

    due_scans = list(db.scans.find({
        "isDeleted": False,
        "rescanTriggered": False,
        "nextScanAt": {"$lte": now},
    }))

    print(f"[RESCAN] {len(due_scans)} scan(s) arrivé(s) à échéance de relance")

    for scan in due_scans:
        try:
            _trigger_rescan(scan)
        except Exception as e:
            print(f"[RESCAN ERROR] échec de la relance pour {scan.get('_id')} : {e}")


def _trigger_rescan(scan: dict):
    db = get_db()

    # Reconstruit une entrée "targets" au format attendu par Scan.build
    # (sans id/status/timestamps, qui appartiennent à l'exécution passée).
    simple_targets = [
        {"target": t["target"], "targetType": t["targetType"]}
        for t in scan.get("targets", [])
    ]

    new_scan_data = {
        "organizationId": scan["organizationId"],
        "name": scan["name"],
        "description": scan.get("description"),
        "scanType": scan["scanType"],
        "targets": simple_targets,
        "createdBy": scan["createdBy"],
        "targetOrganization": scan.get("targetOrganizationId"),
    }

    new_scan_document = Scan.build(new_scan_data)
    result = db.scans.insert_one(new_scan_document)
    new_scan_id = str(result.inserted_id)

    print(f"[RESCAN] Scan {new_scan_id} engendré automatiquement depuis {scan['_id']}")

    dispatch_scan.delay(new_scan_id)

    db.scans.update_one(
        {"_id": scan["_id"]},
        {"$set": {"rescanTriggered": True, "updatedAt": datetime.utcnow()}},
    )