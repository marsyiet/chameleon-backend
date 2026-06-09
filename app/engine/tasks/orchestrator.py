from datetime import datetime, timezone
from bson import ObjectId
from celery import group
from app.engine.celery_app import celery_app
from app.engine.tasks.masscan_task import scan_cidr
from app.engine.tasks.nmap_task import scan_domain
from app.models.db import get_db
 
 
@celery_app.task(bind=True, name="engine.orchestrator.dispatch_scan")
def dispatch_scan(self, scan_id: str):
    db = get_db()
    scan = db.scans.find_one({"_id": ObjectId(scan_id)})
 
    if not scan:
        raise ValueError(f"Scan {scan_id} introuvable")
 
    # Marquer comme démarré
    db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {
            "status": "running",
            "startedAt": datetime.now(timezone.utc),
            "progress": 0
        }}
    )
 
    targets = scan.get("targets", [])
    total   = len(targets)
 
    for i, target_obj in enumerate(targets):
        target_id  = target_obj["id"]
        target_val = target_obj["target"]
        target_type = target_obj["targetType"]
 
        # Marquer la cible comme en cours
        db.scans.update_one(
            {"_id": ObjectId(scan_id), "targets.id": target_id},
            {"$set": {
                "targets.$.status": "running",
                "targets.$.startedAt": datetime.now(timezone.utc)
            }}
        )
 
        try:
            if target_type == "cidr":
                scan_cidr(scan_id, target_id, target_val)   # synchrone ici
            elif target_type == "domain":
                scan_domain(scan_id, target_id, target_val)
 
            # Marquer la cible comme terminée
            db.scans.update_one(
                {"_id": ObjectId(scan_id), "targets.id": target_id},
                {"$set": {
                    "targets.$.status": "completed",
                    "targets.$.completedAt": datetime.now(timezone.utc)
                }}
            )
 
        except Exception as e:
            import traceback
            print(f"[SCAN ERROR] target={target_val} error={e}")
            print(traceback.format_exc())
            db.scans.update_one(
                {"_id": ObjectId(scan_id), "targets.id": target_id},
                {"$set": {"targets.$.status": "failed"}}
            )
 
        # Mettre à jour la progression globale
        progress = int(((i + 1) / total) * 100)
        db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {"progress": progress}}
        )
 
    # Tout terminé
    db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {
            "status": "completed",
            "completedAt": datetime.now(timezone.utc),
            "progress": 100
        }}
    )
