from datetime import datetime, timezone
from bson import ObjectId
from celery import group
from app.engine.celery_app import celery_app
from app.engine.tasks.masscan_task import scan_cidr
from app.engine.tasks.nmap_task import scan_domain
from app.engine.tasks.correlation_task import compute_correlations_for_scan
from app.models.db import get_db


@celery_app.task(bind=True, name="engine.orchestrator.dispatch_scan")
def dispatch_scan(self, scan_id: str):
    db = get_db()
    scan = db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise ValueError(f"Scan {scan_id} introuvable")

    organization_id = scan.get("organizationId")

    db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {
            "status": "running",
            "startedAt": datetime.now(timezone.utc),
            "progress": 0
        }}
    )

    targets = scan.get("targets", [])
    total = len(targets)

    for i, target_obj in enumerate(targets):
        target_id = target_obj["id"]
        target_val = target_obj["target"]
        target_type = target_obj["targetType"]
        site_id = target_obj.get("siteId")

        db.scans.update_one(
            {"_id": ObjectId(scan_id), "targets.id": target_id},
            {"$set": {
                "targets.$.status": "running",
                "targets.$.startedAt": datetime.now(timezone.utc)
            }}
        )

        try:
            if target_type == "cidr":
                scan_cidr(scan_id, target_id, target_val, site_id=site_id, organization_id=organization_id)
            elif target_type == "domain":
                scan_domain(scan_id, target_id, target_val, site_id=site_id, organization_id=organization_id)
            elif target_type == "ip":
                scan_cidr(scan_id, target_id, f"{target_val}/32", site_id=site_id, organization_id=organization_id)
            else:
                print(f"[SCAN ERROR] targetType inconnu: {target_type}")

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

        progress = int(((i + 1) / total) * 100)
        db.scans.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {"progress": progress}}
        )

    try:
        compute_correlations_for_scan(scan_id, organization_id)
    except Exception as e:
        import traceback
        print(f"[CORRELATION ERROR] scan_id={scan_id} error={e}")
        print(traceback.format_exc())

    db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {
            "status": "completed",
            "completedAt": datetime.now(timezone.utc),
            "progress": 100
        }}
    )