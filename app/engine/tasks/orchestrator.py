from datetime import datetime, timezone
from bson import ObjectId
from celery import group
from app.engine.celery_app import celery_app
from app.engine.tasks.masscan_task import scan_cidr
from app.engine.tasks.nmap_task import scan_domain
from app.engine.tasks.correlation_task import compute_correlations_for_scan
from app.models.db import get_db

# Seuils au-delà desquels une variation du nombre d'actifs découverts est
# jugée significative — en-dessous, la fluctuation est considérée comme du
# bruit normal (un hôte injoignable ponctuellement, par exemple).
ASSET_COUNT_ABSOLUTE_THRESHOLD = 2
ASSET_COUNT_RELATIVE_THRESHOLD = 0.20  # 20 %


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

    final_scan = db.scans.find_one({"_id": ObjectId(scan_id)})
    assets_discovered = final_scan.get("assetsDiscovered", 0)

    try:
        _check_asset_count_variation(db, scan, scan_id, assets_discovered)
    except Exception as e:
        import traceback
        print(f"[ASSET COUNT CHECK ERROR] scan_id={scan_id} error={e}")
        print(traceback.format_exc())

    db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {
            "status": "completed",
            "completedAt": datetime.now(timezone.utc),
            "progress": 100
        }}
    )


def _check_asset_count_variation(db, scan: dict, scan_id: str, assets_discovered: int):
    """
    Compare le nombre d'actifs découverts par ce scan au dernier scan
    précédent portant sur le même périmètre (mêmes cibles), et enregistre
    un changement si la variation dépasse les seuils définis — trop
    d'actifs en plus peut signaler une expansion d'infrastructure non
    documentée (shadow IT), trop peu peut signaler une indisponibilité
    ou un problème de couverture du scan lui-même.
    """
    target_values = sorted(t["target"] for t in scan.get("targets", []))

    previous_scan = db.scans.find_one(
        {
            "_id": {"$ne": ObjectId(scan_id)},
            "organizationId": scan.get("organizationId"),
            "targetOrganizationId": scan.get("targetOrganizationId"),
            "status": "completed",
            "isDeleted": False,
        },
        sort=[("completedAt", -1)],
    )

    if not previous_scan:
        return  # premier scan sur ce périmètre, rien à comparer

    previous_targets = sorted(t["target"] for t in previous_scan.get("targets", []))
    if previous_targets != target_values:
        return  # périmètre différent, comparaison non pertinente

    previous_count = previous_scan.get("assetsDiscovered", 0)
    delta = assets_discovered - previous_count

    if previous_count == 0:
        is_significant = assets_discovered > 0
    else:
        relative_delta = abs(delta) / previous_count
        is_significant = (
            abs(delta) >= ASSET_COUNT_ABSOLUTE_THRESHOLD
            and relative_delta >= ASSET_COUNT_RELATIVE_THRESHOLD
        )

    if not is_significant:
        return

    direction = "en hausse" if delta > 0 else "en baisse"
    change = {
        "type": "asset_count_variation",
        "summary": f"Nombre d'actifs découverts {direction} : {previous_count} → {assets_discovered}",
        "field": "assetsDiscovered",
        "oldValue": previous_count,
        "newValue": assets_discovered,
    }

    record_asset_changes(
        db,
        asset_id=None,
        ip_address=None,
        organization_id=scan.get("targetOrganizationId") or scan.get("organizationId"),
        scan_id=scan_id,
        changes=[change],
    )