"""
Compare l'état déjà connu d'un actif à son nouvel état après un scan, et
ne retient que les changements jugés significatifs — pas les fluctuations
mineures (variation infime du score de risque, mise à jour de lastSeenAt,
réordonnancement de listes) qui ne représentent aucune évolution réelle
de l'exposition.
"""

from datetime import datetime

# En-dessous de ce seuil, une variation du score de risque est considérée
# comme du bruit (ex: légère fluctuation EPSS) plutôt qu'un changement réel.
RISK_SCORE_DELTA_THRESHOLD = 1.0


def _service_key(svc: dict) -> tuple:
    return (svc.get("port"), svc.get("protocol"))


def _all_cve_ids(services: list) -> set:
    return {
        cve.get("id")
        for svc in services
        for cve in (svc.get("cves") or [])
        if cve.get("status") == "valid"
    }


def compare_asset_versions(old_asset: dict, new_state: dict) -> list[dict]:
    """
    `old_asset` : document tel qu'il était en base avant ce scan.
    `new_state` : champs recalculés pour ce scan (services, riskScore,
    severity, primaryRoleForDisplay, authenticationSurfaces déjà fusionnés).

    Retourne une liste de changements, chacun avec un type, un résumé
    lisible, et les valeurs avant/après.
    """
    changes = []

    old_services = old_asset.get("services", [])
    new_services = new_state.get("services", [])
    old_keys = {_service_key(s) for s in old_services}
    new_keys = {_service_key(s) for s in new_services}

    for port, protocol in new_keys - old_keys:
        changes.append({
            "type": "service_appeared",
            "summary": f"Nouveau service détecté : {port}/{protocol}",
            "field": "services",
            "newValue": f"{port}/{protocol}",
        })

    for port, protocol in old_keys - new_keys:
        changes.append({
            "type": "service_disappeared",
            "summary": f"Service précédemment détecté absent de ce scan : {port}/{protocol}",
            "field": "services",
            "oldValue": f"{port}/{protocol}",
        })

    old_cves = _all_cve_ids(old_services)
    new_cves = _all_cve_ids(new_services)
    for cve_id in new_cves - old_cves:
        changes.append({
            "type": "new_vulnerability",
            "summary": f"Nouvelle vulnérabilité détectée : {cve_id}",
            "field": "cves",
            "newValue": cve_id,
        })

    old_severity = old_asset.get("severity")
    new_severity = new_state.get("severity")
    if old_severity and new_severity and old_severity != new_severity:
        changes.append({
            "type": "severity_changed",
            "summary": f"Sévérité modifiée : {old_severity} → {new_severity}",
            "field": "severity",
            "oldValue": old_severity,
            "newValue": new_severity,
        })

    old_score = (old_asset.get("riskScore") or {}).get("value")
    new_score = (new_state.get("riskScore") or {}).get("value")
    if old_score is not None and new_score is not None:
        delta = new_score - old_score
        if abs(delta) >= RISK_SCORE_DELTA_THRESHOLD:
            changes.append({
                "type": "risk_score_changed",
                "summary": f"Score de risque : {old_score:.1f} → {new_score:.1f}",
                "field": "riskScore.value",
                "oldValue": old_score,
                "newValue": new_score,
            })

    old_role = old_asset.get("primaryRoleForDisplay")
    new_role = new_state.get("primaryRoleForDisplay")
    if old_role and new_role and old_role != new_role and new_role != "unknown":
        changes.append({
            "type": "role_changed",
            "summary": f"Rôle principal reclassé : {old_role} → {new_role}",
            "field": "primaryRoleForDisplay",
            "oldValue": old_role,
            "newValue": new_role,
        })

    old_auth_count = len(old_asset.get("authenticationSurfaces", []))
    new_auth_count = len(new_state.get("authenticationSurfaces", []))
    if new_auth_count > old_auth_count:
        changes.append({
            "type": "new_authentication_surface",
            "summary": f"Nouvelle(s) surface(s) d'authentification exposée(s) ({old_auth_count} → {new_auth_count})",
            "field": "authenticationSurfaces",
            "oldValue": old_auth_count,
            "newValue": new_auth_count,
        })

    # Certificat TLS : changement d'émetteur, ou bascule vers auto-signé
    old_tls_by_port = {
        s.get("port"): (s.get("tls") or {}) for s in old_services if s.get("tls")
    }
    for svc in new_services:
        new_tls = svc.get("tls")
        if not new_tls:
            continue
        old_tls = old_tls_by_port.get(svc.get("port"))
        if not old_tls:
            continue
        if old_tls.get("issuer") != new_tls.get("issuer"):
            changes.append({
                "type": "tls_issuer_changed",
                "summary": f"Émetteur du certificat TLS modifié sur le port {svc.get('port')} : "
                           f"{old_tls.get('issuer')} → {new_tls.get('issuer')}",
                "field": "services.tls.issuer",
                "oldValue": old_tls.get("issuer"),
                "newValue": new_tls.get("issuer"),
            })
        if not old_tls.get("selfSigned") and new_tls.get("selfSigned"):
            changes.append({
                "type": "tls_downgraded_self_signed",
                "summary": f"Certificat TLS remplacé par un certificat auto-signé sur le port {svc.get('port')}",
                "field": "services.tls.selfSigned",
                "oldValue": False,
                "newValue": True,
            })

    return changes


def record_asset_changes(db, asset_id: str, ip_address: str, organization_id: str,
                          scan_id: str, changes: list[dict]):
    if not changes:
        return
    now = datetime.utcnow()
    documents = [
        {
            **change,
            "assetId": str(asset_id) if asset_id else None,
            "ipAddress": ip_address,
            "organizationId": organization_id,
            "scanId": scan_id,
            "detectedAt": now,
        }
        for change in changes
    ]
    db.asset_changes.insert_many(documents)
    print(f"[CHANGE DETECTION] {len(documents)} changement(s) enregistré(s) pour {ip_address}")