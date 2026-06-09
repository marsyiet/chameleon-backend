import subprocess, json, tempfile, os
from engine.celery_app import celery_app
from config import config
from models.db import get_db
from engine.tasks.nmap_task import fingerprint_host
from engine.tasks.enrichment import enrich_host
 
 
def scan_cidr(scan_id: str, target_id: str, cidr: str):
    """
    Phase 1 : Masscan découvre les ports ouverts sur le CIDR.
    Phase 2 : Pour chaque host découvert → Nmap + Enrichissement.
    """
    open_hosts = _run_masscan(cidr)
 
    for host_ip, ports in open_hosts.items():
        nmap_data    = fingerprint_host(host_ip, ports)
        enriched     = enrich_host(host_ip, nmap_data)
        _save_asset(scan_id, host_ip, ports, nmap_data, enriched)
 
 
def _run_masscan(cidr: str) -> dict:
    """Lance Masscan, retourne {ip: [port1, port2, ...]}"""
    out_file = tempfile.mktemp(suffix=".json")
 
    cmd = [
        "masscan", cidr,
        "-p", "0-65535",
        "--rate", str(config.MASSCAN_RATE),
        "--output-format", "json",
        "--output-filename", out_file,
        "--wait", "3",     # attendre 3s après le scan pour les derniers paquets
    ]
 
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
 
    if result.returncode != 0 and result.returncode != 1:
        raise RuntimeError(f"Masscan failed: {result.stderr}")
 
    if not os.path.exists(out_file):
        return {}
 
    return _parse_masscan_output(out_file)
 
 
def _parse_masscan_output(filepath: str) -> dict:
    """Parse le JSON Masscan → {ip: [ports]}"""
    with open(filepath) as f:
        raw = f.read().strip()
 
    # Masscan génère du JSON non valide (virgule finale)
    raw = raw.rstrip(",").strip()
    if not raw.startswith("["):
        raw = "[" + raw + "]"
 
    data = json.loads(raw)
    hosts = {}
 
    for entry in data:
        ip   = entry.get("ip")
        port = entry.get("ports", [{}])[0].get("port")
        if ip and port:
            hosts.setdefault(ip, []).append(port)
 
    os.unlink(filepath)
    return hosts
 
 
def _save_asset(scan_id, ip, ports, nmap_data, enriched):
    """Upsert d'un asset dans MongoDB Atlas."""
    db = get_db()
    db.assets.update_one(
        {"ip": ip, "scanId": scan_id},
        {"$set": {
            "ip":          ip,
            "scanId":      scan_id,
            "openPorts":   ports,
            "services":    nmap_data.get("services", []),
            "os":          nmap_data.get("os", None),
            "geo":         enriched.get("geo", {}),
            "asn":         enriched.get("asn", {}),
            "rdns":        enriched.get("rdns", ""),
            "cves":        enriched.get("cves", []),
            "tags":        enriched.get("tags", []),
            "updatedAt":   __import__("datetime").datetime.utcnow()
        }},
        upsert=True
    )
 
    # Incrémenter le compteur du scan
    db.scans.update_one(
        {"_id": __import__("bson").ObjectId(scan_id)},
        {"$inc": {"assetsDiscovered": 1}}
    )
