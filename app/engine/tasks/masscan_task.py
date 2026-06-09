import json
import os
import subprocess
import tempfile
from datetime import datetime

from bson import ObjectId

from app.engine.tasks.nmap_task import fingerprint_host
from app.engine.tasks.enrichment import enrich_host
from app.engine.tasks.zgrab_task import zgrab_http
from app.models.db import get_db


def scan_cidr(scan_id: str, target_id: str, cidr: str):
    """
    Phase 1 : Masscan
    Phase 2 : Nmap
    Phase 3 : Zgrab
    Phase 4 : Enrichissement
    """

    open_hosts = _run_masscan(cidr)

    print("[OPEN HOSTS]")
    print(open_hosts)

    for host_ip, ports in open_hosts.items():

        nmap_data = fingerprint_host(
            host_ip,
            ports,
        )

        http_data = {}

        for service in nmap_data.get("services", []):

            port = service.get("port")

            if port in [80, 443, 3000, 3005, 3006, 5000, 8080, 8443]:
                http_data = zgrab_http(
                    host_ip,
                    port,
                )
                break

        enriched = enrich_host(
            host_ip,
            nmap_data,
        )

        _save_asset(
            scan_id,
            host_ip,
            ports,
            nmap_data,
            enriched,
            http_data,
        )


def _run_masscan(cidr: str) -> dict:
    """
    Retourne :
    {
        "192.168.1.10": [80,443],
        "192.168.1.20": [22]
    }
    """

    out_file = tempfile.mktemp(suffix=".json")

    cmd = [
        "masscan",
        cidr,
        "-p",
        "22,80,443,3000,3005,3006,3306,5000,5432,6379,8080,8443,27017",
        "--rate",
        #"5000"
        "1000",
        "--output-format",
        "json",
        "--output-filename",
        out_file,
        "--wait",
        "1",
    ]

    print("[MASSCAN]", " ".join(cmd))

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )

    print("[MASSCAN RETURN CODE]", result.returncode)

    if result.stderr:
        print("[MASSCAN STDERR]")
        print(result.stderr)

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Masscan failed: {result.stderr}"
        )

    if not os.path.exists(out_file):
        return {}

    hosts = _parse_masscan_output(out_file)

    print("[MASSCAN PARSED]")
    print(hosts)

    return hosts


def _parse_masscan_output(filepath: str) -> dict:

    try:
        with open(filepath, "r") as f:
            raw = f.read().strip()

        if not raw:
            return {}

        raw = raw.rstrip(",")

        if not raw.startswith("["):
            raw = "[" + raw + "]"

        data = json.loads(raw)

        hosts = {}

        for entry in data:

            ip = entry.get("ip")

            ports = entry.get("ports", [])

            for port_info in ports:

                port = port_info.get("port")

                if not ip or not port:
                    continue

                hosts.setdefault(ip, []).append(port)

        return hosts

    finally:
        if os.path.exists(filepath):
            os.unlink(filepath)


def _save_asset(
    scan_id,
    ip,
    ports,
    nmap_data,
    enriched,
    http_data=None,
):
    db = get_db()

    scan = db.scans.find_one({"_id": ObjectId(scan_id)})
    org_id = str(scan["organizationId"]) if scan else ""

    db.assets.update_one(
        {"ip": ip, "scanId": scan_id},
        {"$set": {
            "organizationId": org_id,
            "scanId":         scan_id,
            "ip":             ip,
            "openPorts":      ports,
            "services":       nmap_data.get("services", []),
            "os":             nmap_data.get("os"),
            "geo":            enriched.get("geo", {}),
            "asn":            enriched.get("asn", {}),
            "rdns":           enriched.get("rdns", ""),
            "cves":           enriched.get("cves", []),
            "tags":           enriched.get("tags", []),
            "http":           http_data or {},
            "isDeleted":      False,
            "deletedAt":      None,
            "updatedAt":      datetime.utcnow(),
        }},
        upsert=True,
    )

    db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$inc": {"assetsDiscovered": 1}},
    )