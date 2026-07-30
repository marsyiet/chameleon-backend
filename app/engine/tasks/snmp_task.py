"""
Requête SNMP publique (community "public") via snmpget (net-snmp) en
ligne de commande — remplace pysnmp qui est cassé en v7 (API async-only,
imports brisés).

Une seule requête GET sur les OID standards suffit à obtenir des
informations qu'aucune autre source ne donne aussi directement :
modèle exact, nom configuré, uptime.
"""

import re
import subprocess

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"


def query_snmp(ip: str, community: str = "public", timeout: int = 5) -> dict:
    result = {
        "sysDescr": None, "sysName": None, "uptimeSeconds": None,
        "enterpriseName": None, "versionsSupported": [], "communityUsed": None,
    }

    try:
        cmd = [
            "snmpget", "-v2c", "-c", community,
            "-t", str(timeout), "-r", "1",
            "-OQv",
            ip,
            OID_SYS_DESCR, OID_SYS_NAME, OID_SYS_UPTIME,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)

        if proc.returncode != 0:
            print(f"[SNMP ERROR] snmpget retourne {proc.returncode}: {proc.stderr.strip()}")
            return {}

        lines = proc.stdout.strip().splitlines()
        if len(lines) >= 1 and lines[0].strip():
            result["sysDescr"] = lines[0].strip().strip('"')
        if len(lines) >= 2 and lines[1].strip():
            result["sysName"] = lines[1].strip().strip('"')
        if len(lines) >= 3:
            uptime_match = re.search(r"\((\d+)\)", lines[2])
            if uptime_match:
                result["uptimeSeconds"] = int(uptime_match.group(1)) // 100

        if result["sysDescr"]:
            result["communityUsed"] = community
            descr_lower = result["sysDescr"].lower()
            if "mikrotik" in descr_lower or "routeros" in descr_lower:
                result["enterpriseName"] = "MikroTik"
            elif "cisco" in descr_lower:
                result["enterpriseName"] = "Cisco"
            elif "huawei" in descr_lower:
                result["enterpriseName"] = "Huawei"
            elif "fortinet" in descr_lower or "fortigate" in descr_lower:
                result["enterpriseName"] = "Fortinet"
            elif "juniper" in descr_lower or "junos" in descr_lower:
                result["enterpriseName"] = "Juniper"
            elif "ubiquiti" in descr_lower or "unifi" in descr_lower or "edgeos" in descr_lower:
                result["enterpriseName"] = "Ubiquiti"
            elif "zte" in descr_lower:
                result["enterpriseName"] = "ZTE"

        return result

    except Exception as e:
        print(f"[SNMP ERROR] {ip}: {e}")
        return {}