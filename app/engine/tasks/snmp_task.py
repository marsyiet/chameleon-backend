"""
Requête SNMP publique (community "public") — protocole gratuit et non
authentifié dans sa configuration par défaut sur énormément d'équipements
réseau. Une seule requête GET sur les OID standards suffit à obtenir des
informations qu'aucune autre source ne donne aussi directement.
"""

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"


def query_snmp(ip: str, community: str = "public", timeout: int = 3) -> dict:
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
    except ImportError:
        print("[SNMP] pysnmp non installé — pip install pysnmp --break-system-packages")
        return {}

    result = {
        "sysDescr": None, "sysName": None, "uptimeSeconds": None,
        "enterpriseName": None, "versionsSupported": [], "communityUsed": None,
    }

    try:
        for oid, key in [(OID_SYS_DESCR, "sysDescr"), (OID_SYS_NAME, "sysName"), (OID_SYS_UPTIME, "uptimeSeconds")]:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
            error_indication, error_status, _, var_binds = next(iterator)
            if error_indication or error_status:
                continue
            for var in var_binds:
                value = str(var[1])
                if key == "uptimeSeconds":
                    try:
                        result[key] = int(value) // 100  # TimeTicks en centièmes de seconde
                    except ValueError:
                        pass
                else:
                    result[key] = value

        if result["sysDescr"]:
            result["communityUsed"] = community
            if "mikrotik" in result["sysDescr"].lower() or "routeros" in result["sysDescr"].lower():
                result["enterpriseName"] = "MikroTik"

        return result
    except Exception as e:
        print("[SNMP ERROR]", ip, e)
        return {}