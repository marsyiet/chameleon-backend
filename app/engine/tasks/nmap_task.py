import subprocess, json
from engine.celery_app import celery_app
 
 
def fingerprint_host(host: str, ports: list) -> dict:
    """Nmap sur les ports déjà découverts par Masscan."""
    if not ports:
        return {"services": [], "os": None}
 
    port_str = ",".join(str(p) for p in ports[:50])  # max 50 ports
 
    cmd = [
        "nmap",
        "-sV",              # détection de version de service
        "-sC",              # scripts par défaut
        "-O",               # détection OS (nécessite root)
        "--open",
        "-p", port_str,
        "-T4",              # timing agressif (T1=furtif, T5=insane)
        "--host-timeout", "120s",
        "-oX", "-",         # XML sur stdout
        host
    ]
 
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
 
    if result.returncode != 0:
        return {"services": [], "os": None}
 
    return _parse_nmap_xml(result.stdout)
 
 
def _parse_nmap_xml(xml_output: str) -> dict:
    """Parse le XML Nmap avec python-libnmap."""
    from libnmap.parser import NmapParser
 
    try:
        report = NmapParser.parse_fromstring(xml_output)
    except Exception:
        return {"services": [], "os": None}
 
    services = []
    os_info  = None
 
    for host in report.hosts:
        for svc in host.services:
            services.append({
                "port":     svc.port,
                "protocol": svc.protocol,
                "state":    svc.state,
                "service":  svc.service,
                "product":  svc.service_dict.get("product", ""),
                "version":  svc.service_dict.get("version", ""),
                "banner":   svc.service_dict.get("extrainfo", ""),
            })
 
        if host.os_match_probabilities():
            os_info = host.os_match_probabilities()[0].name
 
    return {"services": services, "os": os_info}
 
 
def scan_domain(scan_id: str, target_id: str, domain: str):
    """Pour un domaine : résolution DNS d'abord, puis scan."""
    import socket
    from engine.tasks.enrichment import enrich_host
    from engine.tasks.masscan_task import _save_asset
 
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return
 
    # Scan rapide des ports courants pour un domaine
    common_ports = [21, 22, 25, 80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 27017]
    nmap_data    = fingerprint_host(ip, common_ports)
    enriched     = enrich_host(ip, nmap_data)
    _save_asset(scan_id, ip, common_ports, nmap_data, enriched)
