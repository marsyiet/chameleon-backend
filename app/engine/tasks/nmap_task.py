import re
import subprocess


def fingerprint_host(host: str, ports: list) -> dict:
    if not ports:
        return {"services": [], "os": None}

    port_str = ",".join(str(p) for p in ports[:50])

    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-sC",
        "--script", "mysql-info,pgsql-brute,mongodb-databases,redis-info",
        "-O",
        "--open",
        "-T4",
        "-p", port_str,
        "--host-timeout", "120s",
        "-oX", "-",
        host,
    ]

    print("[NMAP]", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except Exception as e:
        print("[NMAP EXEC ERROR]", e)
        return {"services": [], "os": None}

    if result.returncode != 0:
        print("[NMAP ERROR]", result.stderr)
        return {"services": [], "os": None}

    return _parse_nmap_xml(result.stdout)


def _parse_nmap_xml(xml_output: str) -> dict:
    try:
        from libnmap.parser import NmapParser
        report = NmapParser.parse_fromstring(xml_output)
    except Exception as e:
        print("[NMAP XML PARSE ERROR]", e)
        return {"services": [], "os": None}

    services = []
    os_info  = None

    for host in report.hosts:
        for svc in host.services:
            product = svc.service_dict.get("product", "")
            version = svc.service_dict.get("version", "")
            banner  = svc.service_dict.get("extrainfo", "")

            # Nettoyer version OpenSSH for_Windows
            version = version.replace("for_Windows_", "")

            # Fallback version depuis scripts NSE si product vide
            if not product and svc.scripts_results:
                for script in svc.scripts_results:
                    output = script.get("output", "")

                    if "MariaDB" in output:
                        product = "MariaDB"
                        match = re.search(r"(\d+\.\d+\.\d+[-\w]*)", output)
                        if match:
                            version = match.group(1)
                        break

                    if "MySQL" in output:
                        product = "MySQL"
                        match = re.search(r"(\d+\.\d+\.\d+[-\w]*)", output)
                        if match:
                            version = match.group(1)
                        break

                    if "PostgreSQL" in output:
                        product = "PostgreSQL"
                        match = re.search(r"(\d+\.\d+)", output)
                        if match:
                            version = match.group(1)
                        break

                    # mongodb-databases : la sortie liste les bases si l'accès
                    # est possible SANS authentification — signal de risque
                    # au moins aussi important que la version elle-même.
                    if "mongod" in output.lower() or "MongoDB" in output:
                        product = "MongoDB"
                        if "ERROR" not in output and "requires authentication" not in output.lower():
                            banner = "accès sans authentification possible"
                        match = re.search(r"version[:\s]+([\d.]+)", output, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                        break

                    # redis-info renvoie généralement "redis_version:X.X.X"
                    if "redis_version" in output:
                        product = "Redis"
                        match = re.search(r"redis_version:\s*([\d.]+)", output)
                        if match:
                            version = match.group(1)
                        break

            services.append({
                "port":     svc.port,
                "protocol": svc.protocol,
                "state":    svc.state,
                "service":  svc.service,
                "product":  product,
                "version":  version,
                "banner":   banner,
            })

        try:
            matches = host.os_match_probabilities()
            if matches:
                os_info = matches[0].name
        except Exception:
            pass

    return {"services": services, "os": os_info}


def scan_domain(scan_id: str, target_id: str, domain: str, site_id: str = None):
    import socket
    from app.engine.tasks.masscan_task import _process_host

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"[DNS ERROR] {domain}")
        return

    common_ports = [
        21, 22, 23, 25, 80, 110, 143, 161, 443,
        3000, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
    ]

    # Réutilise exactement le même traitement que scan_cidr (nmap + zgrab http/tls
    # + favicon + crawler + scoring) au lieu de dupliquer une version incomplète —
    # c'est ce qui manquait avant (zgrab n'était jamais appelé ici).
    _process_host(
        scan_id, ip, common_ports,
        target_type="domain", domain=domain, site_id=site_id,
    )