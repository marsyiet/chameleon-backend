import re
import socket
import time
import random
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
        "--host-timeout", "240s",
        "-oX", "-",
        host,
    ]

    print("[NMAP]", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except Exception as e:
        print("[NMAP EXEC ERROR]", e)
        return {"services": [], "os": None}

    if result.returncode != 0:
        print("[NMAP ERROR]", result.stderr)
        return {"services": [], "os": None}

    print("[NMAP RAW XML LENGTH]", len(result.stdout))

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

            version = version.replace("for_Windows_", "")

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

                    if "mongod" in output.lower() or "MongoDB" in output:
                        product = "MongoDB"
                        if "ERROR" not in output and "requires authentication" not in output.lower():
                            banner = "accès sans authentification possible"
                        match = re.search(r"version[:\s]+([\d.]+)", output, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                        break

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


def scan_domain(scan_id: str, target_id: str, domain: str, site_id: str = None, organization_id: str = None):
    from app.engine.tasks.masscan_task import (
        _process_host, _run_masscan, _filter_suspicious_ports,
        DEFAULT_PORTS, UDP_PORTS,
    )
    from app.engine.tasks.enrichment import (
        discover_subdomains_ct, resolve_dns_records,
        test_zone_transfer, get_whois_domain,
    )

    dns_records = resolve_dns_records(domain)
    subdomains = discover_subdomains_ct(domain)
    zone_transfer_vulnerable = test_zone_transfer(domain, dns_records.get("ns", []))
    dns_records["zoneTransferVulnerable"] = zone_transfer_vulnerable
    whois_domain = get_whois_domain(domain)

    print(f"[SUBDOMAINS] {len(subdomains)} découverts pour {domain}")
    if zone_transfer_vulnerable:
        print(f"[ZONE TRANSFER] {domain} : AU MOINS UN nameserver accepte l'AXFR — configuration à risque")

    all_hostnames = [domain] + subdomains
    ip_to_hostnames = {}

    for hostname in all_hostnames:
        try:
            ip = socket.gethostbyname(hostname)
            ip_to_hostnames.setdefault(ip, []).append(hostname)
        except socket.gaierror:
            continue

    if not ip_to_hostnames:
        print(f"[DNS ERROR] Impossible de résoudre {domain} ni ses sous-domaines")
        return

    consecutive_failures = 0
    circuit_breaker_threshold = 3
    circuit_breaker_cooldown = 30
    total_tcp_ports = len(DEFAULT_PORTS.split(","))

    for ip, hostnames in ip_to_hostnames.items():
        time.sleep(random.uniform(0.3, 1.2))

        primary_hostname = hostnames[0]
        cidr = f"{ip}/32"

        try:
            tcp_hosts = _run_masscan(cidr, DEFAULT_PORTS, udp=False)
            udp_hosts = _run_masscan(cidr, UDP_PORTS, udp=True)

            raw_tcp_ports = tcp_hosts.get(ip, [])
            filtered_tcp_ports = _filter_suspicious_ports(ip, raw_tcp_ports, total_tcp_ports)

            ports = {
                "tcp": filtered_tcp_ports,
                "udp": udp_hosts.get(ip, []),
            }

            if not ports["tcp"] and not ports["udp"]:
                print(f"[NO OPEN PORT] {ip} ({primary_hostname}) — aucun port ouvert détecté")
                continue

            _process_host(
                scan_id, ip, ports,
                target_type="domain", domain=primary_hostname, site_id=site_id,
                organization_id=organization_id,
                dns_data=dns_records if primary_hostname == domain else None,
                subdomains_discovered=subdomains if primary_hostname == domain else None,
                whois_domain=whois_domain if primary_hostname == domain else None,
                all_hostnames_for_ip=hostnames,
            )
            consecutive_failures = 0
        except Exception as e:
            print(f"[HOST ERROR] {ip} ({primary_hostname}) -> {e}")
            consecutive_failures += 1
            if consecutive_failures >= circuit_breaker_threshold:
                print(f"[CIRCUIT BREAKER] pause de {circuit_breaker_cooldown}s")
                time.sleep(circuit_breaker_cooldown)
                consecutive_failures = 0