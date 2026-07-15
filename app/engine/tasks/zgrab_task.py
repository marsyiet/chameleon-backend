import base64
import json
import subprocess

import requests


def zgrab_http(target: str, port: int) -> dict:
    """
    `target` : hostname si connu (scan organisationnel), sinon IP (scan CIDR).
    Piper un hostname à zgrab2 lui fait envoyer le bon Host header
    automatiquement — c'est ce qui manquait avant (on pipait toujours l'IP,
    donc sur un hébergeur mutualisé comme Vercel on tombait sur le vhost
    par défaut, pas le vrai site).
    """
    try:
        cmd = [
            "zgrab2",
            "http",
            "--port", str(port),
            "--timeout", "10s",
            "--follow-location",
        ]
        result = subprocess.run(
            cmd, input=target, text=True, capture_output=True, timeout=20,
        )
        if result.returncode != 0:
            return {}
        lines = result.stdout.strip().splitlines()
        if not lines:
            return {}
        data = json.loads(lines[0])
        http_result = data.get("data", {}).get("http", {}).get("result", {})
        response = http_result.get("response", {})

        return {
            "title": http_result.get("title"),
            "statusCode": response.get("status_code"),
            "server": (response.get("headers", {}).get("server", [""]))[0],
            "headers": response.get("headers", {}),
            "redirectChain": [
                r.get("url", "") for r in http_result.get("redirect_response_chain", [])
            ],
        }
    except Exception as e:
        print("[ZGRAB HTTP ERROR]", e)
        return {}


def zgrab_tls(target: str, port: int) -> dict:
    """
    Même principe : `target` en hostname donne un SNI correct, donc le bon
    certificat (essentiel sur un hébergeur mutualisé, chaque vhost a son
    propre certificat).
    """
    try:
        cmd = [
            "zgrab2",
            "tls",
            "--port", str(port),
            "--timeout", "10s",
        ]
        result = subprocess.run(
            cmd, input=target, text=True, capture_output=True, timeout=20,
        )
        if result.returncode != 0:
            return {}
        lines = result.stdout.strip().splitlines()
        if not lines:
            return {}
        data = json.loads(lines[0])
        handshake = data.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {})
        cert = (
            handshake.get("server_certificates", {})
            .get("certificate", {})
            .get("parsed", {})
        )
        if not cert:
            return {}

        issuer = cert.get("issuer", {}).get("common_name", [""])
        subject = cert.get("subject", {}).get("common_name", [""])
        san = cert.get("extensions", {}).get("subject_alt_name", {}).get("dns_names", [])
        validity = cert.get("validity", {})

        return {
            "issuer": issuer[0] if issuer else None,
            "subject": subject[0] if subject else None,
            "san": san or [],
            "validFrom": validity.get("start"),
            "validTo": validity.get("end"),
            "signatureAlgorithm": cert.get("signature_algorithm", {}).get("name"),
            "selfSigned": cert.get("signature", {}).get("self_signed"),
        }
    except Exception as e:
        print("[ZGRAB TLS ERROR]", e)
        return {}


def fetch_favicon(target: str, port: int, use_https: bool) -> dict:
    """
    `target` en hostname => requests envoie le bon Host header nativement
    (c'est juste l'URL). C'était le bug : avant, on construisait toujours
    l'URL avec l'IP brute.
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target}:{port}/favicon.ico"
    try:
        r = requests.get(url, timeout=8, verify=False)
        if r.status_code != 200 or not r.content:
            return {}

        import mmh3
        encoded = base64.encodebytes(r.content)
        favicon_hash = mmh3.hash(encoded)

        return {
            "faviconUrl": url,
            "faviconHash": favicon_hash,
        }
    except ImportError:
        print("[FAVICON] mmh3 non installé — pip install mmh3 --break-system-packages")
        return {"faviconUrl": url}
    except Exception as e:
        print("[FAVICON ERROR]", e)
        return {}