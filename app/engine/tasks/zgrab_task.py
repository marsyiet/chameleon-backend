import base64
import hashlib
import json
import subprocess

import requests


def zgrab_http(target: str, port: int, use_https: bool = False) -> dict:
    """
    `target` : hostname si connu, sinon IP. Le hostname donne le bon Host
    header / SNI — essentiel sur hébergement mutualisé (Vercel, Google
    Cloud...), où l'IP nue seule ne suffit pas à obtenir la vraie réponse.
    """
    try:
        cmd = [
            "zgrab2",
            "http",
            "--port", str(port),
            "--connect-timeout", "10s",
            "--target-timeout", "15s",
            "--max-redirects", "5",
            "--redirects-succeed",
            "--max-size", "512",
        ]
        if use_https:
            cmd.append("--use-https")

        result = subprocess.run(
            cmd, input=target, text=True, capture_output=True, timeout=25,
        )
        if result.returncode != 0:
            print("[ZGRAB HTTP NONZERO EXIT]", result.returncode, result.stderr[:300])
            return {}
        lines = result.stdout.strip().splitlines()
        if not lines:
            return {}
        data = json.loads(lines[0])
        http_result = data.get("data", {}).get("http", {}).get("result", {})
        response = http_result.get("response", {})
        body = response.get("body", "") or ""

        content_type = (response.get("headers", {}).get("content_type", [""]))[0]

        return {
            "title": http_result.get("title"),
            "statusCode": response.get("status_code"),
            "server": (response.get("headers", {}).get("server", [""]))[0],
            "poweredBy": (response.get("headers", {}).get("x_powered_by", [""]))[0],
            "contentType": content_type,
            "headers": response.get("headers", {}),
            "redirectChain": [
                r.get("url", "") for r in http_result.get("redirect_response_chain", [])
            ],
            "bodyPreview": body[:8000] if body else None,
            "bodyHashSha256": hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest() if body else None,
        }
    except Exception as e:
        print("[ZGRAB HTTP ERROR]", e)
        return {}


def zgrab_tls(target: str, port: int) -> dict:
    try:
        cmd = [
            "zgrab2",
            "tls",
            "--port", str(port),
            "--connect-timeout", "10s",
        ]
        result = subprocess.run(
            cmd, input=target, text=True, capture_output=True, timeout=20,
        )
        if result.returncode != 0:
            print("[ZGRAB TLS NONZERO EXIT]", result.returncode, result.stderr[:300])
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
        fingerprint = cert.get("fingerprint_sha256") or data.get("data", {}).get("tls", {}).get("result", {}).get("handshake_log", {}).get("server_certificates", {}).get("certificate", {}).get("raw", {}).get("fingerprint_sha256")

        return {
            "issuer": issuer[0] if issuer else None,
            "subject": subject[0] if subject else None,
            "san": san or [],
            "validFrom": validity.get("start"),
            "validTo": validity.get("end"),
            "signatureAlgorithm": cert.get("signature_algorithm", {}).get("name"),
            "selfSigned": cert.get("signature", {}).get("self_signed"),
            "fingerprintSha256": fingerprint,
        }
    except Exception as e:
        print("[ZGRAB TLS ERROR]", e)
        return {}


def zgrab_ssh(target: str, port: int = 22) -> dict:
    """
    Récupère la bannière de version SSH et les paramètres négociés
    (algorithme de clé hôte, chiffrement) sans authentification — cette
    partie de l'échange SSH est envoyée par le serveur à toute connexion,
    avant toute tentative de login.
    """
    try:
        cmd = [
            "zgrab2",
            "ssh",
            "--port", str(port),
            "--client-id", "ANTIC-EASM_1.0",
            "--connect-timeout", "10s",
        ]
        result = subprocess.run(
            cmd, input=target, text=True, capture_output=True, timeout=20,
        )
        if result.returncode != 0:
            print("[ZGRAB SSH NONZERO EXIT]", result.returncode, result.stderr[:300])
            return {}
        lines = result.stdout.strip().splitlines()
        if not lines:
            return {}
        data = json.loads(lines[0])
        ssh_result = data.get("data", {}).get("ssh", {}).get("result", {})
        server_id = ssh_result.get("server_id", {})
        algos = ssh_result.get("algorithm_selection", {})

        return {
            "banner": server_id.get("raw"),
            "protocolVersion": server_id.get("version"),
            "softwareVersion": server_id.get("software"),
            "hostKeyAlgorithm": algos.get("host_key_algorithm"),
            "encryptionAlgorithm": algos.get("client_to_server_alg_group", {}).get("cipher"),
        }
    except Exception as e:
        print("[ZGRAB SSH ERROR]", e)
        return {}


def fetch_favicon(target: str, port: int, use_https: bool) -> dict:
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