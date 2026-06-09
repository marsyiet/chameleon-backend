import json
import subprocess


def zgrab_http(host: str, port: int) -> dict:
    """
    Lance zgrab2 HTTP.
    Retourne les infos utiles pour enrichir l'asset.
    """

    try:
        cmd = [
            "zgrab2",
            "http",
            "--port",
            str(port),
            "--timeout",
            "10s",
        ]

        result = subprocess.run(
            cmd,
            input=host,
            text=True,
            capture_output=True,
            timeout=20,
        )

        if result.returncode != 0:
            return {}

        lines = result.stdout.strip().splitlines()

        if not lines:
            return {}

        data = json.loads(lines[0])

        response = (
            data.get("data", {})
            .get("http", {})
            .get("result", {})
            .get("response", {})
        )

        return {
            "title": (
                data.get("data", {})
                .get("http", {})
                .get("result", {})
                .get("title")
            ),
            "statusCode": response.get("status_code"),
            "server": (
                response.get("headers", {})
                .get("server", [""])
            )[0],
            "headers": response.get("headers", {}),
        }

    except Exception as e:
        print("[ZGRAB ERROR]", e)
        return {}