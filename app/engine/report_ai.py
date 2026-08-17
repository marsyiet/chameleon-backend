"""
Génère le résumé exécutif et les recommandations en langage naturel
pour un rapport d'actif, via un modèle Qwen exécuté localement (Ollama).

Ollama doit tourner sur la machine (ollama serve), avec le modèle déjà
téléchargé : `ollama pull qwen3:1.7b`.
"""

import re
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen3:1.7b"

# Qwen3 est un modèle hybride qui peut insérer un raisonnement interne entre
# balises <think>...</think> avant sa réponse finale. On désactive ce mode
# via le paramètre "think" (Ollama >= 0.6), et on retire ces balises par
# sécurité si elles apparaissent malgré tout.
THINK_TAG_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def _strip_thinking(text: str) -> str:
    return THINK_TAG_RE.sub("", text).strip()


def _summarize_asset_for_prompt(asset: dict) -> str:
    """Réduit l'actif à un résumé texte compact, pour ne pas saturer le contexte du modèle."""
    identity = asset.get("identity", {})
    services = asset.get("services", [])
    vulns = [
        cve for svc in services for cve in svc.get("cves", [])
        if cve.get("status") == "valid"
    ]
    auth_surfaces = asset.get("authenticationSurfaces", [])

    lines = [
        f"IP: {asset.get('ipAddress')}",
        f"Sévérité: {asset.get('severity')}",
        f"Score de risque: {asset.get('riskScore', {}).get('value')}/10",
        f"Rôle principal: {asset.get('primaryRoleForDisplay')}",
        f"Fabricant/modèle: {identity.get('vendor')} {identity.get('model') or ''}",
        f"Services exposés: " + ", ".join(f"{s.get('port')}/{s.get('service')}" for s in services),
        f"Vulnérabilités: " + (", ".join(f"{v['id']} (CVSS {v.get('cvss')})" for v in vulns) or "aucune"),
        f"Points d'authentification exposés: {len(auth_surfaces)}",
    ]
    return "\n".join(lines)


def _call_ollama(prompt: str, timeout: int = 60) -> str:
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "think": False,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        raw = response.json().get("response", "").strip()
        return _strip_thinking(raw)
    except Exception as e:
        print("[OLLAMA ERROR]", e)
        return None


def generate_executive_summary(asset: dict) -> str:
    context = _summarize_asset_for_prompt(asset)
    prompt = f"""Tu rédiges le résumé exécutif d'un rapport de sécurité, en français, pour une équipe CIRT.
Voici les données de l'actif détecté :

{context}

Rédige un résumé exécutif de 3 à 5 phrases, factuel, sans exagération, qui explique ce que représente \
cet actif et pourquoi son niveau de risque est ce qu'il est. Ne donne aucune instruction d'exploitation. \
Réponds uniquement avec le texte du résumé, sans titre ni formule d'introduction."""

    result = _call_ollama(prompt)
    return result or (
        f"Actif {asset.get('ipAddress')} détecté avec une sévérité {asset.get('severity')} "
        f"et un score de risque de {asset.get('riskScore', {}).get('value')}/10."
    )


def generate_recommendations(asset: dict) -> str:
    context = _summarize_asset_for_prompt(asset)
    prompt = f"""Tu rédiges les recommandations de remédiation d'un rapport de sécurité, en français.
Voici les données de l'actif détecté :

{context}

Propose 3 à 5 recommandations concrètes et actionnables pour réduire le risque, sous forme de liste \
à puces (une ligne par recommandation, commençant par "- "). Ne donne aucune instruction d'exploitation \
ni de contournement d'authentification. Réponds uniquement avec la liste, sans titre."""

    result = _call_ollama(prompt)
    return result or "- Mettre à jour les services exposés vers leur dernière version stable.\n- Restreindre l'accès aux services critiques par adresse IP."