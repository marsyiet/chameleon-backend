"""
Agent de crawl — découverte de formulaires de login réels, sondage de
signaux API, extraction de métadonnées, détection de technologies.

Réutilise le corps de page déjà récupéré par zgrab_http (homepage_body)
au lieu de refaire une requête séparée — évite un second appel réseau
redondant qui peut échouer indépendamment du premier (rate limiting,
timing), ce qui laissait auparavant technologies/loginPoints vides même
quand zgrab avait pourtant bien récupéré le contenu.

Correctif dédup SPA : sur un site à routing catch-all (Next.js, React
Router...), tester une liste de chemins fixes renvoie souvent la MÊME
page pour chaque chemin — on ne compte un formulaire "trouvé" que si son
contenu diffère réellement de ce qui a déjà été vu (page d'accueil ou
autre chemin), sinon ce n'est pas un nouveau signal.
"""

import hashlib
import requests
from bs4 import BeautifulSoup

COMMON_LOGIN_PATHS = [
    "/login", "/admin", "/administrator", "/wp-login.php", "/wp-admin",
    "/manage", "/user/login", "/signin", "/auth",
]

API_PATHS = [
    "/api", "/api/v1", "/api/health", "/api/status",
    "/swagger.json", "/openapi.json", "/api-docs", "/graphql",
]

COMMON_CONTACT_PATHS = [
    "/contact", "/contact-us", "/nous-contacter", "/contactez-nous",
]

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", 'name="generator" content="WordPress'],
    "Joomla": ["/media/jui/", 'name="generator" content="Joomla'],
    "Drupal": ["sites/default/files", 'name="generator" content="Drupal'],
    "Laravel": ["laravel_session"],
    "Django": ["csrftoken"],
    "Next.js": ["__next", "_next/static"],
    "React": ["__react", "data-reactroot"],
    "EGroupware": ["egroupware", "egw_"],
}

API_CONTENT_MARKERS = [
    '"status"', '"data"', '"error"', '"message"', '"version"',
    '"api"', "endpoint", "swagger", "openapi",
]


def _body_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "ignore")).hexdigest()


def _safe_get(url, return_headers=False):
    try:
        r = requests.get(url, timeout=6, verify=False, allow_redirects=True)
        body = r.text if r.status_code == 200 else None
        if return_headers:
            return body, r.status_code, dict(r.headers)
        return body, r.status_code
    except Exception:
        if return_headers:
            return None, None, {}
        return None, None


def _normalize_zgrab_headers(zgrab_headers: dict) -> dict:
    """
    zgrab retourne des clés snake_case en listes (ex: content_type: [...]),
    requests retourne du Pascal-Case en chaînes simples — on normalise vers
    ce dernier format pour réutiliser les mêmes fonctions de détection.
    """
    if not zgrab_headers:
        return {}
    normalized = {}
    for key, value in zgrab_headers.items():
        pascal_key = "-".join(part.capitalize() for part in key.split("_"))
        normalized[pascal_key] = value[0] if isinstance(value, list) and value else value
    return normalized


def get_site_intelligence(target: str, port: int, use_https: bool,
                           homepage_body: str = None, homepage_status: int = None,
                           homepage_headers: dict = None) -> dict:
    """
    `homepage_body`/`homepage_status`/`homepage_headers` : si déjà connus
    (typiquement récupérés par zgrab_http juste avant), on les réutilise
    plutôt que de refaire une requête réseau qui peut échouer indépendamment.
    """
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{target}:{port}"

    result = {
        "pageTitle": None,
        "metaDescription": None,
        "technologies": [],
        "loginPoints": [],
        "contactForms": [],
        "apiSignalsFound": [],
        "isApi": False,
    }

    if homepage_body is not None:
        homepage_html = homepage_body
        homepage_headers_final = _normalize_zgrab_headers(homepage_headers)
    else:
        homepage_html, _, homepage_headers_final = _safe_get(base_url, return_headers=True)

    homepage_hash = _body_hash(homepage_html) if homepage_html else None

    if homepage_html:
        result["technologies"] = _detect_technologies(homepage_html, homepage_headers_final)
        result["pageTitle"] = _extract_title(homepage_html)
        result["metaDescription"] = _extract_meta_description(homepage_html)

        real_forms = _find_login_forms(homepage_html, base_url)
        result["loginPoints"].extend(real_forms)

        result["contactForms"].extend(_find_contact_forms(homepage_html, base_url))

        content_type = homepage_headers_final.get("Content-Type", "")
        if _looks_like_api_response(homepage_html, content_type):
            result["isApi"] = True
            result["apiSignalsFound"].append(base_url)

    seen_hashes = {homepage_hash} if homepage_hash else set()

    for path in COMMON_LOGIN_PATHS:
        html, status = _safe_get(base_url + path)
        if not html or status != 200:
            continue

        h = _body_hash(html)
        if h in seen_hashes:
            continue
        seen_hashes.add(h)

        found = _find_login_forms(html, base_url + path)
        if found:
            result["loginPoints"].extend(found)

    for path in API_PATHS:
        html, status, headers = _safe_get(base_url + path, return_headers=True)
        if status != 200:
            continue
        content_type = headers.get("Content-Type", "") if headers else ""
        if _looks_like_api_response(html, content_type):
            result["isApi"] = True
            result["apiSignalsFound"].append(base_url + path)

    for path in COMMON_CONTACT_PATHS:
        html, status = _safe_get(base_url + path)
        if html and status == 200:
            h = _body_hash(html)
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            result["contactForms"].extend(_find_contact_forms(html, base_url + path))

    result["loginPoints"] = list({p["url"]: p for p in result["loginPoints"]}.values())
    result["contactForms"] = list({c["url"]: c for c in result["contactForms"]}.values())
    result["apiSignalsFound"] = list(dict.fromkeys(result["apiSignalsFound"]))

    return result


def _extract_title(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("title")
        return tag.get_text(strip=True) if tag and tag.get_text(strip=True) else None
    except Exception:
        return None


def _extract_meta_description(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("meta", attrs={"name": "description"})
        if tag and tag.get("content"):
            return tag.get("content")
        og_tag = soup.find("meta", attrs={"property": "og:description"})
        return og_tag.get("content") if og_tag else None
    except Exception:
        return None


def _looks_like_api_response(body: str, content_type: str) -> bool:
    if "application/json" in (content_type or "").lower():
        return True
    if "application/xml" in (content_type or "").lower() and "swagger" in (body or "").lower():
        return True
    if body:
        lowered = body.lower().strip()
        if lowered.startswith("{") or lowered.startswith("["):
            return True
        if any(marker in lowered for marker in API_CONTENT_MARKERS) and len(body) < 2000:
            return True
    return False


def _detect_technologies(html: str, headers: dict) -> list:
    found = []
    lowered = html.lower()
    header_blob = " ".join(f"{k}: {v}".lower() for k, v in (headers or {}).items())

    for tech, signatures in TECH_SIGNATURES.items():
        if any(sig.lower() in lowered or sig.lower() in header_blob for sig in signatures):
            found.append(tech)

    powered_by = (headers or {}).get("X-Powered-By", "")
    if powered_by and powered_by not in found:
        found.append(powered_by)

    server = (headers or {}).get("Server", "")
    if server and "envoy" in server.lower() and "Istio/Envoy" not in found:
        found.append("Istio/Envoy")

    return list(dict.fromkeys(found))


def _find_login_forms(html: str, page_url: str) -> list:
    points = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            if form.find("input", {"type": "password"}) is not None:
                points.append({
                    "url": page_url,
                    "type": "form",
                    "confidence": "certaine",
                })
    except Exception:
        pass
    return points


def _find_contact_forms(html: str, page_url: str) -> list:
    forms_found = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            fields_detected = []
            for input_tag in form.find_all(["input", "textarea"]):
                field_type = (input_tag.get("type") or input_tag.name or "").lower()
                field_name = (input_tag.get("name") or "").lower()
                if "email" in field_name or field_type == "email":
                    fields_detected.append("email")
                elif "phone" in field_name or "tel" in field_type:
                    fields_detected.append("phone")
                elif "message" in field_name or input_tag.name == "textarea":
                    fields_detected.append("message")

            has_password = form.find("input", {"type": "password"}) is not None
            if fields_detected and not has_password:
                forms_found.append({
                    "url": page_url,
                    "fieldsDetected": list(set(fields_detected)),
                })
    except Exception:
        pass
    return forms_found