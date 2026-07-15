"""
Agent de crawl léger — voir la documentation complète dans la version
précédente. Seul changement ici : `crawl_site` prend un `target` (hostname
ou IP) au lieu de `host` fixe, pour cibler le bon vhost sur un hébergeur
mutualisé (Vercel, Netlify, Cloudflare Pages...).
"""

import requests
from bs4 import BeautifulSoup

COMMON_LOGIN_PATHS = [
    "/login", "/admin", "/administrator", "/wp-login.php", "/wp-admin",
    "/manage", "/user/login", "/signin", "/auth",
]

COMMON_API_PATHS = [
    "/api", "/api/v1", "/swagger.json", "/openapi.json", "/api-docs",
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
}


def crawl_site(target: str, port: int, use_https: bool) -> dict:
    """
    `target` : hostname si connu, sinon IP. Sur un hébergeur mutualisé,
    crawler l'IP nue renvoie le vhost par défaut, pas le vrai site — d'où
    des loginPoints/contactForms identiques et non pertinents pour chaque
    actif du même hébergeur.
    """
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{target}:{port}"

    result = {
        "technologies": [],
        "loginPoints": [],
        "contactForms": [],
        "apiPathsFound": [],
    }

    homepage_html = _safe_get(base_url)
    if homepage_html:
        result["technologies"] = _detect_technologies(homepage_html)
        result["loginPoints"].extend(_find_login_forms(homepage_html, base_url))
        result["contactForms"].extend(_find_contact_forms(homepage_html, base_url))

    for path in COMMON_LOGIN_PATHS:
        html, status = _safe_get(base_url + path, return_status=True)
        if html and status == 200:
            found = _find_login_forms(html, base_url + path)
            if found:
                result["loginPoints"].extend(found)
            elif _looks_like_login_page(html):
                result["loginPoints"].append({
                    "url": base_url + path,
                    "type": "form",
                    "confidence": "probable",
                })
        # status != 200 (404, redirect vers home, etc.) => on n'ajoute rien,
        # contrairement à avant où le chemin pouvait finir listé quand même
        # via le vhost par défaut qui répondait 200 à tout.

    for path in COMMON_API_PATHS:
        _, status = _safe_get(base_url + path, return_status=True)
        if status == 200:
            result["apiPathsFound"].append(base_url + path)

    for path in COMMON_CONTACT_PATHS:
        html, status = _safe_get(base_url + path, return_status=True)
        if html and status == 200:
            result["contactForms"].extend(_find_contact_forms(html, base_url + path))

    result["loginPoints"] = list({p["url"]: p for p in result["loginPoints"]}.values())
    result["contactForms"] = list({c["url"]: c for c in result["contactForms"]}.values())

    return result


def _safe_get(url, return_status=False):
    try:
        r = requests.get(url, timeout=6, verify=False, allow_redirects=True)
        if return_status:
            return (r.text if r.status_code == 200 else None), r.status_code
        return r.text if r.status_code == 200 else None
    except Exception:
        return (None, None) if return_status else None


def _detect_technologies(html: str) -> list:
    found = []
    lowered = html.lower()
    for tech, signatures in TECH_SIGNATURES.items():
        if any(sig.lower() in lowered for sig in signatures):
            found.append(tech)
    return found


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


def _looks_like_login_page(html: str) -> bool:
    lowered = html.lower()
    keywords = ["password", "mot de passe", "se connecter", "sign in", "username"]
    return any(k in lowered for k in keywords)


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