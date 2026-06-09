import random
import requests
 
PROXY_POOL = [
    # Format : socks5://user:pass@host:port
    # Charger depuis .env ou base de données
]
 
def get_session_with_proxy() -> requests.Session:
    session = requests.Session()
    if PROXY_POOL:
        proxy = random.choice(PROXY_POOL)
        session.proxies = {"http": proxy, "https": proxy}
    return session
