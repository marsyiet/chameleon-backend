# engine/evasion/rate_limiter.py
import redis as redis_lib
from config import config
 
_r = redis_lib.from_url(config.REDIS_URL)
 
 
def get_scan_rate(target_subnet: str) -> int:
    """
    Réduit le rate si trop de timeouts sont détectés sur ce /24.
    Appelé avant chaque scan pour adapter la vitesse.
    """
    base_rate  = config.MASSCAN_RATE
    key        = f"timeouts:{target_subnet}"
    timeouts   = int(_r.get(key) or 0)
 
    if timeouts > 100:
        return max(50, base_rate // 8)    # très lent
    elif timeouts > 50:
        return max(100, base_rate // 4)   # lent
    elif timeouts > 20:
        return base_rate // 2              # modéré
    return base_rate
 
 
def record_timeout(ip: str):
    subnet = ".".join(ip.split(".")[:3])
    key    = f"timeouts:{subnet}"
    _r.incr(key)
    _r.expire(key, 3600)    # reset après 1h
