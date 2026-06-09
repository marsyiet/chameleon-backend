import os
from dotenv import load_dotenv
 
load_dotenv()
 
class Config:
    MONGO_URI       = os.getenv("MONGO_URI")
    MONGO_DB_NAME   = os.getenv("MONGO_DB_NAME", "chameleon")
    REDIS_URL       = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    SECRET_KEY      = os.getenv("SECRET_KEY", "dev")
    MASSCAN_RATE    = int(os.getenv("MASSCAN_RATE", 500))
    GEOIP_DB_PATH   = os.getenv("GEOIP_DB_PATH", "")
 
# Instance globale importable partout
config = Config()
