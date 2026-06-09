from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.database import Database
from config import config
 
_client: MongoClient = None
 
 
def get_db() -> Database:
    global _client
    if _client is None:
        _client = MongoClient(
            config.MONGO_URI,
            serverSelectionTimeoutMS=5000,
            maxPoolSize=20,        # connexions max dans le pool
            minPoolSize=2,
        )
    return _client[config.MONGO_DB_NAME]
 
 
def create_indexes():
    """Appeler une fois au démarrage de l'app."""
    db = get_db()
 
    # Index sur les scans
    db.scans.create_index([("organizationId", ASCENDING)])
    db.scans.create_index([("status", ASCENDING)])
    db.scans.create_index([("createdAt", DESCENDING)])
 
    # Index sur les assets
    db.assets.create_index([("scanId", ASCENDING)])
    db.assets.create_index([("ip", ASCENDING)])
    db.assets.create_index([("tags", ASCENDING)])
    db.assets.create_index([("geo.country", ASCENDING)])
    db.assets.create_index([
        ("ip", ASCENDING),
        ("scanId", ASCENDING)
    ], unique=True)
