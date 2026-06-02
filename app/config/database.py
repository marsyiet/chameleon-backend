from os import getenv

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv("app/.env")

client = MongoClient(
    getenv("MONGO_URI")
)

db = client[
    getenv("DB_NAME")
]