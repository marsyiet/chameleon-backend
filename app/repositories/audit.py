from app.config.database import db


class AuditRepository:

    collection = db.audit_logs

    @classmethod
    def create(cls, log):
        cls.collection.insert_one(log)