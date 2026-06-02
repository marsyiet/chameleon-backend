from app.models.audit import Audit
from app.repositories.audit import (
    AuditRepository,
)


class AuditService:

    @staticmethod
    def log(
        user_id,
        organization_id,
        action,
        resource,
        resource_id,
        metadata=None,
    ):
        audit = Audit.build(
            user_id,
            organization_id,
            action,
            resource,
            resource_id,
            metadata,
        )

        AuditRepository.create(
            audit
        )