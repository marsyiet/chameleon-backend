from datetime import datetime


class Audit:

    @staticmethod
    def build(
        user_id,
        organization_id,
        action,
        resource,
        resource_id,
        metadata=None,
    ):
        return {
            "userId": user_id,
            "organizationId": organization_id,
            "action": action,
            "resource": resource,
            "resourceId": resource_id,
            "metadata": metadata or {},
            "createdAt": datetime.utcnow(),
        }