from app.models.audit_log import (
    AuditLog
)

from app.repositories.audit_log import (
    AuditLogRepository
)


class AuditLogService:

    @staticmethod
    def create(
        action,
        resource,
        user_id=None,
        organization_id=None,
        resource_id=None,
        details=None,
    ):

        audit_log = (
            AuditLog.build(
                {
                    "action":
                        action,

                    "resource":
                        resource,

                    "userId":
                        user_id,

                    "organizationId":
                        organization_id,

                    "resourceId":
                        resource_id,

                    "details":
                        details or {}
                }
            )
        )

        return (
            AuditLogRepository.create(
                audit_log
            )
        )

    @staticmethod
    def get_all(
        organization_id,
        page=1,
        limit=20,
        action=None,
        resource=None,
        user_id=None,
    ):

        filters = {
            "organizationId":
                organization_id
        }

        if action:

            filters["action"] = action

        if resource:

            filters["resource"] = resource

        if user_id:

            filters["userId"] = user_id

        return (
            AuditLogRepository
            .find_paginated(
                filters,
                page,
                limit
            )
        )