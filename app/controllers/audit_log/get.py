from flask import (
    request,
    g,
)

from app.middlewares.auth import (
    auth_required
)

from app.services.audit_log import (
    AuditLogService
)

from app.utils.api_response import (
    success_response
)


@auth_required
def get_all():

    page = int(
        request.args.get(
            "page",
            1
        )
    )

    limit = int(
        request.args.get(
            "limit",
            20
        )
    )

    action = request.args.get(
        "action"
    )

    resource = request.args.get(
        "resource"
    )

    user_id = request.args.get(
        "userId"
    )

    result = (
        AuditLogService.get_all(
            organization_id=g.user[
                "organizationId"
            ],
            page=page,
            limit=limit,
            action=action,
            resource=resource,
            user_id=user_id,
        )
    )

    for log in result["logs"]:

        log["_id"] = str(
            log["_id"]
        )

        if log.get(
            "createdAt"
        ):
            log["createdAt"] = str(
                log["createdAt"]
            )

    return success_response(
        "Audit logs retrieved",
        result
    )