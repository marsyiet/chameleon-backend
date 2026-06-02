from datetime import datetime


class AuditLog:

    @staticmethod
    def build(data):

        return {

            "organizationId":
                data.get(
                    "organizationId"
                ),

            "userId":
                data.get(
                    "userId"
                ),

            "action":
                data["action"],

            "resource":
                data["resource"],

            "resourceId":
                data.get(
                    "resourceId"
                ),

            "details":
                data.get(
                    "details",
                    {}
                ),

            "ip":
                data.get("ip"),

            "userAgent":
                data.get(
                    "userAgent"
                ),

            "createdAt":
                datetime.utcnow(),
        }