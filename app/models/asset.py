from datetime import datetime


class Asset:

    @staticmethod
    def build(data):

        now = datetime.utcnow()

        return {
            "organizationId": data["organizationId"],

            "assetType": data["assetType"],

            "value": data["value"],

            "firstSeenAt": now,
            "lastSeenAt": now,

            "riskScore": 0,

            "tags": [],

            "createdAt": now,
            "updatedAt": now,
        }