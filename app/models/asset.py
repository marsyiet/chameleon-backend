from datetime import datetime


class Asset:

    @staticmethod
    def build(data):

        now = datetime.utcnow()

        return {
            "organizationId": data["organizationId"],

            "scanId": data.get(
                "scanId"
            ),

            "assetType": data[
                "assetType"
            ],

            "value": data[
                "value"
            ],

            "hostname": data.get(
                "hostname"
            ),

            "ipAddress": data.get(
                "ipAddress"
            ),

            "status": "active",

            "country": None,

            "city": None,

            "asn": None,

            "organization": None,

            "openPorts": [],

            "technologies": [],

            "tags": [],

            "lastSeenAt": now,

            "isDeleted": False,

            "deletedAt": None,

            "createdAt": now,

            "updatedAt": now,
        }