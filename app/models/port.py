from datetime import datetime


class Port:

    @staticmethod
    def build(data):

        now = datetime.utcnow()

        return {
            "assetId": data["assetId"],

            "port": data["port"],

            "protocol": data["protocol"],

            "state": data["state"],

            "firstSeenAt": now,
            "lastSeenAt": now,

            "createdAt": now,
            "updatedAt": now,
        }