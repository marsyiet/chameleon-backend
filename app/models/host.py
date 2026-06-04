from datetime import datetime


class Host:

    @staticmethod
    def build(data):

        now = datetime.utcnow()

        return {
            "assetId": data["assetId"],

            "hostname": data["hostname"],

            "ip": data["ip"],

            "firstSeenAt": now,
            "lastSeenAt": now,

            "createdAt": now,
            "updatedAt": now,
        }