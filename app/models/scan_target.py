from datetime import datetime


class ScanTarget:

    @staticmethod
    def build(data):

        now = datetime.utcnow()

        return {
            "scanId": data["scanId"],

            "target": data["target"],

            "targetType": data["targetType"],

            "createdAt": now,
            "updatedAt": now,
        }