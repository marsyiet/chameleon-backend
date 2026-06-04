from datetime import datetime


class Service:

    @staticmethod
    def build(data):

        now = datetime.utcnow()

        return {
            "portId": data["portId"],

            "name": data["name"],

            "product": data["product"],

            "version": data["version"],

            "banner": data["banner"],

            "createdAt": now,
            "updatedAt": now,
        }