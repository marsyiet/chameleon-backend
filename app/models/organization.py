from datetime import datetime


class Organization:

    @staticmethod
    def build(data):

        return {
            "name": data["name"],
            "description": data.get(
                "description"
            ),
            "sector": data.get(
                "sector"
            ),
            "status": "active",
            "isDeleted": False,
            "deletedAt": None,
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow(),
        }