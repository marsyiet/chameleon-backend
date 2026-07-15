from datetime import datetime
from bson import ObjectId


class Organization:
    @staticmethod
    def build(data):
        now = datetime.utcnow()
        return {
            "name": data["name"],
            "description": data.get(
                "description"
            ),
            "sector": data.get(
                "sector"
            ),
            "status": "active",

            # ---- Sites déclarés (ancrage carte organisationnelle, chapitre 2 §2.1.4) ----
            # chaque élément : { id, name, city, lat, lon }
            "sites": [
                Organization.build_site(site) for site in data.get("sites", [])
            ],

            # ---- Périmètre déclaré (déclaration collaborative, chapitre 2 §2.1.2) ----
            "declaredPerimeter": {
                "domains": data.get("declaredDomains", []),
                "internalRanges": data.get("declaredInternalRanges", []),
                "providers": data.get("declaredProviders", []),  # SaaS/cloud/mail
                # chaque élément : { name, criticality, description }
                "apps": data.get("declaredApps", []),
            },

            "isDeleted": False,
            "deletedAt": None,
            "createdAt": now,
            "updatedAt": now,
        }

    @staticmethod
    def build_site(data):
        return {
            "id": str(ObjectId()),
            "name": data["name"],
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
        }