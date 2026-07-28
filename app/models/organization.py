from datetime import datetime
from bson import ObjectId


class Organization:
    @staticmethod
    def build(data):
        now = datetime.utcnow()
        return {
            "name": data["name"],
            "description": data.get("description"),
            "sector": data.get("sector"),
            "status": "active",

            # ---- Localisation : une organisation = un point sur la carte.
            # Une antenne/succursale se déclare comme une organisation à
            # part entière (ex: "ANTIC — Antenne Littoral"), pas comme un
            # sous-objet imbriqué — plus simple à gérer, cohérent avec le
            # fait que chaque antenne a son propre périmètre déclaré.
            "geo": {
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
            },

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