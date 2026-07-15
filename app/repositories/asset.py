from bson import ObjectId
from datetime import datetime
from app.config.database import db
class AssetRepository:
    collection = db.assets

    @classmethod
    def create(
        cls,
        asset
    ):
        result = (
            cls.collection.insert_one(
                asset
            )
        )
        return str(
            result.inserted_id
        )

    @classmethod
    def find_all(
        cls,
        filters,
        page,
        limit
    ):
        skip = (
            page - 1
        ) * limit
        cursor = (
            cls.collection
            .find(filters)
            .skip(skip)
            .limit(limit)
            .sort(
                "createdAt",
                -1
            )
        )
        return list(
            cursor
        )

    @classmethod
    def count(
        cls,
        filters
    ):
        return (
            cls.collection.count_documents(
                filters
            )
        )

    @classmethod
    def find_by_id(
        cls,
        asset_id
    ):
        return (
            cls.collection.find_one(
                {
                    "_id": ObjectId(
                        asset_id
                    ),
                    "isDeleted": False,
                }
            )
        )

    @classmethod
    def update(
        cls,
        asset_id,
        data
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(
                    asset_id
                )
            },
            {
                "$set": data
            }
        )

    @classmethod
    def soft_delete(
        cls,
        asset_id,
        data
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(
                    asset_id
                )
            },
            {
                "$set": data
            }
        )

    # ================================================================
    # Carte nationale : actifs géolocalisables (IP publique), avec ou
    # sans organisation confirmée — c'est justement le point de la carte
    # nationale de pouvoir afficher des actifs non encore attribués.
    # ================================================================
    @classmethod
    def find_national_map(
        cls,
        filters
    ):
        query = {
            **filters,
            "isDeleted": False,
            "exposure": "externe",
            "geo.country": {"$ne": None},
        }
        return list(
            cls.collection.find(query)
        )

    # ================================================================
    # Carte organisationnelle : tous les actifs rattachés à une
    # organisation confirmée, indépendamment de leur géographie
    # d'hébergement réelle.
    # ================================================================
    @classmethod
    def find_by_organization(
        cls,
        organization_id
    ):
        return list(
            cls.collection.find(
                {
                    "organizationId": organization_id,
                    "isDeleted": False,
                }
            )
        )

    # ================================================================
    # Regroupement des sous-domaines découverts pour une organisation
    # (affichage "sous-domaines trouvés" au clic sur la carte organisationnelle).
    # ================================================================
    @classmethod
    def find_root_domains(
        cls,
        organization_id
    ):
        return cls.collection.distinct(
            "rootDomain",
            {
                "organizationId": organization_id,
                "rootDomain": {"$ne": None},
                "isDeleted": False,
            }
        )

    # ================================================================
    # Mise à jour de l'attribution ESTIMÉE (carte nationale, avant
    # confirmation) — ne touche jamais organizationId.
    # ================================================================
    @classmethod
    def update_attribution(
        cls,
        asset_id,
        attribution
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(asset_id)
            },
            {
                "$set": {
                    "attribution": attribution,
                    "updatedAt": datetime.utcnow(),
                }
            }
        )

    # ================================================================
    # Confirmation manuelle de l'organisation propriétaire — c'est le
    # seul chemin qui fait passer un actif de la carte nationale
    # "non attribué" vers la carte organisationnelle d'une structure.
    # ================================================================
    @classmethod
    def confirm_organization(
        cls,
        asset_id,
        organization_id,
        confirmed_by
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(asset_id)
            },
            {
                "$set": {
                    "organizationId": organization_id,
                    "attribution.confidence": "certaine",
                    "updatedAt": datetime.utcnow(),
                }
            }
        )

    # ================================================================
    # Ajout d'un service détecté au tableau embarqué (remplace l'ancien
    # modèle Service séparé).
    # ================================================================
    @classmethod
    def add_service(
        cls,
        asset_id,
        service
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(asset_id)
            },
            {
                "$push": {
                    "services": service
                },
                "$set": {
                    "lastSeenAt": datetime.utcnow(),
                    "updatedAt": datetime.utcnow(),
                }
            }
        )

    # ================================================================
    # Mise à jour du score de risque composite (chapitre 2, §2.3.1),
    # recalculé à chaque cycle d'enrichissement.
    # ================================================================
    @classmethod
    def update_risk_score(
        cls,
        asset_id,
        risk_score,
        severity
    ):
        cls.collection.update_one(
            {
                "_id": ObjectId(asset_id)
            },
            {
                "$set": {
                    "riskScore": risk_score,
                    "severity": severity,
                    "updatedAt": datetime.utcnow(),
                }
            }
        )

    # ================================================================
    # Actifs non revus depuis N jours (fraîcheur, chapitre 2 tableau 2.1)
    # ================================================================
    @classmethod
    def find_stale(
        cls,
        organization_id,
        older_than
    ):
        return list(
            cls.collection.find(
                {
                    "organizationId": organization_id,
                    "lastSeenAt": {"$lt": older_than},
                    "isDeleted": False,
                }
            )
        )