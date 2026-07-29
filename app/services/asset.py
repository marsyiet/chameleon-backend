from datetime import datetime
from flask import g
from bson import ObjectId
from app.models.asset import (
    Asset,
)
from app.repositories.asset import (
    AssetRepository,
)
from app.utils.exceptions import (
    NotFoundException,
    UnauthorizedException,
)


class AssetService:
    @staticmethod
    def create(data):
        asset = Asset.build(
            {
                **data,
                "organizationId":
                    g.user[
                        "organizationId"
                    ],
            }
        )
        return (
            AssetRepository.create(
                asset
            )
        )

    @staticmethod
    def get_all(page, limit, search, scan_id=None):
        filters = {
            "organizationId": g.user["organizationId"],
            "isDeleted": False,
        }
        if search:
            filters["$or"] = [
                {"hostname": {"$regex": search, "$options": "i"}},
                {"ipAddress": {"$regex": search, "$options": "i"}},
                {"rootDomain": {"$regex": search, "$options": "i"}},
            ]
        if scan_id:
            # lastScanId : référence au dernier scan ayant mis à jour l'actif,
            # remplace l'ancien scanId qui faisait partie de la clé d'identité
            # (chaque rescan produisait un doublon plutôt qu'une mise à jour).
            filters["lastScanId"] = scan_id
        assets = AssetRepository.find_all(filters, page, limit)
        total  = AssetRepository.count(filters)
        return {"assets": assets, "page": page, "limit": limit, "total": total}

    @staticmethod
    def get_by_id(
        asset_id
    ):
        asset = (
            AssetRepository.find_by_id(
                asset_id
            )
        )
        if not asset:
            raise NotFoundException(
                "Asset not found",
                404,
            )
        if (
            asset[
                "organizationId"
            ]
            !=
            g.user[
                "organizationId"
            ]
        ):
            raise UnauthorizedException(
                "Permission denied",
                403,
            )
        return asset

    @staticmethod
    def update(
        asset_id,
        data
    ):
        asset = (
            AssetRepository.find_by_id(
                asset_id
            )
        )
        if not asset:
            raise NotFoundException(
                "Asset not found",
                404,
            )
        if (
            asset[
                "organizationId"
            ]
            !=
            g.user[
                "organizationId"
            ]
        ):
            raise UnauthorizedException(
                "Permission denied",
                403,
            )
        data[
            "updatedAt"
        ] = (
            datetime.utcnow()
        )
        AssetRepository.update(
            asset_id,
            data,
        )

    @staticmethod
    def confirm_attribution(asset_id, organization_id):
        """
        Fait passer un actif d'une attribution estimée (carte nationale,
        déduite par WHOIS/rDNS) à un propriétaire confirmé — action
        distincte d'une mise à jour générique, avec sa propre sémantique
        (chapitre 2, cartographie nationale vs organisationnelle).
        """
        asset = AssetRepository.find_by_id(asset_id)
        if not asset:
            raise NotFoundException("Asset not found", 404)

        AssetRepository.update(
            asset_id,
            {
                "organizationId": organization_id,
                "attribution": {
                    "guessedOrganizationName": asset.get("attribution", {}).get("guessedOrganizationName"),
                    "confidence": "certaine",
                    "signals": ["manual_confirmation"],
                },
                "updatedAt": datetime.utcnow(),
            },
        )

    @staticmethod
    def delete(
        asset_id
    ):
        asset = (
            AssetRepository.find_by_id(
                asset_id
            )
        )
        if not asset:
            raise NotFoundException(
                "Asset not found",
                404,
            )
        if (
            asset[
                "organizationId"
            ]
            !=
            g.user[
                "organizationId"
            ]
        ):
            raise UnauthorizedException(
                "Permission denied",
                403,
            )
        AssetRepository.soft_delete(
            asset_id,
            {
                "isDeleted": True,
                "deletedAt":
                    datetime.utcnow(),
            },
        )