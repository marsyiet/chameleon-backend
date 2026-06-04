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
    def get_all(
        page,
        limit,
        search
    ):

        filters = {
            "organizationId":
                g.user[
                    "organizationId"
                ],
            "isDeleted": False,
        }

        if search:

            filters["value"] = {
                "$regex": search,
                "$options": "i",
            }

        assets = (
            AssetRepository.find_all(
                filters,
                page,
                limit,
            )
        )

        total = (
            AssetRepository.count(
                filters
            )
        )

        return {
            "assets": assets,
            "page": page,
            "limit": limit,
            "total": total,
        }

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