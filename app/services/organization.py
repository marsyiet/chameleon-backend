from datetime import datetime

from flask import g

from bson import ObjectId

from app.models.organization import (
    Organization
)

from app.models.db import get_db

from app.repositories.organization import (
    OrganizationRepository
)

from app.utils.exceptions import (
    NotFoundException,
    UnauthorizedException,
)


class OrganizationService:

    @staticmethod
    def create(data):

        organization = (
            Organization.build(
                data
            )
        )

        return (
            OrganizationRepository.create(
                organization
            )
        )

    @staticmethod
    def get_all(
        page,
        limit,
        search
    ):

        filters = {
            "isDeleted": False
        }

        if g.user["role"] != "super_admin":

            filters["_id"] = ObjectId(
                g.user["organizationId"]
            )

        if search:

            filters["name"] = {
                "$regex": search,
                "$options": "i"
            }

        organizations = (
            OrganizationRepository.find_all(
                filters,
                page,
                limit
            )
        )

        total = (
            OrganizationRepository.count(
                filters
            )
        )

        return {
            "organizations":
                organizations,
            "page": page,
            "limit": limit,
            "total": total,
        }

    @staticmethod
    def get_by_id(
        organization_id
    ):

        organization = (
            OrganizationRepository.find_by_id(
                organization_id
            )
        )

        if not organization:

            raise NotFoundException(
                "Organization not found",
                404,
            )

        if (
            g.user["role"] != "super_admin"
            and
            str(
                organization["_id"]
            )
            != g.user["organizationId"]
        ):

            raise UnauthorizedException(
                "Permission denied",
                403,
            )

        return organization

    @staticmethod
    def update(
        organization_id,
        data
    ):

        organization = (
            OrganizationRepository.find_by_id(
                organization_id
            )
        )

        if not organization:

            raise NotFoundException(
                "Organization not found",
                404,
            )

        if (
            g.user["role"] != "super_admin"
            and
            str(
                organization["_id"]
            )
            != g.user["organizationId"]
        ):

            raise UnauthorizedException(
                "Permission denied",
                403,
            )

        data["updatedAt"] = (
            datetime.utcnow()
        )

        OrganizationRepository.update(
            organization_id,
            data,
        )

    @staticmethod
    def delete(
        organization_id
    ):

        organization = (
            OrganizationRepository.find_by_id(
                organization_id
            )
        )

        if not organization:

            raise NotFoundException(
                "Organization not found",
                404,
            )

        if (
            g.user["role"] != "super_admin"
            and
            str(
                organization["_id"]
            )
            != g.user["organizationId"]
        ):

            raise UnauthorizedException(
                "Permission denied",
                403,
            )

        OrganizationRepository.soft_delete(
            organization_id,
            {
                "isDeleted": True,
                "deletedAt":
                    datetime.utcnow()
            },
        )

    @staticmethod
    def get_map_points():
        db = get_db()

        filters = {
            "isDeleted": False,
            "geo.lat": {"$ne": None},
            "geo.lon": {"$ne": None},
        }

        if g.user["role"] != "super_admin":
            filters["_id"] = ObjectId(g.user["organizationId"])

        organizations = list(OrganizationRepository.collection.find(filters))

        # Compte d'actifs rattachés à chaque organisation, en une seule
        # requête d'agrégation plutôt qu'une boucle avec N requêtes.
        org_ids = [str(org["_id"]) for org in organizations]
        counts = db.assets.aggregate([
            {"$match": {"organizationId": {"$in": org_ids}, "isDeleted": False}},
            {"$group": {"_id": "$organizationId", "count": {"$sum": 1}}},
        ])
        count_by_org = {c["_id"]: c["count"] for c in counts}

        for org in organizations:
            org["assetCount"] = count_by_org.get(str(org["_id"]), 0)

        return organizations