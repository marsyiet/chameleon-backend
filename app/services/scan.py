from flask import g

from bson import ObjectId

from app.models.scan import (
    Scan
)

from app.repositories.scan import (
    ScanRepository
)

from app.utils.exceptions import (
    NotFoundException,
)

from datetime import datetime



class ScanService:

    @staticmethod
    def create(data):

        data["organizationId"] = (
            g.user["organizationId"]
        )

        data["createdBy"] = (
            g.user["userId"]
        )

        scan = Scan.build(
            data
        )

        return (
            ScanRepository.create(
                scan
            )
        )

    @staticmethod
    def get_all(
        page,
        limit
    ):

        filters = {
            "organizationId":
                g.user[
                    "organizationId"
                ],
            "isDeleted": False,
        }

        scans = (
            ScanRepository.find_all(
                filters,
                page,
                limit,
            )
        )

        total = (
            ScanRepository.count(
                filters
            )
        )

        return {
            "scans": scans,
            "page": page,
            "limit": limit,
            "total": total,
        }

    @staticmethod
    def get_by_id(
        scan_id
    ):

        scan = (
            ScanRepository.find_by_id(
                scan_id
            )
        )

        if not scan:

            raise NotFoundException(
                "Scan not found",
                404,
            )

        if (
            scan[
                "organizationId"
            ]
            !=
            g.user[
                "organizationId"
            ]
        ):

            raise NotFoundException(
                "Scan not found",
                404,
            )

        return scan


    @staticmethod
    def update(
        scan_id,
        data
    ):

        scan = (
            ScanRepository.find_by_id(
                scan_id
            )
        )

        if not scan:

            raise NotFoundException(
                "Scan not found",
                404,
            )

        if (
            scan["organizationId"]
            !=
            g.user["organizationId"]
        ):

            raise NotFoundException(
                "Scan not found",
                404,
            )

        data["updatedAt"] = (
            datetime.utcnow()
        )

        ScanRepository.update(
            scan_id,
            data,
        )


    @staticmethod
    def delete(
        scan_id
    ):

        scan = (
            ScanRepository.find_by_id(
                scan_id
            )
        )

        if not scan:

            raise NotFoundException(
                "Scan not found",
                404,
            )

        if (
            scan["organizationId"]
            !=
            g.user["organizationId"]
        ):

            raise NotFoundException(
                "Scan not found",
                404,
            )

        ScanRepository.soft_delete(
            scan_id,
            {
                "isDeleted": True,
                "deletedAt":
                    datetime.utcnow(),
                "updatedAt":
                    datetime.utcnow(),
            }
        )