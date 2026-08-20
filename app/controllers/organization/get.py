from flask import request
from app.services.organization import OrganizationService
from app.middlewares.auth import auth_required
from app.middlewares.permissions import permission_required
from app.utils.api_response import success_response
from app.utils.mongo import serialize_document, serialize_documents

from app.services import organization_relations
from app.utils.mongo import serialize_documents

@auth_required
@permission_required("organization.read")
def get_all():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 10))
    search = request.args.get("search")

    result = OrganizationService.get_all(page, limit, search)
    result["organizations"] = serialize_documents(result["organizations"])

    return success_response("Organizations retrieved", result)


@auth_required
@permission_required("organization.read")
def get_by_id(organization_id):
    organization = OrganizationService.get_by_id(organization_id)
    return success_response(
        "Organization retrieved",
        serialize_document(organization),
    )


@auth_required
@permission_required("organization.read")
def get_map_points():
    """
    Liste allégée pour la carte organisationnelle : uniquement les
    organisations avec des coordonnées déclarées, enrichies du compte
    d'actifs rattachés (organizationId). Pas de pagination — le volume
    d'organisations reste faible comparé aux actifs.
    """
    points = OrganizationService.get_map_points()
    return success_response(
        "Organization map points retrieved",
        serialize_documents(points),
    )




@auth_required
@permission_required("organization.read")
def get_assets(organization_id):
    assets = organization_relations.get_assets_for_organization(organization_id)
    return success_response(
        "Organization assets retrieved",
        serialize_documents(assets),
    )


@auth_required
@permission_required("organization.read")
def get_scans(organization_id):
    scans = organization_relations.get_scans_for_organization(organization_id)
    return success_response(
        "Organization scans retrieved",
        serialize_documents(scans),
    )


@auth_required
@permission_required("organization.read")
def get_stats(organization_id):
    stats = organization_relations.get_organization_stats(organization_id)
    return success_response(
        "Organization stats retrieved",
        stats,
    )