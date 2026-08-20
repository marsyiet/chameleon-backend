"""
GET /api/assets/<asset_id>/report

Renvoie un PDF téléchargeable pour l'actif demandé, avec un résumé
exécutif et des recommandations générés par Qwen, et les données
structurées (services, CVE, score) directement issues de MongoDB.
"""

import os
import tempfile

from bson import ObjectId
from flask import Blueprint, send_file, jsonify

from app.models.db import get_db
from app.engine.report_ai import generate_executive_summary, generate_recommendations
from app.engine.report_pdf import build_asset_report_pdf

report_bp = Blueprint("report", __name__)


@report_bp.route("/<asset_id>/report", methods=["GET"])
def download_asset_report(asset_id):
    db = get_db()

    try:
        asset = db.assets.find_one({"_id": ObjectId(asset_id)})
    except Exception:
        return jsonify({"error": "Identifiant d'actif invalide."}), 400

    if not asset:
        return jsonify({"error": "Actif introuvable."}), 404

    # Génération des sections narratives par Qwen (avec repli automatique
    # si Ollama est indisponible, cf. report_ai.py)
    executive_summary = generate_executive_summary(asset)
    recommendations = generate_recommendations(asset)

    tmp_path = os.path.join(tempfile.gettempdir(), f"rapport_{asset_id}.pdf")
    build_asset_report_pdf(
        asset=asset,
        executive_summary=executive_summary,
        recommendations=recommendations,
        output_path=tmp_path,
    )

    filename = f"rapport_{asset.get('ipAddress', asset_id)}.pdf"
    return send_file(
        tmp_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )