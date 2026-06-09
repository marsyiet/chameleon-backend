from flask import jsonify
from app.services.scan import ScanService
from app.utils.exceptions import NotFoundException

def start(scan_id):
    try:
        ScanService.start_scan(scan_id)
        return jsonify({"success": True, "message": "Scan started"}), 200
    except NotFoundException as e:
        return jsonify({"success": False, "message": str(e)}), 404
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400