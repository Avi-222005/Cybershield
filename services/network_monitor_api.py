"""
Flask Blueprint providing REST API endpoints for the CyberShield Network Monitor.
Mounted at /api/network.
"""

from flask import Blueprint, jsonify, request
from services.network_monitor_service import get_network_service

network_monitor_bp = Blueprint("network_monitor", __name__, url_prefix="/api/network")


@network_monitor_bp.route("/interfaces", methods=["GET"])
def get_interfaces():
    """Retrieve detected physical and virtual network adapters."""
    try:
        service = get_network_service()
        interfaces = service.get_interfaces()
        return jsonify({
            "success": True,
            "interfaces": interfaces,
            "count": len(interfaces),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/status", methods=["GET"])
def get_status():
    """Retrieve current monitoring agent status and subsystem health."""
    try:
        service = get_network_service()
        status = service.get_status()
        return jsonify({
            "success": True,
            "status": status,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/start", methods=["POST"])
def start_monitoring():
    """Start packet, connection, and bandwidth monitoring."""
    try:
        data = request.get_json(silent=True) or {}
        interface_name = data.get("interface")
        force_adapter = data.get("force_adapter")

        service = get_network_service()
        res = service.start_monitoring(interface_name=interface_name, force_adapter=force_adapter)
        status_code = 200 if res.get("success") else 400
        return jsonify(res), status_code
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/stop", methods=["POST"])
def stop_monitoring():
    """Gracefully stop monitoring and purge temporary in-memory buffers."""
    try:
        service = get_network_service()
        res = service.stop_monitoring()
        return jsonify(res)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/traffic", methods=["GET"])
def get_traffic():
    """Retrieve upload/download throughput and packet rate metrics."""
    try:
        service = get_network_service()
        traffic = service.get_traffic()
        return jsonify({
            "success": True,
            "traffic": traffic,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/connections", methods=["GET"])
def get_connections():
    """Retrieve active TCP/UDP internet socket connections."""
    try:
        service = get_network_service()
        conns = service.get_connections()
        return jsonify({
            "success": True,
            "connections": conns,
            "count": len(conns),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/protocols", methods=["GET"])
def get_protocols():
    """Retrieve observed protocol and direction distribution statistics."""
    try:
        service = get_network_service()
        protocols = service.get_protocols()
        return jsonify({
            "success": True,
            "protocols": protocols,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/events", methods=["GET"])
def get_events():
    """Retrieve recent bounded packet metadata events without payloads."""
    try:
        limit = request.args.get("limit", default=50, type=int)
        service = get_network_service()
        events = service.get_events(limit=limit)
        return jsonify({
            "success": True,
            "events": events,
            "count": len(events),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/summary", methods=["GET"])
def get_summary():
    """Retrieve aggregated overview snapshot for dashboard display."""
    try:
        service = get_network_service()
        summary = service.get_summary()
        return jsonify({
            "success": True,
            "summary": summary,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/health", methods=["GET"])
def get_health():
    """Retrieve backend readiness, driver availability, and component health."""
    try:
        service = get_network_service()
        health = service.get_health()
        return jsonify({
            "success": True,
            "health": health,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ==================== Module 5: Alerts API Endpoints ====================

@network_monitor_bp.route("/alerts", methods=["GET"])
def get_alerts():
    """Retrieve bounded in-memory security alerts filtered by parameters."""
    try:
        severity = request.args.get("severity")
        status = request.args.get("status")
        category = request.args.get("category")
        search = request.args.get("search")
        limit = request.args.get("limit", default=100, type=int)

        service = get_network_service()
        alerts = service.get_alerts(
            severity=severity,
            status=status,
            category=category,
            search=search,
            limit=limit,
        )
        return jsonify({
            "success": True,
            "alerts": alerts,
            "count": len(alerts),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/alerts/summary", methods=["GET"])
def get_alerts_summary():
    """Retrieve counts of alerts categorized by severity and status."""
    try:
        service = get_network_service()
        summary = service.get_alerts_summary()
        return jsonify({
            "success": True,
            "summary": summary,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/alerts/<alert_id>", methods=["GET"])
def get_alert_detail(alert_id):
    """Retrieve detailed information and evidence for an individual alert."""
    try:
        service = get_network_service()
        alert = service.get_alert(alert_id)
        if not alert:
            return jsonify({"success": False, "error": f"Alert '{alert_id}' not found"}), 404
        return jsonify({
            "success": True,
            "alert": alert,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/alerts/<alert_id>/acknowledge", methods=["POST"])
def acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    try:
        service = get_network_service()
        res = service.acknowledge_alert(alert_id)
        status_code = 200 if res.get("success") else 400
        return jsonify(res), status_code
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/alerts/<alert_id>/investigate", methods=["POST"])
def investigate_alert(alert_id):
    """Transition alert to investigating status with optional analyst notes."""
    try:
        data = request.get_json(silent=True) or {}
        notes = data.get("notes")
        service = get_network_service()
        res = service.investigate_alert(alert_id, notes=notes)
        status_code = 200 if res.get("success") else 400
        return jsonify(res), status_code
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/alerts/<alert_id>/resolve", methods=["POST"])
def resolve_alert(alert_id):
    """Resolve an alert with closing notes."""
    try:
        data = request.get_json(silent=True) or {}
        notes = data.get("notes")
        service = get_network_service()
        res = service.resolve_alert(alert_id, notes=notes)
        status_code = 200 if res.get("success") else 400
        return jsonify(res), status_code
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/alerts/<alert_id>/false-positive", methods=["POST"])
def mark_false_positive(alert_id):
    """Mark an alert as false positive with analyst rationale."""
    try:
        data = request.get_json(silent=True) or {}
        reason = data.get("reason")
        service = get_network_service()
        res = service.mark_false_positive(alert_id, reason=reason)
        status_code = 200 if res.get("success") else 400
        return jsonify(res), status_code
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ==================== Module 4: Detection Config Endpoints ====================

@network_monitor_bp.route("/detection/config", methods=["GET"])
def get_detection_config():
    """Retrieve rule configuration and threshold parameters."""
    try:
        service = get_network_service()
        rules = service.get_detection_config()
        return jsonify({
            "success": True,
            "rules": rules,
            "count": len(rules),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/detection/config", methods=["POST"])
def update_detection_config():
    """Update runtime configuration for a specific detection rule."""
    try:
        data = request.get_json(silent=True) or {}
        rule_id = data.get("rule_id")
        config = data.get("config", {})
        if not rule_id:
            return jsonify({"success": False, "error": "Missing 'rule_id' parameter."}), 400

        service = get_network_service()
        res = service.update_detection_config(rule_id, config)
        status_code = 200 if res.get("success") else 400
        return jsonify(res), status_code
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ==================== Module 6: Advanced Analytics Endpoint ====================

@network_monitor_bp.route("/analytics", methods=["GET"])
def get_analytics():
    """Retrieve incremental session-level IP aggregation, hourly traffic, and process correlation."""
    try:
        limit_ips = request.args.get("limit_ips", default=15, type=int)
        service = get_network_service()
        analytics = service.get_analytics(limit_ips=limit_ips)
        return jsonify({
            "success": True,
            "analytics": analytics,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ==================== Module 7: Agent Management Endpoints ====================

@network_monitor_bp.route("/agent/info", methods=["GET"])
def get_agent_info():
    """Retrieve centralized agent version, operating system, and memory buffer diagnostics."""
    try:
        service = get_network_service()
        info = service.get_agent_info()
        return jsonify({
            "success": True,
            "info": info,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/agent/version", methods=["GET"])
def get_agent_version():
    """Retrieve centralized agent version constant."""
    try:
        service = get_network_service()
        version = service.get_agent_version()
        return jsonify({
            "success": True,
            "version": version,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/agent/deployment", methods=["GET"])
def get_agent_deployment():
    """Retrieve local operational status and server deployment readiness."""
    try:
        service = get_network_service()
        deployment = service.get_agent_deployment()
        return jsonify({
            "success": True,
            "deployment": deployment,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/agent/config", methods=["GET"])
def get_agent_config():
    """Retrieve runtime agent configuration."""
    try:
        service = get_network_service()
        config = service.get_agent_config()
        return jsonify({
            "success": True,
            "config": config,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@network_monitor_bp.route("/agent/config", methods=["POST"])
def update_agent_config():
    """Update runtime agent configuration with privacy guarantees."""
    try:
        data = request.get_json(silent=True) or {}
        service = get_network_service()
        res = service.update_agent_config(data)
        return jsonify(res)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
