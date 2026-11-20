"""
Service layer integrating CyberShield Flask application with the autonomous
Windows Network Monitor agent located in services/network-monitor.
Maintains a singleton AgentController instance with thread-safe lifecycle operations.
"""

import os
import sys
import threading
from typing import Dict, Any, List, Optional

# Ensure services/network-monitor is in sys.path
_MONITOR_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network-monitor")
if _MONITOR_DIR not in sys.path:
    sys.path.insert(0, _MONITOR_DIR)

from agent.controller import AgentController
from agent.version import AGENT_VERSION
from agent.config import AGENT_CONFIG, load_config
from core.interface_manager import InterfaceManager
from utils.system_checks import check_system_readiness


class NetworkMonitorService:
    """
    Singleton service managing the local network monitor agent lifecycle
    and providing formatted telemetry for Flask API consumers.
    """
    _instance: Optional["NetworkMonitorService"] = None
    _lock = threading.Lock()

    def __init__(self):
        self.interface_manager = InterfaceManager()
        self.controller: Optional[AgentController] = None
        self.selected_interface: Optional[str] = None
        self._lifecycle_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "NetworkMonitorService":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """List all detected network interfaces with selected flag."""
        all_ifaces = self.interface_manager.get_all_interfaces()
        default_iface = self.interface_manager.get_default_interface()
        current_sel = self.selected_interface or (
            self.controller.selected_interface if self.controller else default_iface
        )

        result = []
        for name, details in all_ifaces.items():
            result.append({
                "name": name,
                "is_up": details.get("is_up", False),
                "speed": details.get("speed", 0),
                "mtu": details.get("mtu", 0),
                "ipv4": details.get("ipv4", []),
                "ipv6": details.get("ipv6", []),
                "mac_address": details.get("mac_address"),
                "selected": name == current_sel,
                "is_default": name == default_iface,
            })
        return result

    def get_status(self) -> Dict[str, Any]:
        """Return comprehensive agent status and health."""
        if not self.controller:
            default_iface = self.interface_manager.get_default_interface()
            return {
                "state": "STOPPED",
                "uptime_seconds": 0.0,
                "monitored_interface": self.selected_interface or default_iface,
                "active_connections_count": 0,
                "memory_buffer_usage": {
                    "packet_events": 0,
                    "max_packet_events": 5000,
                    "connections": 0,
                    "alerts": 0,
                },
                "components": {
                    "interface_manager": {"name": "interface_manager", "status": "HEALTHY"},
                    "bandwidth_monitor": {"name": "bandwidth_monitor", "status": "STOPPED"},
                    "connection_monitor": {"name": "connection_monitor", "status": "STOPPED"},
                    "packet_capture": {"name": "packet_capture", "status": "STOPPED"},
                    "data_manager": {"name": "data_manager", "status": "HEALTHY"},
                },
            }

        return self.controller.get_summary()

    def start_monitoring(
        self,
        interface_name: Optional[str] = None,
        force_adapter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Start network monitoring on target interface.
        Prevents duplicate agent instances.
        """
        with self._lifecycle_lock:
            # If already running on the same interface, return current status
            if self.controller and self.controller.state == "RUNNING":
                if not interface_name or interface_name == self.controller.selected_interface:
                    return {
                        "success": True,
                        "message": "Monitoring agent is already running.",
                        "state": self.controller.state,
                        "interface": self.controller.selected_interface,
                    }
                else:
                    # Interface changed, stop existing first
                    self.controller.stop()

            # Validate interface if provided
            if interface_name and interface_name != "auto":
                details = self.interface_manager.get_interface_details(interface_name)
                if not details:
                    return {
                        "success": False,
                        "error": f"Interface '{interface_name}' not found on this system.",
                    }
                self.selected_interface = interface_name
            else:
                self.selected_interface = self.interface_manager.get_default_interface()

            # Initialize new controller
            overrides = {
                "monitoring": {
                    "interface": self.selected_interface or "auto",
                    "capture_packets": True,
                    "monitor_connections": True,
                    "monitor_bandwidth": True,
                }
            }
            if force_adapter:
                overrides["monitoring"]["force_adapter"] = force_adapter

            self.controller = AgentController(overrides)
            started = self.controller.start()

            if not started:
                return {
                    "success": False,
                    "error": "Failed to start network monitoring agent. Check permissions or interface state.",
                    "state": self.controller.state,
                }

            return {
                "success": True,
                "message": f"Network monitoring started on '{self.controller.selected_interface}'.",
                "state": self.controller.state,
                "interface": self.controller.selected_interface,
            }

    def stop_monitoring(self) -> Dict[str, Any]:
        """Gracefully stop monitoring and clear in-memory buffers."""
        with self._lifecycle_lock:
            if not self.controller or self.controller.state == "STOPPED":
                return {
                    "success": True,
                    "message": "Monitoring agent is already stopped.",
                    "state": "STOPPED",
                }

            self.controller.stop()
            return {
                "success": True,
                "message": "Network monitoring agent stopped cleanly. Temporary buffers purged.",
                "state": "STOPPED",
            }

    def get_traffic(self) -> Dict[str, Any]:
        """Return bandwidth and packet counter speeds."""
        target_iface = (
            self.controller.selected_interface
            if self.controller
            else (self.selected_interface or self.interface_manager.get_default_interface())
        )

        if not self.controller or self.controller.state != "RUNNING":
            return {
                "interface": target_iface or "N/A",
                "upload_bytes_per_sec": 0.0,
                "download_bytes_per_sec": 0.0,
                "upload_mbps": 0.0,
                "download_mbps": 0.0,
                "total_bytes_sent": 0,
                "total_bytes_received": 0,
                "packets_sent_per_sec": 0.0,
                "packets_recv_per_sec": 0.0,
                "captured_packets_per_sec": 0.0,
                "timestamp": 0.0,
                "active": False,
            }

        bw = self.controller.bandwidth_monitor.get_latest_stats(target_iface)
        cap = self.controller.data_manager.get_capture_stats(target_iface or "")

        res = bw.to_dict() if bw else {}
        res["captured_packets_per_sec"] = cap.packets_per_sec if cap else 0.0
        res["active"] = True
        return res

    def get_connections(self) -> List[Dict[str, Any]]:
        """Return current active socket connection snapshot."""
        if not self.controller:
            return []
        conns = self.controller.data_manager.get_active_connections()
        return [c.to_dict() for c in conns]

    def get_protocols(self) -> Dict[str, Any]:
        """Return observed protocol distribution and directional metrics."""
        target_iface = (
            self.controller.selected_interface
            if self.controller
            else (self.selected_interface or "")
        )
        if not self.controller:
            return {
                "protocol_distribution": {},
                "direction_distribution": {"inbound": 0, "outbound": 0, "internal": 0, "unknown": 0},
                "total_packets_captured": 0,
                "packets_per_sec": 0.0,
                "dropped_packets": 0,
            }

        cap = self.controller.data_manager.get_capture_stats(target_iface)
        return cap.to_dict()

    def get_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent bounded packet metadata events without payloads."""
        if not self.controller:
            return []
        events = self.controller.data_manager.get_recent_packets(limit=min(200, max(1, limit)))
        return [e.to_dict() for e in events]

    def get_summary(self) -> Dict[str, Any]:
        """Return aggregated dashboard snapshot for overview page."""
        target_iface = (
            self.controller.selected_interface
            if self.controller
            else (self.selected_interface or self.interface_manager.get_default_interface())
        )

        status = self.get_status()
        traffic = self.get_traffic()
        protocols = self.get_protocols()
        recent_events = self.get_events(limit=15)
        conns = self.get_connections()

        return {
            "status": status,
            "traffic": traffic,
            "protocols": protocols,
            "active_connections_count": len(conns),
            "recent_events": recent_events,
            "selected_interface": target_iface,
            "readiness": check_system_readiness(),
        }

    def get_health(self) -> Dict[str, Any]:
        """Return system readiness and component health."""
        readiness = check_system_readiness()
        status = self.get_status()
        return {
            "backend_online": True,
            "agent_state": status.get("state", "STOPPED"),
            "readiness": readiness,
            "components": status.get("components", {}),
        }

    # ==================== Module 5: Alerts API ====================

    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve bounded in-memory security alerts filtered by parameters."""
        if not self.controller:
            return []
        alerts = self.controller.alert_manager.get_alerts(
            severity=severity,
            status=status,
            category=category,
            search=search,
            limit=limit,
        )
        return [a.to_dict() for a in alerts]

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific security alert by its unique UUID."""
        if not self.controller:
            return None
        alert = self.controller.alert_manager.get_alert(alert_id)
        return alert.to_dict() if alert else None

    def acknowledge_alert(self, alert_id: str) -> Dict[str, Any]:
        """Mark an alert as acknowledged by analyst."""
        if not self.controller:
            return {"success": False, "error": "Monitoring agent is not active."}
        success = self.controller.alert_manager.acknowledge_alert(alert_id)
        if not success:
            return {"success": False, "error": f"Alert '{alert_id}' not found."}
        alert = self.controller.alert_manager.get_alert(alert_id)
        return {"success": True, "alert": alert.to_dict() if alert else None}

    def investigate_alert(self, alert_id: str, notes: Optional[str] = None) -> Dict[str, Any]:
        """Transition alert to investigating status with analyst notes."""
        if not self.controller:
            return {"success": False, "error": "Monitoring agent is not active."}
        success = self.controller.alert_manager.investigate_alert(alert_id, notes=notes)
        if not success:
            return {"success": False, "error": f"Alert '{alert_id}' not found."}
        alert = self.controller.alert_manager.get_alert(alert_id)
        return {"success": True, "alert": alert.to_dict() if alert else None}

    def resolve_alert(self, alert_id: str, notes: Optional[str] = None) -> Dict[str, Any]:
        """Resolve alert with closing notes."""
        if not self.controller:
            return {"success": False, "error": "Monitoring agent is not active."}
        success = self.controller.alert_manager.resolve_alert(alert_id, notes=notes)
        if not success:
            return {"success": False, "error": f"Alert '{alert_id}' not found."}
        alert = self.controller.alert_manager.get_alert(alert_id)
        return {"success": True, "alert": alert.to_dict() if alert else None}

    def mark_false_positive(self, alert_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """Mark alert as false positive with analyst rationale."""
        if not self.controller:
            return {"success": False, "error": "Monitoring agent is not active."}
        success = self.controller.alert_manager.mark_false_positive(alert_id, reason=reason)
        if not success:
            return {"success": False, "error": f"Alert '{alert_id}' not found."}
        alert = self.controller.alert_manager.get_alert(alert_id)
        return {"success": True, "alert": alert.to_dict() if alert else None}

    def get_alerts_summary(self) -> Dict[str, Any]:
        """Return counts of alerts categorized by severity and status."""
        if not self.controller:
            return {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "new": 0,
                "acknowledged": 0,
                "investigating": 0,
                "resolved": 0,
                "false_positive": 0,
            }
        return self.controller.alert_manager.get_summary()

    # ==================== Module 4: Detection Config ====================

    def get_detection_config(self) -> List[Dict[str, Any]]:
        """Return information and configuration status for all 5 threat detection rules."""
        if not self.controller:
            from threat_detection.engine import ThreatDetectionEngine
            temp_engine = ThreatDetectionEngine()
            return temp_engine.get_rules_info()
        return self.controller.threat_detection.get_rules_info()

    def update_detection_config(self, rule_id: str, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Update runtime thresholds or enabled flag for a detection rule."""
        if not self.controller:
            return {"success": False, "error": "Monitoring agent must be running to update runtime config."}
        success = self.controller.threat_detection.update_rule_config(rule_id, new_config)
        if not success:
            return {"success": False, "error": f"Detection rule '{rule_id}' not found."}
        return {
            "success": True,
            "message": f"Rule '{rule_id}' configuration updated successfully.",
            "rules": self.controller.threat_detection.get_rules_info(),
        }

    # ==================== Module 6: Advanced Analytics API ====================

    def get_analytics(self, limit_ips: int = 15) -> Dict[str, Any]:
        """Return session-level incremental IP aggregation, hourly buckets, and process analytics."""
        if not self.controller or self.controller.state != "RUNNING":
            return {
                "session": {
                    "start_time": 0.0,
                    "uptime_seconds": 0.0,
                    "storage_policy": "IN_MEMORY_SESSION_ONLY",
                    "data_cleared_on_stop": True,
                },
                "bandwidth": {
                    "total_bytes_sent": 0,
                    "total_bytes_received": 0,
                    "total_bytes_combined": 0,
                    "peak_upload_mbps": 0.0,
                    "peak_download_mbps": 0.0,
                    "average_upload_mbps": 0.0,
                    "average_download_mbps": 0.0,
                    "samples_count": 0,
                    "has_sufficient_samples": False,
                },
                "packets": {
                    "total_captured": 0,
                    "average_packets_per_sec": 0.0,
                    "current_packets_per_sec": 0.0,
                    "dropped_packets": 0,
                },
                "top_ips": [],
                "total_tracked_ips_count": 0,
                "processes": [],
                "protocols": {},
                "directions": {},
                "hourly_traffic": [],
            }

        conns = self.controller.data_manager.get_active_connections()
        traffic = self.controller.data_manager.traffic_stats
        cap_stats = self.controller.data_manager.get_capture_stats(self.controller.selected_interface or "").to_dict()
        return self.controller.analytics_engine.get_analytics(conns, traffic, cap_stats, limit_ips=limit_ips)

    # ==================== Module 7: Agent Management API ====================

    def get_agent_info(self) -> Dict[str, Any]:
        """Return centralized agent version, operating system, and memory buffer diagnostics."""
        status = self.get_status()
        readiness = check_system_readiness()
        return {
            "agent_name": "CyberShield Network Agent",
            "version": AGENT_VERSION,
            "platform": "windows",
            "python_version": sys.version.split()[0],
            "state": status.get("state", "STOPPED"),
            "monitored_interface": status.get("monitored_interface"),
            "uptime_seconds": status.get("uptime_seconds", 0.0),
            "memory_buffers": status.get("memory_buffer_usage", {}),
            "components": status.get("components", {}),
            "readiness": readiness,
            "privacy_policy": {
                "store_payloads": False,
                "persist_traffic": False,
                "retention_mode": "IN_MEMORY_ONLY",
                "description": "Zero persistent packet captures, no payload inspection, strictly metadata analysis.",
            },
            "threat_detection_rules_count": 5,
        }

    def get_agent_version(self) -> Dict[str, Any]:
        """Return agent version constant and compatibility info."""
        return {
            "version": AGENT_VERSION,
            "name": "CyberShield Network Agent",
            "build_date": "2026-03",
            "compatible_platforms": ["windows", "linux (future)"],
        }

    def get_agent_deployment(self) -> Dict[str, Any]:
        """Return local vs server deployment readiness."""
        current_iface = self.selected_interface or (
            self.controller.selected_interface if self.controller else None
        )
        is_active = self.controller is not None and self.controller.state == "RUNNING"
        return {
            "local": {
                "status": "operational",
                "platform": "windows",
                "description": "Local host network adapter monitor running natively in-process.",
                "interface": current_iface,
                "is_active": is_active,
            },
            "server": {
                "status": "planned",
                "platform": "linux",
                "description": "Remote Linux/Server capture agent integration planned for future release.",
                "is_active": False,
            },
        }

    def get_agent_config(self) -> Dict[str, Any]:
        """Return runtime agent configuration with privacy guarantees."""
        if self.controller:
            return self.controller.config
        return load_config()

    def update_agent_config(self, overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Update runtime configuration while strictly enforcing immutable privacy invariants."""
        # Enforce privacy invariants
        if "privacy" in overrides:
            overrides["privacy"]["store_payloads"] = False
            overrides["privacy"]["persist_traffic"] = False

        if self.controller:
            # Deep update controller config
            def deep_update(d, u):
                for k, v in u.items():
                    if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                        deep_update(d[k], v)
                    else:
                        d[k] = v
            deep_update(self.controller.config, overrides)
            self.controller.config["privacy"]["store_payloads"] = False
            self.controller.config["privacy"]["persist_traffic"] = False
            return {
                "success": True,
                "message": "Agent configuration updated.",
                "config": self.controller.config,
            }
        return {
            "success": True,
            "message": "Configuration validated (agent not currently running).",
            "config": load_config(overrides),
        }


# Singleton accessor
def get_network_service() -> NetworkMonitorService:
    return NetworkMonitorService.get_instance()
