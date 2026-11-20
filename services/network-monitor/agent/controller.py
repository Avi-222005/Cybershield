"""
Agent Controller for CyberShield Network Monitor.
Orchestrates monitoring components, background worker threads, lifecycle state transitions,
and component health reporting.
"""

import time
import threading
from typing import Dict, Any, Optional, Set

from models.traffic_stats import (
    ComponentHealth,
    AgentStatusReport,
    BandwidthStats,
    PacketCaptureStats,
)
from core.interface_manager import InterfaceManager
from core.bandwidth_monitor import BandwidthMonitor
from core.connection_monitor import ConnectionMonitor
from core.packet_capture import PacketCaptureEngine
from core.data_manager import DataManager
from threat_detection.engine import ThreatDetectionEngine
from agent.config import load_config
from agent.version import AGENT_VERSION
from utils.logger import logger
from utils.system_checks import check_system_readiness


class AgentController:
    """
    Central controller managing lifecycle, thread coordination, and telemetry aggregation.
    """

    STATES = ("STOPPED", "INITIALIZING", "RUNNING", "STOPPING", "ERROR")

    def __init__(self, config_overrides: Optional[Dict[str, Any]] = None):
        self.config = load_config(config_overrides)
        self.state: str = "STOPPED"
        self.start_time: Optional[float] = None
        self._stop_event = threading.Event()
        self._state_lock = threading.Lock()

        # Component instances
        self.interface_manager = InterfaceManager()
        self.bandwidth_monitor = BandwidthMonitor()
        self.connection_monitor = ConnectionMonitor()
        self.data_manager = DataManager(
            max_packet_events=self.config["memory"]["max_packet_events"],
            max_connections=self.config["memory"]["max_connections"],
            max_alerts=self.config["memory"]["max_alerts"],
        )
        self.packet_capture = PacketCaptureEngine(
            tshark_path=self.config.get("tshark_path"),
            force_adapter=self.config["monitoring"].get("force_adapter"),
            fallback_to_synthetic=self.config["monitoring"].get("fallback_to_synthetic", True),
        )

        # Active monitoring target
        self.selected_interface: Optional[str] = None
        self.interface_ips: Set[str] = set()

        # Threat Detection & In-Memory Alert Management
        self.threat_detection = ThreatDetectionEngine()
        self.alert_manager = self.data_manager.alert_manager
        self.analytics_engine = self.data_manager.analytics_engine

        # Component health tracking
        self.component_health: Dict[str, ComponentHealth] = {
            "interface_manager": ComponentHealth(name="interface_manager", status="HEALTHY"),
            "bandwidth_monitor": ComponentHealth(name="bandwidth_monitor", status="HEALTHY"),
            "connection_monitor": ComponentHealth(name="connection_monitor", status="HEALTHY"),
            "packet_capture": ComponentHealth(name="packet_capture", status="HEALTHY"),
            "threat_detection": ComponentHealth(name="threat_detection", status="HEALTHY"),
            "data_manager": ComponentHealth(name="data_manager", status="HEALTHY"),
        }

        # Worker threads
        self._bandwidth_thread: Optional[threading.Thread] = None
        self._connection_thread: Optional[threading.Thread] = None
        self._aggregator_thread: Optional[threading.Thread] = None
        self._detection_thread: Optional[threading.Thread] = None

    def _set_state(self, new_state: str) -> None:
        with self._state_lock:
            self.state = new_state
            logger.info(f"Agent state changed to: {new_state}")

    def initialize(self) -> bool:
        """
        Verify prerequisites, select active network interface, and prepare data structures.
        """
        self._set_state("INITIALIZING")
        logger.info(f"Initializing {self.config['agent_name']}...")

        # System readiness check (logged for operational diagnostics)
        readiness = check_system_readiness(self.config.get("tshark_path"))
        logger.info(f"System readiness: Python={readiness['python']['version']}, TShark={readiness['tshark']['passed']}, Admin={readiness['admin']['is_admin']}")

        # Interface resolution
        target_iface = self.config["monitoring"].get("interface")
        if not target_iface or target_iface.lower() == "auto":
            selected = self.interface_manager.get_default_interface()
            if not selected:
                logger.error("No active network interface could be detected.")
                self.component_health["interface_manager"].status = "ERROR"
                self.component_health["interface_manager"].details = "No active interface found"
                self._set_state("ERROR")
                return False
            self.selected_interface = selected
            logger.info(f"Auto-selected default active network interface: '{self.selected_interface}'")
        else:
            details = self.interface_manager.get_interface_details(target_iface)
            if not details:
                logger.warning(f"Configured interface '{target_iface}' not found. Falling back to default.")
                self.selected_interface = self.interface_manager.get_default_interface()
            else:
                self.selected_interface = target_iface

        # Cache IP addresses for packet direction inference
        self.interface_ips = self.interface_manager.get_interface_ips(self.selected_interface)
        logger.info(f"Interface '{self.selected_interface}' IPs: {list(self.interface_ips)}")

        # Configure bandwidth monitor
        self.bandwidth_monitor.set_interface(self.selected_interface)

        return True

    def start(self) -> bool:
        """
        Start all background monitoring worker threads.
        """
        if self.state == "RUNNING":
            logger.warning("Agent is already running.")
            return True

        if self.state != "INITIALIZING":
            if not self.initialize():
                return False

        self._stop_event.clear()
        self.start_time = time.time()
        self.analytics_engine.start_session()
        monitoring_cfg = self.config["monitoring"]
        intervals = self.config["intervals"]

        # 1. Start Packet Capture (Thread 1)
        if monitoring_cfg.get("capture_packets", True):
            try:
                def on_packet(event):
                    self.data_manager.add_packet(event)

                started = self.packet_capture.start_capture(
                    self.selected_interface,
                    callback=on_packet,
                    local_ips=self.interface_ips,
                )
                if started:
                    self.component_health["packet_capture"].status = "HEALTHY"
                    self.component_health["packet_capture"].last_updated = time.time()
                else:
                    self.component_health["packet_capture"].status = "DEGRADED"
                    self.component_health["packet_capture"].details = "Capture adapter failed to start"
            except Exception as e:
                logger.error(f"Error starting packet capture: {e}")
                self.component_health["packet_capture"].status = "ERROR"
                self.component_health["packet_capture"].details = str(e)
                self.component_health["packet_capture"].error_count += 1
        else:
            self.component_health["packet_capture"].status = "DISABLED"

        # 2. Start Bandwidth Monitoring (Thread 2)
        if monitoring_cfg.get("monitor_bandwidth", True):
            def bandwidth_worker():
                interval = max(0.5, intervals.get("bandwidth", 1.0))
                logger.info(f"Bandwidth monitor thread running (interval={interval}s)")
                while not self._stop_event.is_set():
                    try:
                        stats = self.bandwidth_monitor.update(self.selected_interface)
                        if stats:
                            self.data_manager.update_traffic(stats.to_dict())
                            self.component_health["bandwidth_monitor"].status = "HEALTHY"
                            self.component_health["bandwidth_monitor"].last_updated = time.time()
                    except Exception as e:
                        logger.debug(f"Bandwidth monitor tick error: {e}")
                        self.component_health["bandwidth_monitor"].error_count += 1
                        self.component_health["bandwidth_monitor"].details = str(e)
                    self._stop_event.wait(interval)
                logger.info("Bandwidth monitor thread stopped.")

            self._bandwidth_thread = threading.Thread(
                target=bandwidth_worker,
                name="BandwidthWorker",
                daemon=True,
            )
            self._bandwidth_thread.start()
        else:
            self.component_health["bandwidth_monitor"].status = "DISABLED"

        # 3. Start Connection Monitoring (Thread 3)
        if monitoring_cfg.get("monitor_connections", True):
            def connection_worker():
                interval = max(1.0, intervals.get("connections", 3.0))
                logger.info(f"Connection monitor thread running (interval={interval}s)")
                while not self._stop_event.is_set():
                    try:
                        conns = self.connection_monitor.get_active_connections()
                        self.data_manager.update_connections(conns)
                        self.component_health["connection_monitor"].status = "HEALTHY"
                        self.component_health["connection_monitor"].last_updated = time.time()
                    except Exception as e:
                        logger.debug(f"Connection monitor tick error: {e}")
                        self.component_health["connection_monitor"].error_count += 1
                        self.component_health["connection_monitor"].details = str(e)
                    self._stop_event.wait(interval)
                logger.info("Connection monitor thread stopped.")

            self._connection_thread = threading.Thread(
                target=connection_worker,
                name="ConnectionWorker",
                daemon=True,
            )
            self._connection_thread.start()
        else:
            self.component_health["connection_monitor"].status = "DISABLED"

        # 4. Start Telemetry Aggregator & Health Checker (Thread 4)
        def aggregator_worker():
            agg_interval = max(0.5, intervals.get("aggregation", 1.0))
            health_interval = max(2.0, intervals.get("health_check", 5.0))
            last_health_check = time.time()

            while not self._stop_event.is_set():
                now = time.time()
                try:
                    # Update rolling capture metrics
                    capture_stats = self.data_manager.get_capture_stats(self.selected_interface or "")
                    # Health check cycle
                    if (now - last_health_check) >= health_interval:
                        last_health_check = now
                        self._check_component_health()
                except Exception as e:
                    logger.debug(f"Aggregator loop exception: {e}")

                self._stop_event.wait(agg_interval)
            logger.info("Aggregator thread stopped.")

        self._aggregator_thread = threading.Thread(
            target=aggregator_worker,
            name="AggregatorWorker",
            daemon=True,
        )
        self._aggregator_thread.start()

        # 5. Start Threat Detection (Thread 5)
        if monitoring_cfg.get("threat_detection", True):
            def detection_worker():
                interval = max(0.5, intervals.get("threat_detection", 1.0))
                logger.info(f"Threat detection worker running (interval={interval}s)")
                while not self._stop_event.is_set():
                    try:
                        telemetry = {
                            "recent_packets": self.data_manager.get_recent_packets(limit=200),
                            "connections": self.data_manager.get_active_connections(),
                            "traffic": self.data_manager.traffic_stats,
                            "protocols": self.data_manager.protocol_stats,
                        }
                        findings = self.threat_detection.analyze_telemetry(telemetry)
                        if findings:
                            for f in findings:
                                alert = self.alert_manager.process_finding(f)
                                self.data_manager.add_alert(alert.to_dict())
                        self.component_health["threat_detection"].status = "HEALTHY"
                        self.component_health["threat_detection"].last_updated = time.time()
                    except Exception as e:
                        logger.debug(f"Threat detection tick error: {e}")
                        self.component_health["threat_detection"].error_count += 1
                        self.component_health["threat_detection"].details = str(e)
                    self._stop_event.wait(interval)
                logger.info("Threat detection thread stopped.")

            self._detection_thread = threading.Thread(
                target=detection_worker,
                name="ThreatDetectionWorker",
                daemon=True,
            )
            self._detection_thread.start()
        else:
            self.component_health["threat_detection"].status = "DISABLED"

        self._set_state("RUNNING")
        logger.info("CyberShield Monitoring Agent is now RUNNING.")
        return True

    def _check_component_health(self) -> None:
        """Periodic health verification of active subsystems."""
        now = time.time()

        # Check packet capture
        if self.config["monitoring"].get("capture_packets", True):
            status = self.packet_capture.get_capture_status()
            if status.get("is_running"):
                self.component_health["packet_capture"].status = "HEALTHY"
                self.component_health["packet_capture"].details = f"Active ({status.get('adapter')})"
            else:
                if self.state == "RUNNING":
                    self.component_health["packet_capture"].status = "DEGRADED"
                    self.component_health["packet_capture"].details = status.get("error") or "Capture stopped unexpectedly"

        # Check interface existence
        if self.selected_interface:
            details = self.interface_manager.get_interface_details(self.selected_interface)
            if not details or not details.get("is_up"):
                self.component_health["interface_manager"].status = "DEGRADED"
                self.component_health["interface_manager"].details = f"Interface {self.selected_interface} appears DOWN or disconnected"
            else:
                self.component_health["interface_manager"].status = "HEALTHY"

    def stop(self) -> None:
        """
        Gracefully stop all monitoring components within 5 seconds.
        """
        if self.state in ("STOPPED", "STOPPING"):
            return

        self._set_state("STOPPING")
        logger.info("Stopping CyberShield Monitoring Agent...")
        self._stop_event.set()

        # Stop packet capture engine first
        try:
            self.packet_capture.stop_capture()
        except Exception as e:
            logger.debug(f"Error stopping packet capture: {e}")

        # Wait for worker threads (budget max 2 seconds per thread)
        threads = [self._bandwidth_thread, self._connection_thread, self._aggregator_thread, self._detection_thread]
        for t in threads:
            if t and t.is_alive():
                t.join(timeout=1.5)

        # Clear in-memory buffers to guarantee zero data retention
        self.data_manager.clear_all()
        self.threat_detection.reset()
        self._set_state("STOPPED")
        logger.info("CyberShield Monitoring Agent stopped cleanly. In-memory data cleared.")

    def get_status(self) -> AgentStatusReport:
        """
        Retrieve structured health and status report across all components.
        """
        uptime = (time.time() - self.start_time) if (self.start_time and self.state == "RUNNING") else 0.0
        bw_stats = self.bandwidth_monitor.get_latest_stats(self.selected_interface)
        cap_stats = self.data_manager.get_capture_stats(self.selected_interface or "")
        active_conns = self.data_manager.get_active_connections()

        buffer_usage = {
            "packet_events": len(self.data_manager.packet_events),
            "max_packet_events": self.data_manager.max_packet_events,
            "connections": len(self.data_manager.connections),
            "alerts": len(self.data_manager.alerts),
        }

        return AgentStatusReport(
            agent_name=self.config["agent_name"],
            state=self.state,
            uptime_seconds=round(uptime, 1),
            monitored_interface=self.selected_interface,
            bandwidth=bw_stats,
            capture=cap_stats,
            active_connections_count=len(active_conns),
            memory_buffer_usage=buffer_usage,
            components=dict(self.component_health),
        )

    def get_summary(self) -> Dict[str, Any]:
        """Convenience method returning serialized status summary."""
        res = self.get_status().to_dict()
        res["agent_version"] = AGENT_VERSION
        res["alerts_summary"] = self.alert_manager.get_summary()
        return res
