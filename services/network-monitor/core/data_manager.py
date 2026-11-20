"""
In-Memory Data Manager for CyberShield Network Monitor.
Provides strictly temporary, thread-safe, bounded queues and rolling statistics.
No persistent packet captures, no payloads, no database storage.
"""

import time
import threading
from collections import deque
from typing import Dict, List, Any, Optional, Deque
from models.packet_event import PacketEvent
from models.connection import Connection
from models.traffic_stats import BandwidthStats, PacketCaptureStats
from alerts.alert_manager import AlertManager
from core.analytics_engine import AnalyticsEngine
from utils.logger import logger


class DataManager:
    """
    Central in-memory store for real-time monitoring events and telemetry.
    Thread-safe and strictly bounded to prevent unbounded memory growth.
    """

    def __init__(
        self,
        max_packet_events: int = 5000,
        max_connections: int = 2000,
        max_alerts: int = 500,
    ):
        self._lock = threading.RLock()
        self.max_packet_events = max_packet_events
        self.max_connections = max_connections
        self.max_alerts = max_alerts

        # Bounded ring buffers
        self.packet_events: Deque[PacketEvent] = deque(maxlen=max_packet_events)
        self.alerts: Deque[Dict[str, Any]] = deque(maxlen=max_alerts)

        # In-Memory Alert and Analytics Managers
        self.alert_manager: AlertManager = AlertManager(max_alerts=max_alerts)
        self.analytics_engine: AnalyticsEngine = AnalyticsEngine()

        # Connection and metric maps
        self.connections: Dict[str, Connection] = {}
        self.traffic_stats: Dict[str, Any] = {}
        self.protocol_stats: Dict[str, int] = {}
        self.direction_stats: Dict[str, int] = {"inbound": 0, "outbound": 0, "internal": 0, "unknown": 0}

        # Rolling packet counters for packets-per-second calculation
        # Timestamps of packets received in recent window (pruned to last 5 seconds)
        self._packet_timestamps: Deque[float] = deque()
        self._total_packets_captured: int = 0
        self._dropped_packets: int = 0

    def add_packet(self, event: PacketEvent) -> None:
        """
        Record a normalized packet event into memory.
        Updates protocol and direction tallies and rolling rate counters.
        """
        if not event:
            return

        with self._lock:
            self._total_packets_captured += 1
            self.packet_events.append(event)

            # Record in analytics engine
            self.analytics_engine.record_packet(event)

            # Protocol stats
            proto = event.protocol or "UNKNOWN"
            self.protocol_stats[proto] = self.protocol_stats.get(proto, 0) + 1

            # Direction stats
            direction = event.direction or "unknown"
            self.direction_stats[direction] = self.direction_stats.get(direction, 0) + 1

            # Rolling timestamp registration
            now = event.timestamp or time.time()
            self._packet_timestamps.append(now)

            # Prune rolling timestamps older than 5 seconds
            cutoff = now - 5.0
            while self._packet_timestamps and self._packet_timestamps[0] < cutoff:
                self._packet_timestamps.popleft()

    def record_drop(self, count: int = 1) -> None:
        """Record packets dropped by the capture pipeline due to buffer saturation."""
        with self._lock:
            self._dropped_packets += count

    def update_connections(self, connections: List[Connection]) -> None:
        """Update active connection snapshot (bounded to max_connections)."""
        with self._lock:
            conn_dict = {}
            for c in connections[: self.max_connections]:
                conn_dict[c.key] = c
            self.connections = conn_dict

    def update_traffic(self, stats: Dict[str, Any]) -> None:
        """Update bandwidth and interface traffic counters."""
        with self._lock:
            self.traffic_stats = dict(stats)
            # Record speed sample for session analytics averages and peaks
            up_mbps = float(stats.get("upload_mbps", 0.0) or 0.0)
            down_mbps = float(stats.get("download_mbps", 0.0) or 0.0)
            self.analytics_engine.record_bandwidth_sample(up_mbps, down_mbps)

    def add_alert(self, alert: Dict[str, Any]) -> None:
        """Add an operational or security alert to the bounded alert buffer."""
        with self._lock:
            self.alerts.append(alert)

    def get_recent_packets(self, limit: int = 100) -> List[PacketEvent]:
        """Retrieve recent packet events up to limit."""
        with self._lock:
            count = min(limit, len(self.packet_events))
            # Return newest first or chronological based on slice
            return list(self.packet_events)[-count:]

    def get_active_connections(self) -> List[Connection]:
        """Retrieve current snapshot of active connections."""
        with self._lock:
            return list(self.connections.values())

    def get_packet_rate(self) -> float:
        """Calculate rolling packets per second based on the sliding window."""
        with self._lock:
            now = time.time()
            cutoff = now - 5.0
            while self._packet_timestamps and self._packet_timestamps[0] < cutoff:
                self._packet_timestamps.popleft()

            window_len = len(self._packet_timestamps)
            if window_len == 0:
                return 0.0
            earliest = self._packet_timestamps[0]
            delta = max(1.0, now - earliest)
            return round(window_len / delta, 2)

    def get_capture_stats(self, interface: str) -> PacketCaptureStats:
        """Get structured capture metrics for the given interface."""
        with self._lock:
            return PacketCaptureStats(
                interface=interface,
                total_packets_captured=self._total_packets_captured,
                packets_per_sec=self.get_packet_rate(),
                dropped_packets=self._dropped_packets,
                protocol_distribution=dict(self.protocol_stats),
                direction_distribution=dict(self.direction_stats),
                timestamp=time.time(),
            )

    def get_summary(self, interface: str) -> Dict[str, Any]:
        """Aggregate high-level overview for dashboard and console display."""
        with self._lock:
            return {
                "interface": interface,
                "total_packets_captured": self._total_packets_captured,
                "packets_per_second": self.get_packet_rate(),
                "dropped_packets": self._dropped_packets,
                "active_connections_count": len(self.connections),
                "buffered_packets_count": len(self.packet_events),
                "max_packet_buffer": self.max_packet_events,
                "protocol_distribution": dict(self.protocol_stats),
                "direction_distribution": dict(self.direction_stats),
                "traffic_stats": dict(self.traffic_stats),
            }

    def clear_all(self) -> None:
        """Purge all in-memory buffers and state on agent shutdown."""
        with self._lock:
            self.packet_events.clear()
            self.alerts.clear()
            self.alert_manager.clear()
            self.analytics_engine.reset()
            self.connections.clear()
            self.traffic_stats.clear()
            self.protocol_stats.clear()
            self.direction_stats = {"inbound": 0, "outbound": 0, "internal": 0, "unknown": 0}
            self._packet_timestamps.clear()
            self._total_packets_captured = 0
            self._dropped_packets = 0
