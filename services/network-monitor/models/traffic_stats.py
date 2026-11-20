"""
Traffic, bandwidth, and health statistics models for CyberShield Network Monitor.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional


@dataclass
class BandwidthStats:
    """
    OS-level network interface traffic counters and calculated transmission speeds.
    """
    interface: str
    upload_bytes_per_sec: float = 0.0
    download_bytes_per_sec: float = 0.0
    upload_mbps: float = 0.0
    download_mbps: float = 0.0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    packets_sent_per_sec: float = 0.0
    packets_recv_per_sec: float = 0.0
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PacketCaptureStats:
    """
    Real-time statistics of packets observed directly by the capture engine.
    """
    interface: str
    total_packets_captured: int = 0
    packets_per_sec: float = 0.0
    dropped_packets: int = 0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    direction_distribution: Dict[str, int] = field(default_factory=dict)
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentHealth:
    """
    Health state of an individual monitoring component.
    """
    name: str
    status: str  # 'HEALTHY', 'DEGRADED', 'ERROR', 'STOPPED', 'DISABLED'
    details: Optional[str] = None
    last_updated: float = 0.0
    error_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AgentStatusReport:
    """
    Aggregated health and status report across all monitoring subsystems.
    """
    agent_name: str
    state: str  # 'STOPPED', 'INITIALIZING', 'RUNNING', 'STOPPING', 'ERROR'
    uptime_seconds: float
    monitored_interface: Optional[str]
    bandwidth: Optional[BandwidthStats]
    capture: Optional[PacketCaptureStats]
    active_connections_count: int
    memory_buffer_usage: Dict[str, int]
    components: Dict[str, ComponentHealth]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
