"""
Threat detection rules package.
"""

from .connection_attempts import RepeatedConnectionAttemptsRule
from .port_scan_indicator import PortScanIndicatorRule
from .outbound_anomaly import UnusualOutboundConnectionRule
from .traffic_spike import TrafficSpikeRule
from .dns_anomaly import DNSAnomalyRule

__all__ = [
    "RepeatedConnectionAttemptsRule",
    "PortScanIndicatorRule",
    "UnusualOutboundConnectionRule",
    "TrafficSpikeRule",
    "DNSAnomalyRule",
]
