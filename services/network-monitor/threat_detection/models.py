"""
Data models for the CyberShield Threat Detection Engine.
Defines findings, severities, and detection categories.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import time


class DetectionSeverity:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    ALL = (LOW, MEDIUM, HIGH, CRITICAL)


class DetectionCategory:
    NETWORK_RECONNAISSANCE = "NETWORK_RECONNAISSANCE"
    RECONNAISSANCE = "NETWORK_RECONNAISSANCE"
    PORT_SCAN = "NETWORK_RECONNAISSANCE"
    SUSPICIOUS_CONNECTION = "SUSPICIOUS_CONNECTION"
    COMMAND_AND_CONTROL = "SUSPICIOUS_CONNECTION"
    OUTBOUND_ANOMALY = "OUTBOUND_ANOMALY"
    TRAFFIC_ANOMALY = "TRAFFIC_ANOMALY"
    EXFILTRATION = "TRAFFIC_ANOMALY"
    DNS_ANOMALY = "DNS_ANOMALY"


@dataclass
class DetectionFinding:
    """
    Structured finding produced by an active threat detection rule.
    Strictly in-memory and derived purely from observed packet and socket telemetry.
    """
    rule_id: str
    rule_name: str
    category: str
    severity: str
    confidence: float  # 0.0 to 1.0
    description: str
    reason: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_ports: List[int] = field(default_factory=list)
    protocol: Optional[str] = None
    process_name: Optional[str] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    _custom_fingerprint: Optional[str] = None

    @property
    def fingerprint(self) -> str:
        """
        Unique fingerprint identifying the detection context for deduplication.
        """
        if self._custom_fingerprint:
            return self._custom_fingerprint
        src = self.source_ip or "any"
        dst = self.destination_ip or "any"
        proto = self.protocol or "any"
        return f"{self.rule_id}:{src}->{dst}:{proto}"

    @fingerprint.setter
    def fingerprint(self, val: str) -> None:
        self._custom_fingerprint = val

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["fingerprint"] = self.fingerprint
        return res
