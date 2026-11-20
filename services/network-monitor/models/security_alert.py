"""
Security Alert data model for CyberShield Network Monitor.
Standard normalized representation of security detection findings.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
import time
import uuid


class AlertStatus:
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

    ALL = (NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE)


@dataclass
class SecurityAlert:
    """
    Representation of an active or acknowledged security alert.
    Strictly in-memory and temporary for the duration of the monitoring session.
    """
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: float
    description: str
    reason: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_ports: List[int] = field(default_factory=list)
    protocol: Optional[str] = None
    process_name: Optional[str] = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    timestamp: float = field(default_factory=time.time)
    occurrence_count: int = 1
    status: str = AlertStatus.NEW
    acknowledgement_timestamp: Optional[float] = None
    investigation_notes: Optional[str] = None
    resolution_notes: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    fingerprint: Optional[str] = None
    false_positive_reason: Optional[str] = None

    @property
    def notes(self) -> Optional[str]:
        return self.investigation_notes or self.resolution_notes

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["notes"] = self.notes
        return d

    def acknowledge(self) -> None:
        self.status = AlertStatus.ACKNOWLEDGED
        self.acknowledgement_timestamp = time.time()

    def investigate(self, notes: Optional[str] = None) -> None:
        self.status = AlertStatus.INVESTIGATING
        if notes:
            self.investigation_notes = notes

    def resolve(self, notes: Optional[str] = None) -> None:
        self.status = AlertStatus.RESOLVED
        if notes:
            self.resolution_notes = notes

    def mark_false_positive(self, reason: Optional[str] = None) -> None:
        self.status = AlertStatus.FALSE_POSITIVE
        if reason:
            self.false_positive_reason = reason
            self.resolution_notes = f"False positive: {reason}"
