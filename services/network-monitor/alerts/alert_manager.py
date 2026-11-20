"""
Alert Manager for CyberShield Network Monitor.
Receives detection findings from ThreatDetectionEngine, performs deduplication,
tracks occurrence counts, and manages the in-memory security alert lifecycle.
"""

import threading
import time
from collections import deque
from typing import Dict, Any, List, Optional, Deque
from models.security_alert import SecurityAlert, AlertStatus
from threat_detection.models import DetectionFinding, DetectionSeverity


class AlertManager:
    """
    In-memory alert manager with thread-safe deduplication and state transitions.
    """

    def __init__(self, max_alerts: int = 500, deduplication_cooldown: float = 120.0):
        self._lock = threading.RLock()
        self.max_alerts = max_alerts
        self.deduplication_cooldown = deduplication_cooldown

        # Bounded ring buffer of alerts
        self._alerts_list: Deque[SecurityAlert] = deque(maxlen=max_alerts)
        # ID lookup map
        self._alerts_by_id: Dict[str, SecurityAlert] = {}
        # Fingerprint -> alert_id for active deduplication
        self._fingerprint_map: Dict[str, str] = {}

    def process_finding(self, finding: DetectionFinding) -> SecurityAlert:
        """
        Process a detection finding into an alert, updating existing alerts if within deduplication window.
        """
        with self._lock:
            now = time.time()
            fp = finding.fingerprint

            existing_id = self._fingerprint_map.get(fp)
            if existing_id and existing_id in self._alerts_by_id:
                existing = self._alerts_by_id[existing_id]
                # If within cooldown or not resolved, update occurrence count and last_seen
                if (now - existing.last_seen) < self.deduplication_cooldown or existing.status != AlertStatus.RESOLVED:
                    existing.last_seen = now
                    existing.occurrence_count += 1
                    # Merge destination ports if any
                    for p in finding.destination_ports:
                        if p not in existing.destination_ports:
                            existing.destination_ports.append(p)
                    # Update evidence
                    existing.evidence.update(finding.evidence)
                    return existing

            # Create new alert
            alert = SecurityAlert(
                rule_id=finding.rule_id,
                title=finding.rule_name,
                category=finding.category,
                severity=finding.severity,
                confidence=finding.confidence,
                description=finding.description,
                reason=finding.reason,
                source_ip=finding.source_ip,
                destination_ip=finding.destination_ip,
                destination_ports=list(finding.destination_ports),
                protocol=finding.protocol,
                process_name=finding.process_name,
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                timestamp=finding.timestamp,
                occurrence_count=1,
                status=AlertStatus.NEW,
                evidence=dict(finding.evidence),
                fingerprint=fp,
            )

            # Store in ring buffer and maps
            self._alerts_list.append(alert)
            self._alerts_by_id[alert.alert_id] = alert
            self._fingerprint_map[fp] = alert.alert_id

            # Prune ID map if buffer drops oldest alerts
            if len(self._alerts_by_id) > self.max_alerts * 2:
                valid_ids = set(a.alert_id for a in self._alerts_list)
                self._alerts_by_id = {aid: a for aid, a in self._alerts_by_id.items() if aid in valid_ids}

            return alert

    def process_findings(self, findings: List[DetectionFinding]) -> List[SecurityAlert]:
        """Batch process detection findings."""
        with self._lock:
            return [self.process_finding(f) for f in findings]

    def get_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        """Retrieve a specific alert by ID."""
        with self._lock:
            return self._alerts_by_id.get(alert_id)

    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
    ) -> List[SecurityAlert]:
        """Filter and retrieve alerts sorted chronologically (newest first)."""
        with self._lock:
            filtered = list(self._alerts_list)

        if severity and severity.upper() != "ALL":
            filtered = [a for a in filtered if a.severity.upper() == severity.upper()]

        if status and status.upper() != "ALL":
            filtered = [a for a in filtered if a.status.upper() == status.upper()]

        if category and category.upper() != "ALL":
            filtered = [a for a in filtered if a.category.upper() == category.upper()]

        if search:
            q = search.lower().strip()
            filtered = [
                a for a in filtered
                if q in a.title.lower()
                or q in a.description.lower()
                or (a.source_ip and q in a.source_ip.lower())
                or (a.destination_ip and q in a.destination_ip.lower())
                or (a.rule_id and q in a.rule_id.lower())
            ]

        # Sort newest first
        filtered.sort(key=lambda a: a.last_seen, reverse=True)
        return filtered[:max(1, limit)]

    def acknowledge_alert(self, alert_id: str) -> bool:
        with self._lock:
            alert = self._alerts_by_id.get(alert_id)
            if not alert:
                return False
            alert.acknowledge()
            return True

    def investigate_alert(self, alert_id: str, notes: Optional[str] = None) -> bool:
        with self._lock:
            alert = self._alerts_by_id.get(alert_id)
            if not alert:
                return False
            alert.investigate(notes)
            return True

    def resolve_alert(self, alert_id: str, notes: Optional[str] = None) -> bool:
        with self._lock:
            alert = self._alerts_by_id.get(alert_id)
            if not alert:
                return False
            alert.resolve(notes)
            return True

    def mark_false_positive(self, alert_id: str, reason: Optional[str] = None) -> bool:
        with self._lock:
            alert = self._alerts_by_id.get(alert_id)
            if not alert:
                return False
            alert.mark_false_positive(reason)
            return True

    def get_summary(self) -> Dict[str, Any]:
        """Aggregate alert counts by severity and status."""
        with self._lock:
            alerts = list(self._alerts_list)

        counts = {
            "total": len(alerts),
            "critical": sum(1 for a in alerts if a.severity == DetectionSeverity.CRITICAL),
            "high": sum(1 for a in alerts if a.severity == DetectionSeverity.HIGH),
            "medium": sum(1 for a in alerts if a.severity == DetectionSeverity.MEDIUM),
            "low": sum(1 for a in alerts if a.severity == DetectionSeverity.LOW),
            "new": sum(1 for a in alerts if a.status == AlertStatus.NEW),
            "acknowledged": sum(1 for a in alerts if a.status == AlertStatus.ACKNOWLEDGED),
            "investigating": sum(1 for a in alerts if a.status == AlertStatus.INVESTIGATING),
            "resolved": sum(1 for a in alerts if a.status == AlertStatus.RESOLVED),
            "false_positive": sum(1 for a in alerts if a.status == AlertStatus.FALSE_POSITIVE),
        }
        return counts

    def clear(self) -> None:
        """Purge all in-memory alerts on session shutdown."""
        with self._lock:
            self._alerts_list.clear()
            self._alerts_by_id.clear()
            self._fingerprint_map.clear()
