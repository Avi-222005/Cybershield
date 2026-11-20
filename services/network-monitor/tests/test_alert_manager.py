"""
Unit tests for CyberShield AlertManager.
Verifies alert creation, deduplication windows, occurrence counting, status lifecycle, and in-memory purging.
"""

import time
import unittest
from alerts.alert_manager import AlertManager
from models.security_alert import AlertStatus
from threat_detection.models import DetectionFinding, DetectionSeverity, DetectionCategory


class TestAlertManager(unittest.TestCase):

    def setUp(self):
        self.mgr = AlertManager(max_alerts=100, deduplication_cooldown=60.0)

    def _create_sample_finding(self, rule_id="test_rule", src="192.168.1.50", dst="10.0.0.1", port=80):
        now = time.time()
        return DetectionFinding(
            rule_id=rule_id,
            rule_name="Test Rule Detection",
            category=DetectionCategory.RECONNAISSANCE,
            severity=DetectionSeverity.MEDIUM,
            confidence=0.85,
            description="Test alert description",
            reason="Test detection trigger",
            source_ip=src,
            destination_ip=dst,
            destination_ports=[port],
            protocol="TCP",
            process_name="test.exe",
            first_seen=now,
            last_seen=now,
            evidence={"count": 5},
            timestamp=now,
        )

    def test_process_finding_creates_new_alert(self):
        """Verify processing a new finding produces a valid SecurityAlert in NEW state."""
        finding = self._create_sample_finding()
        alert = self.mgr.process_finding(finding)

        self.assertIsNotNone(alert.alert_id)
        self.assertEqual(alert.status, AlertStatus.NEW)
        self.assertEqual(alert.occurrence_count, 1)
        self.assertEqual(alert.source_ip, "192.168.1.50")
        self.assertEqual(len(self.mgr.get_alerts()), 1)

    def test_deduplication_cooldown_increments_occurrence(self):
        """Verify subsequent matching findings within cooldown increment count rather than duplicating."""
        finding1 = self._create_sample_finding(port=80)
        alert1 = self.mgr.process_finding(finding1)
        alert_id = alert1.alert_id

        # Second finding with same fingerprint
        finding2 = self._create_sample_finding(port=8080)
        finding2.fingerprint = finding1.fingerprint
        alert2 = self.mgr.process_finding(finding2)

        self.assertEqual(alert1.alert_id, alert2.alert_id)
        self.assertEqual(alert2.occurrence_count, 2)
        self.assertIn(8080, alert2.destination_ports)
        # Should still be only 1 alert in storage
        self.assertEqual(len(self.mgr.get_alerts()), 1)

    def test_alert_lifecycle_state_transitions(self):
        """Verify status transitions: NEW -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED and FALSE_POSITIVE."""
        finding = self._create_sample_finding()
        alert = self.mgr.process_finding(finding)
        aid = alert.alert_id

        # 1. Acknowledge
        success = self.mgr.acknowledge_alert(aid)
        self.assertTrue(success)
        self.assertEqual(self.mgr.get_alert(aid).status, AlertStatus.ACKNOWLEDGED)

        # 2. Investigate
        success = self.mgr.investigate_alert(aid, notes="Checking process hash")
        self.assertTrue(success)
        a = self.mgr.get_alert(aid)
        self.assertEqual(a.status, AlertStatus.INVESTIGATING)
        self.assertEqual(a.notes, "Checking process hash")

        # 3. Resolve
        success = self.mgr.resolve_alert(aid, notes="Benign scanner verified")
        self.assertTrue(success)
        self.assertEqual(self.mgr.get_alert(aid).status, AlertStatus.RESOLVED)

        # 4. Mark false positive
        success = self.mgr.mark_false_positive(aid, reason="Authorized vulnerability scan")
        self.assertTrue(success)
        a = self.mgr.get_alert(aid)
        self.assertEqual(a.status, AlertStatus.FALSE_POSITIVE)
        self.assertEqual(a.false_positive_reason, "Authorized vulnerability scan")

    def test_filtering_and_summary(self):
        """Verify alerts filtering and aggregation metrics."""
        f_crit = self._create_sample_finding(rule_id="crit_rule")
        f_crit.severity = DetectionSeverity.CRITICAL
        f_crit.category = DetectionCategory.EXFILTRATION
        self.mgr.process_finding(f_crit)

        f_low = self._create_sample_finding(rule_id="low_rule", src="10.10.10.10")
        f_low.severity = DetectionSeverity.LOW
        f_low.category = DetectionCategory.DNS_ANOMALY
        f_low.fingerprint = "different_fp"
        self.mgr.process_finding(f_low)

        # Summary verification
        summary = self.mgr.get_summary()
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["low"], 1)
        self.assertEqual(summary["new"], 2)

        # Filter by severity
        crit_alerts = self.mgr.get_alerts(severity="CRITICAL")
        self.assertEqual(len(crit_alerts), 1)
        self.assertEqual(crit_alerts[0].severity, DetectionSeverity.CRITICAL)

        # Filter by search
        search_alerts = self.mgr.get_alerts(search="10.10.10.10")
        self.assertEqual(len(search_alerts), 1)

    def test_in_memory_purge(self):
        """Verify clear() cleanly purges all alerts and maps without disk retention."""
        self.mgr.process_finding(self._create_sample_finding())
        self.assertEqual(len(self.mgr.get_alerts()), 1)

        self.mgr.clear()
        self.assertEqual(len(self.mgr.get_alerts()), 0)
        self.assertEqual(self.mgr.get_summary()["total"], 0)


if __name__ == "__main__":
    unittest.main()
