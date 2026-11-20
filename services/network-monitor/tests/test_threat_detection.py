"""
Unit tests for CyberShield Threat Detection Engine and Detection Rules.
Verifies all 5 detection rules, baseline calculations, and finding generation.
"""

import time
import unittest
from models.packet_event import PacketEvent
from models.connection import Connection
from threat_detection.engine import ThreatDetectionEngine
from threat_detection.models import DetectionSeverity, DetectionCategory
from threat_detection.rules.connection_attempts import RepeatedConnectionAttemptsRule
from threat_detection.rules.port_scan_indicator import PortScanIndicatorRule
from threat_detection.rules.outbound_anomaly import UnusualOutboundConnectionRule
from threat_detection.rules.traffic_spike import TrafficSpikeRule
from threat_detection.rules.dns_anomaly import DNSAnomalyRule


class TestThreatDetection(unittest.TestCase):

    def setUp(self):
        self.engine = ThreatDetectionEngine()

    def test_repeated_connection_attempts_rule(self):
        """Verify rule triggers on repeated connection attempts from an endpoint exceeding threshold."""
        rule = RepeatedConnectionAttemptsRule(config={"attempt_threshold": 5, "window_seconds": 10.0})
        now = time.time()
        packets = [
            PacketEvent(
                timestamp=now + (i * 0.1),
                interface="eth0",
                source_ip="192.168.1.100",
                destination_ip="10.0.0.5",
                source_port=50000 + i,
                destination_port=80,
                protocol="TCP",
                packet_size=64,
                direction="inbound",
            )
            for i in range(8)
        ]

        findings = rule.analyze({"recent_packets": packets})
        self.assertGreaterEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "repeated_connection_attempts")
        self.assertEqual(finding.source_ip, "192.168.1.100")
        self.assertEqual(finding.destination_ip, "10.0.0.5")
        self.assertGreaterEqual(finding.evidence["attempts_in_window"], 5)

    def test_port_scan_indicator_rule(self):
        """Verify rule identifies sequential/multi-port scan indicators."""
        rule = PortScanIndicatorRule(config={"distinct_port_threshold": 5, "window_seconds": 15.0})
        now = time.time()
        packets = [
            PacketEvent(
                timestamp=now + (i * 0.05),
                interface="eth0",
                source_ip="192.168.1.250",
                destination_ip="192.168.1.1",
                source_port=40000,
                destination_port=20 + i,  # Ports 20, 21, 22, 23, 24, 25, 26
                protocol="TCP",
                packet_size=60,
                direction="inbound",
            )
            for i in range(7)
        ]

        findings = rule.analyze({"recent_packets": packets})
        self.assertGreaterEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "possible_port_scan")
        self.assertEqual(finding.category, DetectionCategory.PORT_SCAN)
        self.assertGreaterEqual(finding.evidence["distinct_ports_targeted"], 5)

    def test_unusual_outbound_connection_rule(self):
        """Verify rule flags outbound traffic to uncommon or suspicious remote ports."""
        rule = UnusualOutboundConnectionRule(config={"suspicious_ports": [4444, 1337, 6667, 31337]})
        conns = [
            Connection(
                local_ip="192.168.1.50",
                local_port=55123,
                remote_ip="203.0.113.88",
                remote_port=4444,  # Metasploit default listener port
                protocol="TCP",
                status="ESTABLISHED",
                pid=1234,
                process_name="test_service.exe",
            )
        ]

        findings = rule.analyze({"connections": conns})
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "unusual_outbound_connection")
        self.assertEqual(finding.severity, DetectionSeverity.HIGH)
        self.assertEqual(finding.destination_ports, [4444])
        self.assertEqual(finding.process_name, "test_service.exe")

    def test_traffic_spike_rule(self):
        """Verify rule detects traffic spikes exceeding established baseline mean."""
        rule = TrafficSpikeRule(config={"spike_multiplier": 2.5, "min_sample_count": 3, "min_baseline_mbps": 0.05})
        telemetry = {
            "traffic": {
                "download_bytes_per_sec": 5_000_000,  # ~40 Mbps
                "upload_bytes_per_sec": 500_000,
            },
            "bandwidth_baseline": {
                "sample_count": 10,
                "download_mean_bps": 200_000,  # ~1.6 Mbps baseline
                "download_std_bps": 50_000,
            },
        }

        findings = rule.analyze(telemetry)
        self.assertGreaterEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "unexpected_traffic_spike")
        self.assertEqual(finding.category, DetectionCategory.EXFILTRATION)

    def test_dns_anomaly_rule(self):
        """Verify rule flags suspicious high-entropy queries or tunneling indicators."""
        rule = DNSAnomalyRule(config={"entropy_threshold": 3.8, "min_domain_length": 15})
        now = time.time()
        packets = [
            PacketEvent(
                timestamp=now,
                interface="eth0",
                source_ip="192.168.1.15",
                destination_ip="8.8.8.8",
                source_port=53535,
                destination_port=53,
                protocol="DNS",
                packet_size=120,
                direction="outbound",
                dns_query="a9f4c3b28d7e10fa65c9283746e5d4.tunnel.evilcorp.com",
                dns_rcode=0,
            )
        ]

        findings = rule.analyze({"recent_packets": packets})
        self.assertGreaterEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "suspicious_dns_pattern")
        self.assertEqual(finding.category, DetectionCategory.DNS_ANOMALY)
        self.assertGreater(finding.evidence["entropy"], 3.8)

    def test_engine_integration_and_config_updates(self):
        """Verify ThreatDetectionEngine manages all rules, executes analysis, and updates configs."""
        self.assertEqual(len(self.engine.rules), 5)
        rules_info = self.engine.get_rules_info()
        self.assertEqual(len(rules_info), 5)

        # Update rule config
        success = self.engine.update_rule_config(
            "repeated_connection_attempts",
            {"enabled": False, "attempt_threshold": 25},
        )
        self.assertTrue(success)
        self.assertFalse(self.engine.rules["repeated_connection_attempts"].enabled)
        self.assertEqual(
            self.engine.rules["repeated_connection_attempts"].config["attempt_threshold"],
            25,
        )

        # Re-enable and reset
        self.engine.update_rule_config("repeated_connection_attempts", {"enabled": True})
        self.engine.reset()
        status = self.engine.get_status()
        self.assertEqual(status["total_findings_generated"], 0)


if __name__ == "__main__":
    unittest.main()
