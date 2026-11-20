"""
Threat Detection Engine for CyberShield Network Monitor.
Coordinates modular detection rules, maintains session baselines,
and produces structured security detection findings.
"""

import threading
import time
from typing import Dict, Any, List, Optional
from threat_detection.models import DetectionFinding
from threat_detection.base_rule import BaseDetectionRule
from threat_detection.baseline_manager import BaselineManager
from threat_detection.rules.connection_attempts import RepeatedConnectionAttemptsRule
from threat_detection.rules.port_scan_indicator import PortScanIndicatorRule
from threat_detection.rules.outbound_anomaly import UnusualOutboundConnectionRule
from threat_detection.rules.traffic_spike import TrafficSpikeRule
from threat_detection.rules.dns_anomaly import DNSAnomalyRule


class ThreatDetectionEngine:
    """
    Independent threat analysis engine.
    Analyzes normalized network telemetry passively and incrementally.
    """

    def __init__(self, config_overrides: Optional[Dict[str, Any]] = None):
        self._lock = threading.RLock()
        self.baseline_manager = BaselineManager()

        # Instantiate detection rules
        self.rules: Dict[str, BaseDetectionRule] = {
            "repeated_connection_attempts": RepeatedConnectionAttemptsRule(),
            "possible_port_scan": PortScanIndicatorRule(),
            "unusual_outbound_connection": UnusualOutboundConnectionRule(),
            "unexpected_traffic_spike": TrafficSpikeRule(),
            "suspicious_dns_pattern": DNSAnomalyRule(),
        }

        # Apply optional configuration overrides
        if config_overrides:
            for rule_id, rule_cfg in config_overrides.items():
                if rule_id in self.rules and isinstance(rule_cfg, dict):
                    self.rules[rule_id].update_config(rule_cfg)

        self._total_findings_generated: int = 0
        self._last_analysis_time: float = 0.0

    def analyze_telemetry(self, telemetry: Dict[str, Any]) -> List[DetectionFinding]:
        """
        Run all active detection rules against current telemetry snapshot.
        Telemetry expected keys: 'recent_packets', 'connections', 'traffic'.
        """
        with self._lock:
            now = time.time()
            self._last_analysis_time = now

            # 1. Update baseline with current bandwidth counters
            traffic = telemetry.get("traffic", {})
            if traffic:
                up_bps = traffic.get("upload_bytes_per_sec", 0.0)
                down_bps = traffic.get("download_bytes_per_sec", 0.0)
                self.baseline_manager.record_bandwidth(up_bps, down_bps, now=now)

            # 2. Enrich telemetry dictionary with baseline data
            telemetry["bandwidth_baseline"] = self.baseline_manager.get_bandwidth_stats()

            findings: List[DetectionFinding] = []

            # 3. Execute detection rules
            for rule_id, rule in self.rules.items():
                if not rule.enabled:
                    continue
                try:
                    rule_findings = rule.analyze(telemetry)
                    if rule_findings:
                        findings.extend(rule_findings)
                except Exception:
                    # Individual rule exceptions must never crash detection engine
                    pass

            self._total_findings_generated += len(findings)
            return findings

    def get_rules_info(self) -> List[Dict[str, Any]]:
        """Return information and configuration status for all detection rules."""
        with self._lock:
            return [rule.get_info() for rule in self.rules.values()]

    def update_rule_config(self, rule_id: str, new_config: Dict[str, Any]) -> bool:
        """Safely update configuration for an individual rule."""
        with self._lock:
            rule = self.rules.get(rule_id)
            if not rule:
                return False
            rule.update_config(new_config)
            return True

    def get_status(self) -> Dict[str, Any]:
        """Return operational diagnostics for the detection engine."""
        with self._lock:
            enabled_count = sum(1 for r in self.rules.values() if r.enabled)
            return {
                "active": True,
                "total_rules": len(self.rules),
                "enabled_rules": enabled_count,
                "total_findings_generated": self._total_findings_generated,
                "last_analysis_time": self._last_analysis_time,
                "baseline_samples": self.baseline_manager.get_bandwidth_stats().get("sample_count", 0),
            }

    def reset(self) -> None:
        """Purge temporary detection rule buffers and baselines on session shutdown."""
        with self._lock:
            for rule in self.rules.values():
                rule.reset()
            self.baseline_manager.reset()
            self._total_findings_generated = 0
            self._last_analysis_time = 0.0
