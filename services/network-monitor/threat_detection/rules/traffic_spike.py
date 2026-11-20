"""
Detection Rule: Unexpected Traffic Spikes.
Identifies anomalous surges in upload or download bandwidth relative to baseline.
"""

import time
from typing import Dict, Any, List
from threat_detection.base_rule import BaseDetectionRule
from threat_detection.models import DetectionFinding, DetectionSeverity, DetectionCategory


class TrafficSpikeRule(BaseDetectionRule):
    rule_id = "unexpected_traffic_spike"
    rule_name = "Unexpected Traffic Spike"
    description = "Identifies sudden, abnormal increases in bandwidth relative to the rolling session baseline."
    category = DetectionCategory.TRAFFIC_ANOMALY
    default_severity = DetectionSeverity.MEDIUM

    def __init__(self, config: Dict[str, Any] = None):
        default_cfg = {
            "enabled": True,
            "spike_multiplier": 3.0,      # Current > 3x mean baseline
            "min_bandwidth_mbps": 5.0,    # Ignore trivial spikes below 5 Mbps
            "min_baseline_samples": 8,    # Need at least 8 samples (8 seconds) of baseline
            "cooldown_seconds": 30,       # Avoid alert flooding on sustained transfers
        }
        if config:
            default_cfg.update(config)
        super().__init__(default_cfg)

        self._last_alert_time: float = 0.0

    def analyze(self, telemetry: Dict[str, Any]) -> List[DetectionFinding]:
        if not self.enabled:
            return []

        now = time.time()
        cooldown = self.config.get("cooldown_seconds", 30)
        if (now - self._last_alert_time) < cooldown:
            return []

        traffic = telemetry.get("traffic", {})
        baseline_stats = telemetry.get("bandwidth_baseline", {})

        min_samples = self.config.get("min_baseline_samples") or self.config.get("min_sample_count", 8)
        sample_count = baseline_stats.get("sample_count", 0)
        has_sufficient = baseline_stats.get("has_sufficient_data", sample_count >= min_samples)

        if not has_sufficient or sample_count < min_samples:
            return []

        down_mbps = traffic.get("download_mbps")
        if down_mbps is None:
            down_mbps = (traffic.get("download_bytes_per_sec", 0.0) * 8.0) / 1_000_000.0

        up_mbps = traffic.get("upload_mbps")
        if up_mbps is None:
            up_mbps = (traffic.get("upload_bytes_per_sec", 0.0) * 8.0) / 1_000_000.0

        # Baseline stats are in Bytes/sec, convert mean to Mbps: (bytes * 8) / 1,000,000
        up_mean_bps = baseline_stats.get("upload_mean") or baseline_stats.get("upload_mean_bps", 0.0)
        down_mean_bps = baseline_stats.get("download_mean") or baseline_stats.get("download_mean_bps", 0.0)

        up_mean_mbps = (up_mean_bps * 8.0) / 1_000_000.0
        down_mean_mbps = (down_mean_bps * 8.0) / 1_000_000.0

        multiplier = self.config.get("spike_multiplier", 3.0)
        min_mbps = self.config.get("min_bandwidth_mbps") or self.config.get("min_baseline_mbps", 5.0)

        findings: List[DetectionFinding] = []

        # Check Upload Spike (often indicative of large exfiltration or flood)
        if up_mbps >= min_mbps and up_mean_mbps > 0 and up_mbps >= (up_mean_mbps * multiplier):
            deviation_pct = ((up_mbps - up_mean_mbps) / up_mean_mbps) * 100
            self._last_alert_time = now
            findings.append(
                DetectionFinding(
                    rule_id=self.rule_id,
                    rule_name="Abnormal Upload Traffic Surge",
                    category=self.category,
                    severity=DetectionSeverity.HIGH if up_mbps > 25.0 else DetectionSeverity.MEDIUM,
                    confidence=0.85,
                    description=f"Upload bandwidth surged to {up_mbps:.2f} Mbps (+{deviation_pct:.0f}% above baseline).",
                    reason=f"Current upload rate exceeds rolling baseline ({up_mean_mbps:.2f} Mbps) by {multiplier}x.",
                    protocol="ALL",
                    evidence={
                        "direction": "upload",
                        "current_mbps": round(up_mbps, 2),
                        "baseline_mean_mbps": round(up_mean_mbps, 2),
                        "percentage_increase": round(deviation_pct, 1),
                        "baseline_samples": sample_count,
                    },
                    timestamp=now,
                )
            )

        # Check Download Spike
        elif down_mbps >= min_mbps and down_mean_mbps > 0 and down_mbps >= (down_mean_mbps * multiplier):
            deviation_pct = ((down_mbps - down_mean_mbps) / down_mean_mbps) * 100
            self._last_alert_time = now
            findings.append(
                DetectionFinding(
                    rule_id=self.rule_id,
                    rule_name="Abnormal Download Traffic Surge",
                    category=self.category,
                    severity=DetectionSeverity.MEDIUM,
                    confidence=0.80,
                    description=f"Download bandwidth surged to {down_mbps:.2f} Mbps (+{deviation_pct:.0f}% above baseline).",
                    reason=f"Current download rate exceeds rolling baseline ({down_mean_mbps:.2f} Mbps) by {multiplier}x.",
                    protocol="ALL",
                    evidence={
                        "direction": "download",
                        "current_mbps": round(down_mbps, 2),
                        "baseline_mean_mbps": round(down_mean_mbps, 2),
                        "percentage_increase": round(deviation_pct, 1),
                        "baseline_samples": sample_count,
                    },
                    timestamp=now,
                )
            )

        return findings

    def reset(self) -> None:
        self._last_alert_time = 0.0
