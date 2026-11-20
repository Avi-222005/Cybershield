"""
Detection Rule: Repeated Connection Attempts.
Identifies repeated rapid connection attempts to the same remote endpoint or multiple ports.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Tuple
from threat_detection.base_rule import BaseDetectionRule
from threat_detection.models import DetectionFinding, DetectionSeverity, DetectionCategory


class RepeatedConnectionAttemptsRule(BaseDetectionRule):
    rule_id = "repeated_connection_attempts"
    rule_name = "Repeated Connection Attempts"
    description = "Detects rapid repeated connection attempts targeting the same destination endpoint."
    category = DetectionCategory.SUSPICIOUS_CONNECTION
    default_severity = DetectionSeverity.MEDIUM

    def __init__(self, config: Dict[str, Any] = None):
        default_cfg = {
            "enabled": True,
            "window_seconds": 60,
            "attempts_threshold": 15,
            "minimum_observations": 15,
        }
        if config:
            default_cfg.update(config)
            if "attempt_threshold" in config:
                default_cfg["attempts_threshold"] = config["attempt_threshold"]
                default_cfg["minimum_observations"] = config["attempt_threshold"]
        super().__init__(default_cfg)

        # Map of (source_ip, destination_ip) -> deque of (timestamp, port)
        self._history: Dict[Tuple[str, str], deque] = defaultdict(deque)

    def _is_benign_endpoint(self, ip: str) -> bool:
        if not ip:
            return True
        # Broadcast, multicast, loopback
        if ip in ("255.255.255.255", "127.0.0.1", "::1", "0.0.0.0"):
            return True
        if ip.startswith("224.") or ip.startswith("239."):
            return True
        return False

    def analyze(self, telemetry: Dict[str, Any]) -> List[DetectionFinding]:
        if not self.enabled:
            return []

        packets = telemetry.get("recent_packets", [])
        connections = telemetry.get("connections", [])
        now = time.time()
        window = self.config.get("window_seconds", 60)
        threshold = self.config.get("attempts_threshold") or self.config.get("attempt_threshold", 15)
        cutoff = now - window

        # Ingest recent packet events into history
        for p in packets:
            src = p.get("source_ip") if isinstance(p, dict) else getattr(p, "source_ip", None)
            dst = p.get("destination_ip") if isinstance(p, dict) else getattr(p, "destination_ip", None)
            port = p.get("destination_port") if isinstance(p, dict) else getattr(p, "destination_port", None)
            ts = p.get("timestamp", now) if isinstance(p, dict) else getattr(p, "timestamp", now)

            if not src or not dst or self._is_benign_endpoint(dst) or self._is_benign_endpoint(src):
                continue

            pair = (src, dst)
            self._history[pair].append((ts, port or 0))

        findings: List[DetectionFinding] = []

        # Analyze each pair
        for (src, dst), events in list(self._history.items()):
            # Prune old events outside sliding window
            while events and events[0][0] < cutoff:
                events.popleft()

            count = len(events)
            if count >= threshold:
                ports = list(set(e[1] for e in events if e[1] > 0))
                first_ts = events[0][0]
                last_ts = events[-1][0]

                findings.append(
                    DetectionFinding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        category=self.category,
                        severity=self.default_severity,
                        confidence=min(0.95, 0.60 + (count / (threshold * 3))),
                        description=f"Observed {count} rapid connection attempts from {src} to {dst}.",
                        reason=f"{count} connection attempts exceeded threshold of {threshold} in {window}s window.",
                        source_ip=src,
                        destination_ip=dst,
                        destination_ports=ports[:10],
                        first_seen=first_ts,
                        last_seen=last_ts,
                        evidence={
                            "attempts_count": count,
                            "attempts_in_window": count,
                            "window_seconds": window,
                            "unique_destination_ports_count": len(ports),
                            "sample_ports": ports[:8],
                        },
                        timestamp=now,
                    )
                )

        return findings

    def reset(self) -> None:
        self._history.clear()
