"""
Detection Rule: Port Scan Indicators.
Passive detection of possible vertical or horizontal port scanning behaviors.
"""

import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Set, Tuple
from threat_detection.base_rule import BaseDetectionRule
from threat_detection.models import DetectionFinding, DetectionSeverity, DetectionCategory


class PortScanIndicatorRule(BaseDetectionRule):
    rule_id = "possible_port_scan"
    rule_name = "Possible Port Scan Indicator"
    description = "Passively detects patterns indicative of vertical or horizontal port scanning activity."
    category = DetectionCategory.NETWORK_RECONNAISSANCE
    default_severity = DetectionSeverity.HIGH

    def __init__(self, config: Dict[str, Any] = None):
        default_cfg = {
            "enabled": True,
            "window_seconds": 60,
            "unique_ports_threshold": 15,
            "minimum_observations": 20,
            "horizontal_host_threshold": 10,
        }
        if config:
            default_cfg.update(config)
            if "distinct_port_threshold" in config:
                default_cfg["unique_ports_threshold"] = config["distinct_port_threshold"]
                default_cfg["minimum_observations"] = config["distinct_port_threshold"]
        super().__init__(default_cfg)

        # src -> deque of (timestamp, dst_ip, dst_port)
        self._src_probes: Dict[str, deque] = defaultdict(deque)

    def analyze(self, telemetry: Dict[str, Any]) -> List[DetectionFinding]:
        if not self.enabled:
            return []

        packets = telemetry.get("recent_packets", [])
        now = time.time()
        window = self.config.get("window_seconds", 60)
        ports_threshold = self.config.get("unique_ports_threshold") or self.config.get("distinct_port_threshold", 15)
        min_obs = self.config.get("minimum_observations", ports_threshold)
        host_threshold = self.config.get("horizontal_host_threshold", 10)
        cutoff = now - window

        for p in packets:
            src = p.get("source_ip") if isinstance(p, dict) else getattr(p, "source_ip", None)
            dst = p.get("destination_ip") if isinstance(p, dict) else getattr(p, "destination_ip", None)
            port = p.get("destination_port") if isinstance(p, dict) else getattr(p, "destination_port", None)
            ts = p.get("timestamp", now) if isinstance(p, dict) else getattr(p, "timestamp", now)

            if not src or not dst or not port:
                continue
            if src in ("127.0.0.1", "::1", "255.255.255.255"):
                continue

            self._src_probes[src].append((ts, dst, port))

        findings: List[DetectionFinding] = []

        for src, probes in list(self._src_probes.items()):
            # Prune old probes outside window
            while probes and probes[0][0] < cutoff:
                probes.popleft()

            if len(probes) < min_obs:
                continue

            # Check Vertical Scan: Single destination targeted across many ports
            dst_to_ports: Dict[str, Set[int]] = defaultdict(set)
            for _, dst, port in probes:
                dst_to_ports[dst].add(port)

            for dst, ports in dst_to_ports.items():
                if len(ports) >= ports_threshold:
                    sorted_ports = sorted(list(ports))
                    findings.append(
                        DetectionFinding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            category=self.category,
                            severity=self.default_severity,
                            confidence=0.85,
                            description=f"Potential vertical port scan detected: {src} targeted {len(ports)} distinct ports on {dst}.",
                            reason=f"Multiple distinct destination ports ({len(ports)}) probed within {window}s window.",
                            source_ip=src,
                            destination_ip=dst,
                            destination_ports=sorted_ports[:15],
                            first_seen=probes[0][0],
                            last_seen=probes[-1][0],
                            evidence={
                                "scan_type": "vertical_port_scan",
                                "distinct_ports_count": len(ports),
                                "distinct_ports_targeted": len(ports),
                                "probed_ports_sample": sorted_ports[:12],
                                "window_seconds": window,
                            },
                            timestamp=now,
                        )
                    )

            # Check Horizontal Scan: Many destinations targeted on the same port
            port_to_dsts: Dict[int, Set[str]] = defaultdict(set)
            for _, dst, port in probes:
                port_to_dsts[port].add(dst)

            for port, dsts in port_to_dsts.items():
                if len(dsts) >= host_threshold:
                    findings.append(
                        DetectionFinding(
                            rule_id=self.rule_id,
                            rule_name="Possible Network Sweep Indicator",
                            category=self.category,
                            severity=DetectionSeverity.MEDIUM,
                            confidence=0.75,
                            description=f"Potential horizontal scan detected: {src} probed port {port} across {len(dsts)} unique hosts.",
                            reason=f"Same destination port {port} probed on {len(dsts)} distinct hosts within {window}s window.",
                            source_ip=src,
                            destination_ip="multiple",
                            destination_ports=[port],
                            first_seen=probes[0][0],
                            last_seen=probes[-1][0],
                            evidence={
                                "scan_type": "horizontal_port_sweep",
                                "target_port": port,
                                "unique_hosts_count": len(dsts),
                                "window_seconds": window,
                            },
                            timestamp=now,
                        )
                    )

        return findings

    def reset(self) -> None:
        self._src_probes.clear()
