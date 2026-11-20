"""
Detection Rule: Suspicious DNS Patterns.
Analyzes DNS metadata for anomalous query rates, excessively long labels, or high entropy.
Does NOT store or persist DNS payloads.
"""

import math
import time
from collections import Counter, defaultdict, deque
from typing import Dict, Any, List
from threat_detection.base_rule import BaseDetectionRule
from threat_detection.models import DetectionFinding, DetectionSeverity, DetectionCategory


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class DNSAnomalyRule(BaseDetectionRule):
    rule_id = "suspicious_dns_pattern"
    rule_name = "Suspicious DNS Activity Indicator"
    description = "Passively analyzes DNS metadata for anomalous query rates, excessively long labels, or high entropy."
    category = DetectionCategory.DNS_ANOMALY
    default_severity = DetectionSeverity.MEDIUM

    def __init__(self, config: Dict[str, Any] = None):
        default_cfg = {
            "enabled": True,
            "max_query_rate_per_10s": 25,
            "max_domain_length": 55,
            "entropy_threshold": 3.85,
        }
        if config:
            default_cfg.update(config)
        super().__init__(default_cfg)

        # src_ip -> deque of timestamps
        self._query_times: Dict[str, deque] = defaultdict(deque)

    def analyze(self, telemetry: Dict[str, Any]) -> List[DetectionFinding]:
        if not self.enabled:
            return []

        packets = telemetry.get("recent_packets", [])
        now = time.time()
        findings: List[DetectionFinding] = []
        max_rate = self.config.get("max_query_rate_per_10s", 25)
        max_len = self.config.get("max_domain_length", 55)
        entropy_threshold = self.config.get("entropy_threshold", 3.85)

        for p in packets:
            proto = p.get("protocol", "") if isinstance(p, dict) else getattr(p, "protocol", "")
            if "DNS" not in str(proto).upper():
                continue

            src = p.get("source_ip") if isinstance(p, dict) else getattr(p, "source_ip", None)
            dst = p.get("destination_ip") if isinstance(p, dict) else getattr(p, "destination_ip", None)
            ts = p.get("timestamp", now) if isinstance(p, dict) else getattr(p, "timestamp", now)
            qname = p.get("dns_query") if isinstance(p, dict) else getattr(p, "dns_query", None)

            if src:
                self._query_times[src].append(ts)
                # Prune older than 10s
                cutoff = now - 10.0
                while self._query_times[src] and self._query_times[src][0] < cutoff:
                    self._query_times[src].popleft()

                # Check high query frequency
                if len(self._query_times[src]) >= max_rate:
                    findings.append(
                        DetectionFinding(
                            rule_id=self.rule_id,
                            rule_name="Excessive DNS Query Rate",
                            category=self.category,
                            severity=DetectionSeverity.LOW,
                            confidence=0.70,
                            description=f"Host {src} issued {len(self._query_times[src])} DNS queries within 10 seconds.",
                            reason=f"Exceeded normal frequency threshold of {max_rate} queries / 10s.",
                            source_ip=src,
                            destination_ip=dst,
                            protocol="DNS",
                            evidence={
                                "queries_in_10s": len(self._query_times[src]),
                                "threshold": max_rate,
                            },
                            timestamp=now,
                        )
                    )
                    self._query_times[src].clear()

            # Check domain characteristics if metadata query name is present
            if qname and isinstance(qname, str):
                # Clean query name
                domain = qname.strip().rstrip(".")
                if len(domain) >= max_len:
                    findings.append(
                        DetectionFinding(
                            rule_id=self.rule_id,
                            rule_name="Abnormally Long DNS Query Label",
                            category=self.category,
                            severity=DetectionSeverity.MEDIUM,
                            confidence=0.75,
                            description=f"Observed unusually long domain label ({len(domain)} characters) in DNS query.",
                            reason=f"Domain length {len(domain)} exceeds threshold of {max_len} characters.",
                            source_ip=src,
                            destination_ip=dst,
                            protocol="DNS",
                            evidence={
                                "domain_length": len(domain),
                                "domain_sample": domain[:40] + "...",
                            },
                            timestamp=now,
                        )
                    )

                # Check Shannon entropy for non-standard labels
                parts = domain.split(".")
                for part in parts[:-1]:
                    if len(part) >= 12:
                        ent = calculate_entropy(part)
                        if ent >= entropy_threshold:
                            findings.append(
                                DetectionFinding(
                                    rule_id=self.rule_id,
                                    rule_name="High-Entropy DNS Query (DGA / Tunneling Indicator)",
                                    category=self.category,
                                    severity=DetectionSeverity.HIGH,
                                    confidence=0.80,
                                    description=f"Subdomain label exhibited unusually high Shannon entropy ({ent:.2f} bits).",
                                    reason=f"Entropy {ent:.2f} exceeds threshold of {entropy_threshold} (potential DGA or DNS tunneling indicator).",
                                    source_ip=src,
                                    destination_ip=dst,
                                    protocol="DNS",
                                    evidence={
                                        "entropy": round(ent, 2),
                                        "entropy_bits": round(ent, 2),
                                        "label_length": len(part),
                                    },
                                    timestamp=now,
                                )
                            )
                            break

        return findings

    def reset(self) -> None:
        self._query_times.clear()
