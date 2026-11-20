"""
Detection Rule: Unusual Outbound Connections.
Identifies outbound connections targeting known high-risk remote ports or suspicious endpoints.
"""

import ipaddress
import time
from typing import Dict, Any, List, Set
from threat_detection.base_rule import BaseDetectionRule
from threat_detection.models import DetectionFinding, DetectionSeverity, DetectionCategory


class UnusualOutboundConnectionRule(BaseDetectionRule):
    rule_id = "unusual_outbound_connection"
    rule_name = "Unusual Outbound Connection"
    description = "Flags outbound connections targeting uncommon high-risk ports or anomalous destinations."
    category = DetectionCategory.OUTBOUND_ANOMALY
    default_severity = DetectionSeverity.MEDIUM

    # Ports commonly associated with reverse shells, IRC botnet C2, unencrypted admin interfaces
    HIGH_RISK_PORTS = {
        4444: "Metasploit / Reverse Shell Default",
        1337: "Common Hacker/Backdoor Port",
        31337: "Back Orifice Trojan",
        6667: "IRC (Legacy Botnet C2 Channel)",
        6666: "IRC Alternative",
        5555: "Android Debug Bridge (ADB)",
        8888: "Non-standard Web/Proxy",
        9999: "Urgent/Backdoor Service",
        12345: "NetBus Trojan",
        2323: "Alternative Telnet / IoT Mirai Port",
    }

    def __init__(self, config: Dict[str, Any] = None):
        default_cfg = {
            "enabled": True,
            "high_risk_ports": list(self.HIGH_RISK_PORTS.keys()),
            "flag_private_destinations": False,
        }
        if config:
            default_cfg.update(config)
            if "suspicious_ports" in config:
                default_cfg["high_risk_ports"] = config["suspicious_ports"]
        super().__init__(default_cfg)

        # Cache of already flagged (src, dst, port) tuples to prevent rapid duplicate findings
        self._flagged_channels: Set[str] = set()

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_link_local:
                return True
            if ip.version == 4:
                return (
                    ip in ipaddress.ip_network("10.0.0.0/8") or
                    ip in ipaddress.ip_network("172.16.0.0/12") or
                    ip in ipaddress.ip_network("192.168.0.0/16")
                )
            return ip.is_private
        except ValueError:
            return True

    def analyze(self, telemetry: Dict[str, Any]) -> List[DetectionFinding]:
        if not self.enabled:
            return []

        connections = telemetry.get("connections", [])
        packets = telemetry.get("recent_packets", [])
        now = time.time()
        findings: List[DetectionFinding] = []
        raw_ports = self.config.get("high_risk_ports") or self.config.get("suspicious_ports") or list(self.HIGH_RISK_PORTS.keys())
        high_risk_set = set(raw_ports)

        # 1. Analyze active OS connection sockets
        for c in connections:
            remote_ip = c.get("remote_ip") if isinstance(c, dict) else getattr(c, "remote_ip", None)
            remote_port = c.get("remote_port") if isinstance(c, dict) else getattr(c, "remote_port", None)
            local_ip = c.get("local_ip") if isinstance(c, dict) else getattr(c, "local_ip", None)
            status = c.get("status", "") if isinstance(c, dict) else getattr(c, "status", "")
            proc = c.get("process_name") if isinstance(c, dict) else getattr(c, "process_name", None)

            if not remote_ip or not remote_port:
                continue
            if not self.config.get("flag_private_destinations") and self._is_private_ip(remote_ip):
                continue

            if remote_port in high_risk_set:
                channel_key = f"{local_ip}->{remote_ip}:{remote_port}"
                if channel_key not in self._flagged_channels:
                    self._flagged_channels.add(channel_key)
                    tag = self.HIGH_RISK_PORTS.get(remote_port, "Unusual Port")
                    findings.append(
                        DetectionFinding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            category=self.category,
                            severity=DetectionSeverity.HIGH if remote_port in (4444, 1337, 31337) else DetectionSeverity.MEDIUM,
                            confidence=0.80,
                            description=f"Outbound connection established to high-risk port {remote_port} ({tag}) at {remote_ip}.",
                            reason=f"Target port {remote_port} is associated with {tag}.",
                            source_ip=local_ip,
                            destination_ip=remote_ip,
                            destination_ports=[remote_port],
                            protocol=getattr(c, "protocol", "tcp") if not isinstance(c, dict) else c.get("protocol", "tcp"),
                            process_name=proc,
                            evidence={
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "port_classification": tag,
                                "connection_status": status,
                                "process": proc or "N/A",
                            },
                            timestamp=now,
                        )
                    )

        # 2. Analyze recent packet stream for outbound probes to high-risk ports
        for p in packets:
            dir_str = getattr(p, "direction", "unknown") if not isinstance(p, dict) else p.get("direction", "unknown")
            if dir_str != "outbound":
                continue

            dst = getattr(p, "destination_ip", None) if not isinstance(p, dict) else p.get("destination_ip")
            dst_port = getattr(p, "destination_port", None) if not isinstance(p, dict) else p.get("destination_port")
            src = getattr(p, "source_ip", None) if not isinstance(p, dict) else p.get("source_ip")

            if dst and dst_port and dst_port in high_risk_set and not self._is_private_ip(dst):
                channel_key = f"{src}->{dst}:{dst_port}"
                if channel_key not in self._flagged_channels:
                    self._flagged_channels.add(channel_key)
                    tag = self.HIGH_RISK_PORTS.get(dst_port, "Unusual High-Risk Port")
                    findings.append(
                        DetectionFinding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            category=self.category,
                            severity=DetectionSeverity.MEDIUM,
                            confidence=0.75,
                            description=f"Observed outbound packet directed to high-risk port {dst_port} ({tag}) on {dst}.",
                            reason=f"Traffic directed to known anomalous port {dst_port}.",
                            source_ip=src,
                            destination_ip=dst,
                            destination_ports=[dst_port],
                            protocol=getattr(p, "protocol", "TCP") if not isinstance(p, dict) else p.get("protocol", "TCP"),
                            evidence={
                                "remote_ip": dst,
                                "remote_port": dst_port,
                                "port_classification": tag,
                            },
                            timestamp=now,
                        )
                    )

        return findings

    def reset(self) -> None:
        self._flagged_channels.clear()
