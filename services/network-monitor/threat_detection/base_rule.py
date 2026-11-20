"""
Base class and interface for all CyberShield Threat Detection rules.
"""

import abc
from typing import Dict, Any, List
from threat_detection.models import DetectionFinding, DetectionSeverity


class BaseDetectionRule(abc.ABC):
    """
    Abstract interface for independent, modular detection rules.
    """
    rule_id: str = "base_rule"
    rule_name: str = "Base Detection Rule"
    description: str = "Base detection rule interface."
    category: str = "GENERAL"
    default_severity: str = DetectionSeverity.MEDIUM

    def __init__(self, config: Dict[str, Any] = None):
        self.enabled: bool = True
        self.config: Dict[str, Any] = {}
        if config:
            self.config.update(config)

    def update_config(self, new_config: Dict[str, Any]) -> None:
        """Update configurable thresholds safely."""
        if "enabled" in new_config:
            self.enabled = bool(new_config["enabled"])
        for k, v in new_config.items():
            self.config[k] = v

    @abc.abstractmethod
    def analyze(self, telemetry: Dict[str, Any]) -> List[DetectionFinding]:
        """
        Analyze current telemetry snapshot and return structured findings.
        Returns empty list if no suspicious behavior detected.
        """
        pass

    def reset(self) -> None:
        """Reset temporary in-memory rule state on session shutdown."""
        pass

    def get_info(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "category": self.category,
            "default_severity": self.default_severity,
            "enabled": self.enabled,
            "config": dict(self.config),
        }
