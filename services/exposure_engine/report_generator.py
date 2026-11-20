"""
CyberShield Exposure Intelligence Engine - Report Generator
Generates executive-ready security reports and summary analytics.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

from .asset_model import ExposureFinding, NormalizedAsset


class ReportGenerator:
    def __init__(self):
        pass

    def generate_executive_summary(
        self,
        target: str,
        assets: List[NormalizedAsset],
        exposures: List[ExposureFinding],
        score_data: Dict[str, Any],
        remediation_plan: List[Dict[str, Any]],
        source_status: Dict[str, str],
        scan_mode: str = "standard",
    ) -> Dict[str, Any]:
        live_hosts = sum(1 for a in assets if a.is_live)
        total_open_ports = len({f"{a.hostname}:{p}" for a in assets for p in a.ports})

        all_techs = {t.name for a in assets for t in a.technologies}
        all_vulns = [v for a in assets for v in a.vulnerabilities]
        unique_cves = {v.cve_id for v in all_vulns}
        kev_cves = {v.cve_id for v in all_vulns if v.kev}

        high_critical_exposures = [
            e for e in exposures if e.priority in ("CRITICAL", "HIGH")
        ]

        # Top 5 priority exposures
        priority_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFORMATIONAL": 5}
        sorted_exposures = sorted(exposures, key=lambda e: priority_order.get(e.priority, 99))
        top_findings = [e.to_dict() for e in sorted_exposures[:5]]

        # Executive narrative
        score = score_data.get("overall_score", 0)
        risk_level = score_data.get("risk_level", "LOW")
        grade = score_data.get("grade", "A")

        if risk_level == "CRITICAL":
            narrative = (
                f"External attack surface assessment for '{target}' revealed critical exposures, including "
                f"actively exploited CVEs or high-risk services exposed directly to the public internet. "
                f"Immediate defensive remediation is recommended."
            )
        elif risk_level == "HIGH":
            narrative = (
                f"The attack surface for '{target}' shows elevated risk factors with confirmed vulnerabilities "
                f"or unprotected infrastructure services requiring prompt defensive attention."
            )
        elif risk_level == "MEDIUM":
            narrative = (
                f"The perimeter for '{target}' exhibits controlled exposure with moderate hardening opportunities "
                f"in encryption, web headers, or software update lifecycle."
            )
        else:
            narrative = (
                f"The external security posture for '{target}' is well-defended with minimal exposed attack surface "
                f"and robust perimeter controls."
            )

        return {
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_mode": scan_mode,
            "metrics": {
                "total_assets": len(assets),
                "live_hosts": live_hosts,
                "open_services": total_open_ports,
                "technologies_count": len(all_techs),
                "known_cves_count": len(unique_cves),
                "kev_cves_count": len(kev_cves),
                "high_priority_exposures": len(high_critical_exposures),
                "exposure_score": score,
                "grade": grade,
                "risk_level": risk_level,
            },
            "narrative": narrative,
            "top_findings": top_findings,
            "top_remediations": remediation_plan[:5],
            "source_status": source_status,
        }
