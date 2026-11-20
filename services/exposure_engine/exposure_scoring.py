"""
CyberShield Exposure Intelligence Engine - Exposure Scoring Engine
Calculates explainable, multi-dimensional CyberShield Exposure Score (0 - 100) with strict guardrails
and transparent evidence-based contributions.
"""

from typing import Any, Dict, List, Tuple

from .asset_model import NormalizedAsset


def _grade_and_level_from_score(score: int) -> Tuple[str, str, str]:
    """
    Returns (grade, grade_label, risk_level).
    0-20: Low Exposure (A, Minimal Risk)
    21-40: Controlled (B, Good / Low-Medium Risk)
    41-60: Watchlist (C, Moderate Exposure)
    61-80: Elevated (D, High Risk)
    81-100: Urgent (F, Critical Risk)
    """
    if score <= 15:
        return "A+", "Excellent Security Posture", "LOW"
    if score <= 25:
        return "A", "Strong Defense", "LOW"
    if score <= 40:
        return "B", "Controlled Exposure", "MEDIUM"
    if score <= 60:
        return "C", "Moderate Exposure", "MEDIUM"
    if score <= 80:
        return "D", "Elevated Exposure", "HIGH"
    return "F", "Critical Exposure", "CRITICAL"


class ExposureScoringEngine:
    def __init__(self):
        pass

    def compute_asset_score(self, asset: NormalizedAsset) -> Dict[str, Any]:
        """Calculates exposure score for a single asset."""
        return self._evaluate_assets([asset], is_single=True)

    def compute_overall_score(self, assets: List[NormalizedAsset]) -> Dict[str, Any]:
        """Calculates global posture score across all discovered assets."""
        return self._evaluate_assets(assets, is_single=False)

    def _evaluate_assets(self, assets: List[NormalizedAsset], is_single: bool = False) -> Dict[str, Any]:
        if not assets:
            return {
                "overall_score": 0,
                "grade": "A+",
                "grade_label": "No Exposed Assets Discovered",
                "risk_level": "LOW",
                "breakdown": {},
            }

        # Category 1: Internet Exposure (0 - 25 points)
        ie_score, ie_evidence = self._calc_internet_exposure(assets)

        # Category 2: Vulnerability (0 - 25 points)
        vuln_score, vuln_evidence = self._calc_vulnerability_score(assets)

        # Category 3: Exploitability (0 - 20 points)
        exp_score, exp_evidence = self._calc_exploitability_score(assets)

        # Category 4: Configuration (0 - 15 points)
        cfg_score, cfg_evidence = self._calc_configuration_score(assets)

        # Category 5: Asset Context & Criticality (0 - 15 points)
        ctx_score, ctx_evidence = self._calc_asset_context_score(assets)

        total_score = min(100, int(ie_score + vuln_score + exp_score + cfg_score + ctx_score))
        grade, grade_label, risk_level = _grade_and_level_from_score(total_score)

        breakdown = {
            "internet_exposure": {
                "score": round(ie_score, 1),
                "max": 25,
                "evidence": ie_evidence,
            },
            "vulnerability": {
                "score": round(vuln_score, 1),
                "max": 25,
                "evidence": vuln_evidence,
            },
            "exploitability": {
                "score": round(exp_score, 1),
                "max": 20,
                "evidence": exp_evidence,
            },
            "configuration": {
                "score": round(cfg_score, 1),
                "max": 15,
                "evidence": cfg_evidence,
            },
            "asset_context": {
                "score": round(ctx_score, 1),
                "max": 15,
                "evidence": ctx_evidence,
            },
        }

        return {
            "overall_score": total_score,
            "grade": grade,
            "grade_label": grade_label,
            "risk_level": risk_level,
            "breakdown": breakdown,
        }

    def _calc_internet_exposure(self, assets: List[NormalizedAsset]) -> Tuple[float, List[str]]:
        evidence = []
        points = 0.0

        live_assets = [a for a in assets if a.is_live]
        all_ports = set()
        for a in assets:
            all_ports.update(a.ports)

        # Base reachable footprint
        if len(live_assets) >= 1:
            points += 4.0
            evidence.append(f"{len(live_assets)} live internet-facing host(s) observed")

        # Open port count
        port_count = len(all_ports)
        if port_count > 0:
            if port_count <= 2:
                points += 3.0
                evidence.append(f"{port_count} standard listening port(s) open")
            elif port_count <= 5:
                points += 6.0
                evidence.append(f"{port_count} listening port(s) open across attack surface")
            else:
                points += 9.0
                evidence.append(f"Broad listening surface: {port_count} distinct ports open")

        # High risk ports penalty (RDP, SMB, Telnet, Database)
        risky_ports = [p for p in all_ports if p in (21, 23, 445, 3389, 3306, 5432, 27017, 6379)]
        if risky_ports:
            port_penalty = min(12.0, len(risky_ports) * 6.0)
            points += port_penalty
            evidence.append(f"Sensitive service port(s) exposed to public internet: {', '.join(map(str, risky_ports))}")

        return min(25.0, points), evidence

    def _calc_vulnerability_score(self, assets: List[NormalizedAsset]) -> Tuple[float, List[str]]:
        evidence = []
        points = 0.0

        all_vulns = []
        for a in assets:
            all_vulns.extend(a.vulnerabilities)

        if not all_vulns:
            evidence.append("No matching software vulnerabilities identified in known catalogs")
            return 0.0, evidence

        confirmed_vulns = [v for v in all_vulns if v.status == "CONFIRMED"]
        potential_vulns = [v for v in all_vulns if v.status == "POTENTIAL"]

        # Guardrail: Confirmed vulnerabilities carry primary weight
        if confirmed_vulns:
            max_cvss = max(v.cvss for v in confirmed_vulns)
            critical_count = sum(1 for v in confirmed_vulns if v.cvss >= 9.0)
            high_count = sum(1 for v in confirmed_vulns if 7.0 <= v.cvss < 9.0)

            if critical_count > 0:
                points += 18.0
                evidence.append(f"{critical_count} confirmed CRITICAL vulnerability(ies) with max CVSS {max_cvss}")
            elif high_count > 0:
                points += 12.0
                evidence.append(f"{high_count} confirmed HIGH vulnerability(ies) with max CVSS {max_cvss}")
            else:
                points += 6.0
                evidence.append(f"Confirmed medium-severity vulnerabilities detected")

            # Additional confirmed count increments
            extra = min(7.0, (len(confirmed_vulns) - 1) * 2.0)
            points += extra

        # Guardrail: Potential unconfirmed vulnerabilities only receive conservative advisory points (max 5)
        if potential_vulns and not confirmed_vulns:
            points += min(5.0, len(potential_vulns) * 1.5)
            evidence.append(f"{len(potential_vulns)} advisory notice(s): technology present but exact version unconfirmed")

        return min(25.0, points), evidence

    def _calc_exploitability_score(self, assets: List[NormalizedAsset]) -> Tuple[float, List[str]]:
        evidence = []
        points = 0.0

        all_vulns = []
        for a in assets:
            all_vulns.extend(a.vulnerabilities)

        # CISA KEV presence (significant driver)
        kev_hits = [v for v in all_vulns if v.kev and v.status == "CONFIRMED"]
        unconfirmed_kev = [v for v in all_vulns if v.kev and v.status != "CONFIRMED"]

        if kev_hits:
            points += 14.0
            kev_cves = ", ".join(v.cve_id for v in kev_hits[:2])
            evidence.append(f"Confirmed vulnerability in CISA Known Exploited Vulnerabilities catalog: {kev_cves}")
        elif unconfirmed_kev:
            points += 5.0
            evidence.append(f"Technology has KEV-listed CVEs, but active version is unconfirmed")

        # EPSS Score distribution
        confirmed_epss = [v.epss for v in all_vulns if v.status == "CONFIRMED" and v.epss > 0]
        if confirmed_epss:
            max_epss = max(confirmed_epss)
            if max_epss >= 0.5:
                points += 6.0
                evidence.append(f"Very high exploit prediction probability (Max EPSS: {max_epss:.1%})")
            elif max_epss >= 0.15:
                points += 4.0
                evidence.append(f"Elevated exploit prediction probability (Max EPSS: {max_epss:.1%})")
            else:
                points += 1.5
                evidence.append(f"Baseline exploit probability (Max EPSS: {max_epss:.1%})")
        else:
            if not kev_hits and not unconfirmed_kev:
                evidence.append("No elevated active exploitation or high EPSS indicators")

        return min(20.0, points), evidence

    def _calc_configuration_score(self, assets: List[NormalizedAsset]) -> Tuple[float, List[str]]:
        evidence = []
        points = 0.0

        all_exposures = []
        for a in assets:
            all_exposures.extend(a.exposures)

        # Guardrail (Part 10, 13):
        # A normal public website must NOT automatically become HIGH risk because:
        # - CSP is missing
        # - one security header is missing
        # - server header exists

        # Expired TLS is a notable issue
        expired_tls = any(e.type == "tls_cryptographic_weakness" and "expired" in e.title.lower() for e in all_exposures)
        if expired_tls:
            points += 6.0
            evidence.append("Expired SSL/TLS certificate detected")

        # Missing DMARC / SPF on apex
        email_issues = [e for e in all_exposures if e.type == "email_spoofing_exposure"]
        if email_issues:
            points += min(4.0, len(email_issues) * 2.0)
            evidence.append(f"Email domain spoofing exposure: {email_issues[0].title}")

        # Missing HSTS on public HTTPS
        missing_hsts = any(e.finding_id.endswith("missing_hsts") for e in all_exposures)
        if missing_hsts:
            points += 2.0
            evidence.append("HSTS header missing on HTTPS service")

        # Missing CSP & Banner leak: minimal points only
        minor_configs = [e for e in all_exposures if e.finding_id.endswith(("missing_csp", "server_banner_leak"))]
        if minor_configs:
            points += min(2.0, len(minor_configs) * 0.5)
            evidence.append("Standard web hardening opportunities (CSP / server banner suppression)")

        if points == 0.0:
            evidence.append("No major configuration defects detected")

        return min(15.0, points), evidence

    def _calc_asset_context_score(self, assets: List[NormalizedAsset]) -> Tuple[float, List[str]]:
        evidence = []
        points = 0.0

        # Assess criticality distribution
        critical_assets = [a for a in assets if a.asset_criticality in ("critical", "high")]
        med_assets = [a for a in assets if a.asset_criticality == "medium"]

        if critical_assets:
            points += min(10.0, len(critical_assets) * 4.0)
            crit_names = ", ".join(a.hostname for a in critical_assets[:2])
            evidence.append(f"High/Critical assets exposed: {crit_names}")
        elif med_assets:
            points += min(6.0, len(med_assets) * 2.0)
            evidence.append(f"{len(med_assets)} medium-sensitivity asset(s) present")
        else:
            points += 2.0
            evidence.append("All assets classified as standard / informational sensitivity")

        # Multi-domain attack surface complexity
        if len(assets) >= 5:
            points += 3.0
            evidence.append(f"Extended perimeter surface with {len(assets)} unique hostnames")

        return min(15.0, points), evidence
