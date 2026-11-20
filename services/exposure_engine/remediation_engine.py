"""
CyberShield Exposure Intelligence Engine - Remediation Engine
Generates prioritized, actionable, defensive remediation roadmaps for identified exposures and vulnerabilities.
Strictly defensive security engineering guidance (no exploit material).
"""

from typing import Any, Dict, List, Optional

from .asset_model import ExposureFinding, NormalizedAsset


class RemediationEngine:
    def __init__(self):
        pass

    def build_remediation_plan(self, assets: List[NormalizedAsset], exposures: List[ExposureFinding]) -> List[Dict[str, Any]]:
        plan: List[Dict[str, Any]] = []
        seen_keys = set()

        # Sort exposures by priority (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFORMATIONAL)
        priority_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFORMATIONAL": 5}
        sorted_exposures = sorted(exposures, key=lambda e: priority_order.get(e.priority, 99))

        for exp in sorted_exposures:
            # Grouping key to prevent duplicate repetitive advice for identical issues
            key = f"{exp.type}::{exp.cve_id or exp.title}"
            if key in seen_keys:
                # Add asset to affected list of existing item
                for item in plan:
                    if item["group_key"] == key and exp.asset not in item["affected_assets"]:
                        item["affected_assets"].append(exp.asset)
                continue

            seen_keys.add(key)
            item = self._generate_recommendation(exp)
            if item:
                item["group_key"] = key
                item["affected_assets"] = [exp.asset]
                plan.append(item)

        # Assign step numbers
        for idx, item in enumerate(plan, 1):
            item["step_number"] = idx

        return plan

    def _generate_recommendation(self, exp: ExposureFinding) -> Dict[str, Any]:
        priority_label = "P1 - Immediate Action Required" if exp.priority == "CRITICAL" else (
            "P2 - High Priority" if exp.priority == "HIGH" else (
                "P3 - Medium Priority" if exp.priority == "MEDIUM" else "P4 - Routine Hardening"
            )
        )

        effort = "Low"
        steps = []
        verification = "Re-run CyberShield Exposure Assessment to confirm the issue is resolved."

        if exp.type == "vulnerable_internet_facing_service":
            effort = "Medium"
            steps = [
                f"Confirm active version running on {exp.asset}.",
                f"Review vendor security advisory for {exp.cve_id or 'the affected component'}.",
                "Test the patched package release in staging or pre-production.",
                "Deploy the vendor-supported update to production systems.",
                "Restrict unnecessary external internet exposure via firewall or security group if public access is not mandatory.",
            ]
        elif exp.type == "exposed_sensitive_infrastructure":
            effort = "Low"
            steps = [
                f"Verify whether {exp.title} genuinely requires public internet exposure.",
                "Implement IP access restriction or move service behind a secure corporate VPN.",
                "Enforce multi-factor authentication (MFA) and strong credential policies.",
                "Disable legacy unencrypted protocols (e.g. Telnet, FTP) in favor of modern encrypted alternatives (SSH, SFTP).",
            ]
        elif exp.type == "tls_cryptographic_weakness":
            effort = "Low"
            steps = [
                "Generate a new Certificate Signing Request (CSR) with 2048-bit or 4096-bit RSA/ECC key.",
                "Obtain and install a valid certificate issued by an authorized public CA.",
                "Configure automated certificate renewal (e.g. Certbot / ACME protocol) to prevent future expirations.",
            ]
        elif exp.type == "email_spoofing_exposure":
            effort = "Low"
            if "dmarc" in exp.title.lower():
                steps = [
                    "Draft a DMARC policy starting in monitoring mode: 'v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com'.",
                    "Monitor aggregated DMARC reports for legitimate outbound email senders.",
                    "Gradually advance policy to 'p=quarantine' and ultimately 'p=reject' to block unauthorized spoofing.",
                ]
            else:
                steps = [
                    "Identify all authorized outbound email sources (Google Workspace, Microsoft 365, Mailgun, SendGrid, etc.).",
                    "Publish a unified DNS SPF TXT record: 'v=spf1 include:_spf.example.com ~all'.",
                    "Validate syntax using CyberShield DNS Lookup Pro.",
                ]
        elif exp.type == "web_security_misconfiguration":
            effort = "Low"
            if "csp" in exp.title.lower():
                steps = [
                    "Inventory all legitimate script, style, and media sources used by the web application.",
                    "Deploy a Content-Security-Policy in Report-Only mode to test for unintended breakage.",
                    "Enforce the policy with strict directives: default-src 'self'; script-src 'self' ...",
                ]
            elif "hsts" in exp.title.lower():
                steps = [
                    "Ensure all HTTP endpoints redirect automatically to HTTPS with 301 Permanent Redirect.",
                    "Inject the HSTS header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                ]
            elif "banner" in exp.title.lower():
                steps = [
                    "Update web server configuration to suppress version banners (e.g., 'ServerTokens Prod' in Apache or 'server_tokens off' in nginx).",
                    "Reload the web server service.",
                ]
            else:
                steps = [
                    "Audit web server configuration files against OWASP Secure Headers guidelines.",
                    "Add missing security headers in reverse proxy or web server configuration.",
                ]
        else:
            steps = [
                f"Review finding details for {exp.title}.",
                "Apply relevant configuration hardening following vendor best practices.",
                "Verify service behavior and accessibility.",
            ]

        return {
            "finding_id": exp.finding_id,
            "title": exp.title,
            "priority": exp.priority,
            "priority_label": priority_label,
            "severity": exp.severity,
            "category": exp.category,
            "effort": effort,
            "reason": exp.reason,
            "remediation_summary": exp.remediation,
            "steps": steps,
            "verification": verification,
        }
