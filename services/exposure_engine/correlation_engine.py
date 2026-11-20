"""
CyberShield Exposure Intelligence Engine - Exposure Correlation Engine
Correlates multi-source observations across internet exposure, open ports, technologies,
vulnerabilities, CISA KEV, EPSS, SSL/TLS, DNS, and HTTP security headers into high-confidence, context-aware findings.
"""

import hashlib
from typing import Any, Dict, List, Optional, Tuple

from .asset_model import ExposureFinding, NormalizedAsset, VulnerabilityFinding

RISKY_PORTS_METADATA = {
    21: ("FTP Cleartext File Transfer", "HIGH", "Exposed FTP service transmits credentials unencrypted over the internet."),
    23: ("Telnet Unencrypted Remote Shell", "CRITICAL", "Telnet protocol transmits all session data and credentials in plaintext."),
    445: ("SMB Windows File Sharing", "CRITICAL", "SMB protocol exposed directly to internet is a prime target for ransomware and wormable exploits."),
    3389: ("RDP Remote Desktop Protocol", "HIGH", "Exposed RDP port allows direct brute-force and remote desktop credential stuffing attacks."),
    3306: ("MySQL Database Server", "HIGH", "Direct internet access to MySQL database server allows external authentication attempts."),
    5432: ("PostgreSQL Database Server", "HIGH", "Direct internet access to PostgreSQL database exposes sensitive data store to internet."),
    27017: ("MongoDB NoSQL Database", "HIGH", "Exposed MongoDB instance risks unauthenticated data access or ransom."),
    6379: ("Redis In-Memory Store", "CRITICAL", "Unprotected Redis instances often lack authentication and allow arbitrary remote file write or RCE."),
    9200: ("Elasticsearch Cluster Endpoint", "HIGH", "Exposed Elasticsearch REST API risks unauthorized index exfiltration."),
    8080: ("Alternative HTTP / Proxy Port", "LOW", "Alternative web service running on non-standard port 8080."),
    8443: ("Alternative HTTPS Port", "LOW", "Alternative TLS web service running on port 8443."),
}


def generate_finding_id(asset: str, finding_type: str, differentiator: str = "") -> str:
    raw = f"{asset.lower()}::{finding_type.lower()}::{differentiator.lower()}"
    return f"EXP-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12].upper()}"


class ExposureCorrelationEngine:
    def __init__(self):
        pass

    def correlate_asset_exposures(self, asset: NormalizedAsset) -> List[ExposureFinding]:
        """
        Evaluates an individual asset and correlates its multi-layer observations into exposure findings.
        """
        exposures: List[ExposureFinding] = []

        # 1. Correlate Vulnerable Internet-Facing Services (Part 9)
        self._correlate_vulnerabilities(asset, exposures)

        # 2. Correlate Risky & Exposed Ports / Protocols
        self._correlate_exposed_ports(asset, exposures)

        # 3. Correlate TLS / SSL Cryptographic Weaknesses
        self._correlate_ssl_exposures(asset, exposures)

        # 4. Correlate HTTP Security Headers & Web Config
        self._correlate_http_security(asset, exposures)

        # 5. Correlate DNS & Email Spoofing Protections
        self._correlate_dns_email_security(asset, exposures)

        asset.exposures = exposures
        return exposures

    def _correlate_vulnerabilities(self, asset: NormalizedAsset, exposures: List[ExposureFinding]) -> None:
        for vuln in asset.vulnerabilities:
            # Check if this vuln runs on an internet-facing open port
            open_port_matching = next(
                (p for p in asset.ports if p in (80, 443, 8080, 8443, 8000, 22, 21)),
                None
            )

            severity = "HIGH"
            priority = "HIGH"
            confidence = 90 if vuln.status == "CONFIRMED" else 65

            if vuln.kev:
                severity = "CRITICAL"
                priority = "CRITICAL"
                confidence = max(confidence, 92)
            elif vuln.cvss >= 9.0 and vuln.epss >= 0.2:
                severity = "CRITICAL"
                priority = "CRITICAL"
            elif vuln.cvss < 7.0 and not vuln.kev:
                severity = "MEDIUM"
                priority = "MEDIUM"

            if vuln.status == "POTENTIAL":
                # Guardrail: never mark unconfirmed versions as CRITICAL priority
                if priority == "CRITICAL":
                    priority = "HIGH"
                if severity == "CRITICAL":
                    severity = "HIGH"
                confidence = min(confidence, 60)

            reason_parts = []
            if vuln.status == "CONFIRMED":
                reason_parts.append(f"Confirmed vulnerable version '{vuln.detected_version}' of {vuln.technology} detected")
            else:
                reason_parts.append(f"{vuln.technology} detected with unconfirmed version; potentially affected by {vuln.cve_id}")

            if vuln.kev:
                reason_parts.append("listed in CISA Known Exploited Vulnerabilities catalog (actively targeted in the wild)")
            if vuln.epss >= 0.2:
                reason_parts.append(f"high exploit prediction score (EPSS: {vuln.epss:.1%})")

            title = f"{'Known Exploited: ' if vuln.kev else ''}{vuln.technology} Vulnerability ({vuln.cve_id})"

            evidence_items = list(vuln.evidence)
            if open_port_matching:
                evidence_items.append(f"Accessible via internet-facing port {open_port_matching}")
            if asset.ip_addresses:
                evidence_items.append(f"Resolved to public IP(s): {', '.join(asset.ip_addresses[:2])}")

            exposures.append(
                ExposureFinding(
                    finding_id=generate_finding_id(asset.hostname, "vulnerable_service", vuln.cve_id),
                    type="vulnerable_internet_facing_service",
                    title=title,
                    asset=asset.hostname,
                    severity=severity,
                    priority=priority,
                    confidence=confidence,
                    status=vuln.status,
                    reason="; ".join(reason_parts),
                    evidence=evidence_items,
                    cve_id=vuln.cve_id,
                    remediation=vuln.remediation or f"Upgrade {vuln.technology} to latest secure release.",
                    category="Vulnerability",
                )
            )

    def _correlate_exposed_ports(self, asset: NormalizedAsset, exposures: List[ExposureFinding]) -> None:
        for port in asset.ports:
            if port in RISKY_PORTS_METADATA:
                name, sev, desc = RISKY_PORTS_METADATA[port]
                # If port 8080/8443, only report as informational or low
                if port in (8080, 8443):
                    continue

                priority = "HIGH" if sev == "CRITICAL" else "MEDIUM"
                exposures.append(
                    ExposureFinding(
                        finding_id=generate_finding_id(asset.hostname, "risky_port", str(port)),
                        type="exposed_sensitive_infrastructure",
                        title=f"Exposed {name} (Port {port})",
                        asset=asset.hostname,
                        severity=sev,
                        priority=priority,
                        confidence=95,
                        status="CONFIRMED",
                        reason=f"Port {port} is directly reachable on public internet-facing asset.",
                        evidence=[
                            f"Port {port}/tcp open",
                            f"Identified service: {name}",
                            f"Risk description: {desc}",
                        ],
                        remediation=f"Block inbound public internet traffic to port {port} via firewall or VPN access control list.",
                        category="Infrastructure",
                    )
                )

    def _correlate_ssl_exposures(self, asset: NormalizedAsset, exposures: List[ExposureFinding]) -> None:
        ssl_info = asset.ssl
        if not ssl_info:
            return

        is_valid = ssl_info.get("valid", True)
        is_expired = ssl_info.get("expired", False)
        days_left = ssl_info.get("days_left") or ssl_info.get("days_until_expiry")
        issues = ssl_info.get("issues", [])

        if is_expired:
            exposures.append(
                ExposureFinding(
                    finding_id=generate_finding_id(asset.hostname, "ssl_expired"),
                    type="tls_cryptographic_weakness",
                    title="Expired SSL/TLS Certificate",
                    asset=asset.hostname,
                    severity="HIGH",
                    priority="HIGH",
                    confidence=95,
                    status="CONFIRMED",
                    reason="The active TLS certificate has passed its expiration date, triggering browser security warnings.",
                    evidence=[
                        f"Certificate expired for {asset.hostname}",
                        f"Issuer: {ssl_info.get('issuer', 'Unknown')}",
                        f"Expiry Date: {ssl_info.get('valid_to', 'N/A')}",
                    ],
                    remediation="Renew and deploy an active TLS certificate from an authorized Certificate Authority immediately.",
                    category="Cryptography",
                )
            )
        elif days_left is not None and isinstance(days_left, (int, float)) and 0 < days_left <= 14:
            exposures.append(
                ExposureFinding(
                    finding_id=generate_finding_id(asset.hostname, "ssl_expiring_soon"),
                    type="tls_cryptographic_weakness",
                    title=f"SSL/TLS Certificate Expiring Soon ({int(days_left)} days remaining)",
                    asset=asset.hostname,
                    severity="MEDIUM",
                    priority="MEDIUM",
                    confidence=95,
                    status="CONFIRMED",
                    reason=f"The certificate will expire in {int(days_left)} days.",
                    evidence=[
                        f"Days until expiry: {int(days_left)}",
                        f"Expiry Date: {ssl_info.get('valid_to', 'N/A')}",
                    ],
                    remediation="Renew the certificate before expiration to avoid service interruption and security warnings.",
                    category="Cryptography",
                )
            )

        if not is_valid and not is_expired:
            exposures.append(
                ExposureFinding(
                    finding_id=generate_finding_id(asset.hostname, "ssl_invalid"),
                    type="tls_cryptographic_weakness",
                    title="Invalid or Untrusted SSL/TLS Certificate",
                    asset=asset.hostname,
                    severity="HIGH",
                    priority="HIGH",
                    confidence=90,
                    status="CONFIRMED",
                    reason="The TLS certificate failed validation checks (e.g. self-signed, untrusted CA, or hostname mismatch).",
                    evidence=list(issues) or [f"Certificate validation failed on {asset.hostname}"],
                    remediation="Install a valid certificate issued by a trusted public Certificate Authority covering this domain.",
                    category="Cryptography",
                )
            )

    def _correlate_http_security(self, asset: NormalizedAsset, exposures: List[ExposureFinding]) -> None:
        headers = asset.headers
        if not headers:
            return

        missing_headers = headers.get("missing_headers", [])
        raw_headers = headers.get("headers", {}) or headers.get("raw_headers", {})

        # Guardrail (Part 10, Part 13):
        # Missing CSP alone is LOW / INFO!
        # Do not make every missing header a critical issue!
        if "Content-Security-Policy" in missing_headers:
            exposures.append(
                ExposureFinding(
                    finding_id=generate_finding_id(asset.hostname, "missing_csp"),
                    type="web_security_misconfiguration",
                    title="Missing Content-Security-Policy (CSP)",
                    asset=asset.hostname,
                    severity="LOW",
                    priority="INFORMATIONAL",
                    confidence=90,
                    status="INFORMATIONAL",
                    reason="No Content-Security-Policy header detected on web responses, increasing vulnerability to client-side injection.",
                    evidence=["Header 'Content-Security-Policy' was not present in HTTP response"],
                    remediation="Define a strict Content-Security-Policy to restrict unauthorized script execution and data exfiltration.",
                    category="Configuration",
                )
            )

        # Missing HSTS on public web assets
        if "Strict-Transport-Security" in missing_headers and 443 in asset.ports:
            exposures.append(
                ExposureFinding(
                    finding_id=generate_finding_id(asset.hostname, "missing_hsts"),
                    type="web_security_misconfiguration",
                    title="Missing HTTP Strict Transport Security (HSTS)",
                    asset=asset.hostname,
                    severity="MEDIUM",
                    priority="LOW",
                    confidence=90,
                    status="LIKELY",
                    reason="HSTS is not enforced on this HTTPS-capable host, leaving users vulnerable to SSL stripping attacks.",
                    evidence=["Header 'Strict-Transport-Security' missing on HTTPS service"],
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
                    category="Configuration",
                )
            )

        # Server banner disclosure
        server_val = raw_headers.get("server") or raw_headers.get("Server")
        if server_val and any(char.isdigit() for char in str(server_val)):
            exposures.append(
                ExposureFinding(
                    finding_id=generate_finding_id(asset.hostname, "server_banner_leak"),
                    type="web_security_misconfiguration",
                    title="Detailed Web Server Version Disclosure",
                    asset=asset.hostname,
                    severity="LOW",
                    priority="INFORMATIONAL",
                    confidence=95,
                    status="CONFIRMED",
                    reason="The Server HTTP response header reveals specific software name and version information.",
                    evidence=[f"Server header: {server_val}"],
                    remediation="Configure the web server to suppress granular version banners (e.g., 'ServerTokens Prod' in Apache or 'server_tokens off' in nginx).",
                    category="Configuration",
                )
            )

    def _correlate_dns_email_security(self, asset: NormalizedAsset, exposures: List[ExposureFinding]) -> None:
        email_sec = asset.email_security
        if not email_sec or asset.hostname != asset.root_domain:
            # Only evaluate SPF/DMARC at apex domain level
            return

        dmarc = email_sec.get("dmarc", {})
        spf = email_sec.get("spf", {})

        # DMARC check
        dmarc_records = dmarc.get("records", []) if isinstance(dmarc, dict) else []
        if not dmarc_records:
            exposures.append(
                ExposureFinding(
                    finding_id=generate_finding_id(asset.hostname, "missing_dmarc"),
                    type="email_spoofing_exposure",
                    title="Missing DMARC Policy Record",
                    asset=asset.hostname,
                    severity="MEDIUM",
                    priority="MEDIUM",
                    confidence=95,
                    status="CONFIRMED",
                    reason="No DMARC record exists on the apex domain, permitting unauthenticated senders to spoof emails from this domain.",
                    evidence=["DNS TXT query for _dmarc.{asset.hostname} returned no policy record"],
                    remediation="Publish a DMARC TXT record under '_dmarc.{asset.hostname}' starting with 'v=DMARC1; p=quarantine;'.",
                    category="Configuration",
                )
            )

        # SPF check
        spf_records = spf.get("records", []) if isinstance(spf, dict) else []
        if not spf_records:
            exposures.append(
                ExposureFinding(
                    finding_id=generate_finding_id(asset.hostname, "missing_spf"),
                    type="email_spoofing_exposure",
                    title="Missing SPF Record",
                    asset=asset.hostname,
                    severity="LOW",
                    priority="LOW",
                    confidence=95,
                    status="CONFIRMED",
                    reason="No Sender Policy Framework (SPF) record was detected.",
                    evidence=["DNS TXT query returned no valid SPF definition starting with 'v=spf1'"],
                    remediation="Define a valid SPF record specifying authorized outbound email mail-exchangers (e.g., 'v=spf1 mx -all').",
                    category="Configuration",
                )
            )
