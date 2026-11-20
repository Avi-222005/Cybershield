"""
CyberShield Exposure Intelligence Engine - Asset Model
Defines normalized data structures for external attack surface assets, observations, and findings.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class TechObservation:
    name: str
    normalized_name: str
    version: str = ""
    confidence: int = 0
    categories: List[str] = field(default_factory=list)
    website: Optional[str] = None
    section: str = "Other"
    evidence: List[str] = field(default_factory=list)
    cpe: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "normalized_name": self.normalized_name,
            "version": self.version,
            "confidence": self.confidence,
            "categories": list(self.categories),
            "website": self.website,
            "section": self.section,
            "evidence": list(self.evidence),
            "cpe": self.cpe,
        }


@dataclass
class ServiceObservation:
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    banner: str = ""
    version: str = ""
    is_tls: bool = False
    risk_level: str = "LOW"
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
            "is_tls": self.is_tls,
            "risk_level": self.risk_level,
            "evidence": list(self.evidence),
        }


@dataclass
class VulnerabilityFinding:
    cve_id: str
    technology: str
    detected_version: str
    affected: bool
    status: str  # CONFIRMED, LIKELY, POTENTIAL, INFORMATIONAL
    cvss: float = 0.0
    cvss_severity: str = "UNKNOWN"
    epss: float = 0.0
    epss_percentile: float = 0.0
    kev: bool = False
    kev_date_added: Optional[str] = None
    summary: str = ""
    affected_version_range: str = ""
    evidence: List[str] = field(default_factory=list)
    source: str = "CyberShield Threat Intelligence"
    remediation: str = ""
    published_date: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "technology": self.technology,
            "detected_version": self.detected_version,
            "affected": self.affected,
            "status": self.status,
            "cvss": self.cvss,
            "cvss_severity": self.cvss_severity,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "kev": self.kev,
            "kev_date_added": self.kev_date_added,
            "summary": self.summary,
            "affected_version_range": self.affected_version_range,
            "evidence": list(self.evidence),
            "source": self.source,
            "remediation": self.remediation,
            "published_date": self.published_date,
        }


@dataclass
class ExposureFinding:
    finding_id: str
    type: str
    title: str
    asset: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    priority: str  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    confidence: int  # 0 - 100
    status: str  # CONFIRMED, LIKELY, POTENTIAL, INFORMATIONAL
    reason: str
    evidence: List[str] = field(default_factory=list)
    cve_id: Optional[str] = None
    remediation: str = ""
    category: str = "general"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "type": self.type,
            "title": self.title,
            "asset": self.asset,
            "severity": self.severity,
            "priority": self.priority,
            "confidence": self.confidence,
            "status": self.status,
            "reason": self.reason,
            "evidence": list(self.evidence),
            "cve_id": self.cve_id,
            "remediation": self.remediation,
            "category": self.category,
        }


@dataclass
class NormalizedAsset:
    asset_id: str
    hostname: str
    root_domain: str
    ip_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    services: List[ServiceObservation] = field(default_factory=list)
    technologies: List[TechObservation] = field(default_factory=list)
    ssl: Dict[str, Any] = field(default_factory=dict)
    dns: Dict[str, Any] = field(default_factory=dict)
    http: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, Any] = field(default_factory=dict)
    email_security: Dict[str, Any] = field(default_factory=dict)
    whois: Dict[str, Any] = field(default_factory=dict)
    subdomain_sources: List[str] = field(default_factory=list)
    is_live: bool = True
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    asset_criticality: str = "unknown"  # unknown, informational, low, medium, high, critical
    criticality_reason: str = "Default unclassified asset"
    criticality_inferred: bool = False
    exposures: List[ExposureFinding] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    risk_score: int = 0
    risk_breakdown: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "root_domain": self.root_domain,
            "ip_addresses": list(self.ip_addresses),
            "ipv6_addresses": list(self.ipv6_addresses),
            "ports": list(self.ports),
            "services": [s.to_dict() for s in self.services],
            "technologies": [t.to_dict() for t in self.technologies],
            "ssl": self.ssl,
            "dns": self.dns,
            "http": self.http,
            "headers": self.headers,
            "email_security": self.email_security,
            "whois": self.whois,
            "subdomain_sources": list(self.subdomain_sources),
            "is_live": self.is_live,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "asset_criticality": self.asset_criticality,
            "criticality_reason": self.criticality_reason,
            "criticality_inferred": self.criticality_inferred,
            "exposures": [e.to_dict() for e in self.exposures],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "risk_score": self.risk_score,
            "risk_breakdown": self.risk_breakdown,
        }
