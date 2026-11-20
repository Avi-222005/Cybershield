"""
CyberShield Exposure Intelligence Engine - Asset Inventory Builder
Aggregates, normalizes, and correlates assets from existing CyberShield scanners into a unified inventory.
"""

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .asset_model import NormalizedAsset, ServiceObservation, TechObservation
from .normalizer import (
    clean_version_string,
    is_ip_address,
    normalize_hostname,
    normalize_ip_address,
    normalize_ports_list,
    normalize_technology_item,
    parse_banner_or_header_technology,
)

SENSITIVE_HOSTNAME_KEYWORDS = {
    "admin": ("high", "Hostname contains 'admin' indicating administrative or management interface"),
    "administrator": ("high", "Hostname contains 'administrator' indicating management portal"),
    "portal": ("medium", "Hostname contains 'portal' indicating potential enterprise login gateway"),
    "auth": ("high", "Hostname contains 'auth' indicating authentication or identity service"),
    "sso": ("high", "Hostname contains 'sso' indicating single sign-on infrastructure"),
    "vpn": ("high", "Hostname contains 'vpn' indicating remote access gateway"),
    "gateway": ("medium", "Hostname contains 'gateway' indicating network entry point"),
    "api": ("medium", "Hostname contains 'api' indicating application programming interface"),
    "dev": ("medium", "Hostname contains 'dev' indicating non-production or development environment"),
    "staging": ("medium", "Hostname contains 'staging' indicating staging or pre-production environment"),
    "test": ("low", "Hostname contains 'test' indicating test environment"),
    "internal": ("high", "Hostname contains 'internal' indicating potentially misrouted private asset"),
    "corp": ("medium", "Hostname contains 'corp' indicating corporate infrastructure"),
    "billing": ("high", "Hostname contains 'billing' indicating financial transaction processing"),
    "payment": ("critical", "Hostname contains 'payment' indicating high-value financial gateway"),
    "db": ("critical", "Hostname contains 'db' indicating database server or endpoint"),
    "database": ("critical", "Hostname contains 'database' indicating data store"),
    "mail": ("medium", "Hostname contains 'mail' indicating email communications infrastructure"),
    "webmail": ("medium", "Hostname contains 'webmail' indicating web email portal"),
}


def infer_asset_criticality(hostname: str) -> Tuple[str, str, bool]:
    """
    Infers potential asset criticality based on hostname keywords.
    Never asserts certainty; always states 'Inferred' with transparent reasoning.
    Returns (criticality_level, reasoning, is_inferred).
    """
    lowered = hostname.lower()
    sub_parts = re.split(r"[.\-_]", lowered)

    for keyword, (level, reason) in SENSITIVE_HOSTNAME_KEYWORDS.items():
        if keyword in sub_parts:
            return level, f"Inferred indicator: {reason}", True

    return "informational", "Standard external asset; no sensitive keywords detected", False


def generate_asset_id(hostname: str, root_domain: str) -> str:
    seed = f"{root_domain.lower()}::{hostname.lower()}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


class AssetInventoryBuilder:
    def __init__(self, root_target: str):
        self.root_target = normalize_hostname(root_target)
        self.assets_by_hostname: Dict[str, NormalizedAsset] = {}
        self.ip_to_hostnames: Dict[str, Set[str]] = {}

    def get_or_create_asset(self, hostname_input: str, is_root: bool = False) -> NormalizedAsset:
        hostname = normalize_hostname(hostname_input)
        if not hostname:
            hostname = self.root_target

        if hostname in self.assets_by_hostname:
            return self.assets_by_hostname[hostname]

        crit_level, crit_reason, is_inferred = infer_asset_criticality(hostname)
        if is_root and crit_level == "informational":
            crit_level = "medium"
            crit_reason = "Apex / Root domain for the organization"

        asset = NormalizedAsset(
            asset_id=generate_asset_id(hostname, self.root_target),
            hostname=hostname,
            root_domain=self.root_target,
            asset_criticality=crit_level,
            criticality_reason=crit_reason,
            criticality_inferred=is_inferred,
        )
        self.assets_by_hostname[hostname] = asset
        return asset

    def ingest_unified_recon(self, recon_result: Dict[str, Any]) -> None:
        """
        Ingests the full output of a Unified Recon scan or individual scanners.
        """
        if not isinstance(recon_result, dict):
            return

        target = recon_result.get("target") or self.root_target
        modules = recon_result.get("modules", {})
        root_asset = self.get_or_create_asset(target, is_root=True)

        # 1. Ingest DNS Pro
        dns_mod = modules.get("dns", {})
        if dns_mod.get("ok"):
            dns_data = dns_mod.get("data", {})
            self._ingest_dns_data(root_asset, dns_data)

        # 2. Ingest Subdomain Discovery
        sub_mod = modules.get("subdomains", {})
        if sub_mod.get("ok"):
            sub_data = sub_mod.get("data", {})
            self._ingest_subdomain_data(sub_data)

        # 3. Ingest Ports & Services (Advanced Network Scan)
        ports_mod = modules.get("ports", {})
        if ports_mod.get("ok"):
            ports_data = ports_mod.get("data", {})
            self._ingest_ports_data(root_asset, ports_data)

        # 4. Ingest Tech Stack Detection
        tech_mod = modules.get("tech", {})
        if tech_mod.get("ok"):
            tech_data = tech_mod.get("data", {})
            self._ingest_tech_data(root_asset, tech_data)

        # 5. Ingest HTTP Headers & Security Audit
        headers_mod = modules.get("headers", {})
        if headers_mod.get("ok"):
            headers_data = headers_mod.get("data", {})
            self._ingest_headers_data(root_asset, headers_data)

        # 6. Ingest SSL Certificate
        ssl_mod = modules.get("ssl", {})
        if ssl_mod.get("ok"):
            ssl_data = ssl_mod.get("data", {})
            self._ingest_ssl_data(root_asset, ssl_data)

        # 7. Ingest WHOIS
        whois_mod = modules.get("whois", {})
        if whois_mod.get("ok"):
            whois_data = whois_mod.get("data", {})
            root_asset.whois = whois_data

    def _ingest_dns_data(self, asset: NormalizedAsset, dns_data: Dict[str, Any]) -> None:
        asset.dns = dns_data

        # A Records
        a_records = dns_data.get("a", {}).get("records", []) if isinstance(dns_data.get("a"), dict) else dns_data.get("A", [])
        for ip in a_records:
            norm_ip = normalize_ip_address(str(ip))
            if norm_ip and norm_ip[1] == "ipv4":
                if norm_ip[0] not in asset.ip_addresses:
                    asset.ip_addresses.append(norm_ip[0])

        # AAAA Records
        aaaa_records = dns_data.get("aaaa", {}).get("records", []) if isinstance(dns_data.get("aaaa"), dict) else dns_data.get("AAAA", [])
        for ip in aaaa_records:
            norm_ip = normalize_ip_address(str(ip))
            if norm_ip and norm_ip[1] == "ipv6":
                if norm_ip[0] not in asset.ipv6_addresses:
                    asset.ipv6_addresses.append(norm_ip[0])

        # Email Security (SPF, DMARC, DKIM, MX)
        spf_info = dns_data.get("spf", {}) if isinstance(dns_data.get("spf"), dict) else {}
        dmarc_info = dns_data.get("dmarc", {}) if isinstance(dns_data.get("dmarc"), dict) else {}
        mx_info = dns_data.get("mx", {}) if isinstance(dns_data.get("mx"), dict) else {}
        asset.email_security = {
            "spf": spf_info,
            "dmarc": dmarc_info,
            "mx": mx_info,
            "dnssec": dns_data.get("dnssec", {}),
        }

    def _ingest_subdomain_data(self, sub_data: Dict[str, Any]) -> None:
        subdomains = sub_data.get("subdomains", [])
        if not isinstance(subdomains, list):
            return

        for sub in subdomains:
            if not isinstance(sub, dict):
                continue
            sub_name = normalize_hostname(sub.get("subdomain") or sub.get("hostname") or "")
            if not sub_name:
                continue

            asset = self.get_or_create_asset(sub_name)
            asset.is_live = bool(sub.get("is_live", sub.get("live", True)))
            asset.subdomain_sources.append("subdomain_finder")

            # Extract IPs
            ip_val = sub.get("ip") or sub.get("ip_address")
            if ip_val:
                ips = [ip_val] if isinstance(ip_val, str) else ip_val
                for i in ips:
                    norm = normalize_ip_address(str(i))
                    if norm:
                        if norm[1] == "ipv4" and norm[0] not in asset.ip_addresses:
                            asset.ip_addresses.append(norm[0])
                        elif norm[1] == "ipv6" and norm[0] not in asset.ipv6_addresses:
                            asset.ipv6_addresses.append(norm[0])

            # HTTP info
            http_status = sub.get("http_status") or sub.get("status_code")
            if http_status:
                asset.http = {
                    "status_code": http_status,
                    "title": sub.get("title", ""),
                    "web_server": sub.get("server", ""),
                }
                # If web server detected
                if sub.get("server"):
                    server_techs = parse_banner_or_header_technology(sub.get("server"))
                    for st in server_techs:
                        norm_t = TechObservation(
                            name=st["name"],
                            normalized_name=st["normalized_name"],
                            version=st["version"],
                            confidence=st["confidence"],
                            categories=st["categories"],
                            evidence=st["evidence"],
                        )
                        if not any(x.name == norm_t.name for x in asset.technologies):
                            asset.technologies.append(norm_t)

    def _ingest_ports_data(self, asset: NormalizedAsset, ports_data: Dict[str, Any]) -> None:
        # Open ports list
        raw_ports = ports_data.get("open_ports", [])
        asset.ports = normalize_ports_list(raw_ports)

        # Services
        services_list = ports_data.get("services", [])
        if isinstance(services_list, list):
            for s in services_list:
                if not isinstance(s, dict):
                    continue
                port_num = int(s.get("port", 0) or 0)
                if not port_num:
                    continue
                banner_str = str(s.get("banner") or "")
                version_str = str(s.get("version") or "")

                service_obs = ServiceObservation(
                    port=port_num,
                    protocol=str(s.get("protocol", "tcp")),
                    service=str(s.get("service", "unknown")),
                    banner=banner_str,
                    version=version_str,
                    is_tls=port_num in (443, 8443) or "ssl" in str(s.get("service", "")).lower(),
                    risk_level=str(s.get("risk_level", "LOW")),
                    evidence=[f"Port {port_num}/{s.get('protocol', 'tcp')} open"] + ([f"Banner: {banner_str}"] if banner_str else []),
                )
                asset.services.append(service_obs)

                # Parse banner technologies
                if banner_str:
                    banner_techs = parse_banner_or_header_technology(banner_str)
                    for bt in banner_techs:
                        t_obs = TechObservation(
                            name=bt["name"],
                            normalized_name=bt["normalized_name"],
                            version=bt["version"],
                            confidence=bt["confidence"],
                            categories=bt["categories"],
                            evidence=[f"Port {port_num} banner: {banner_str}"],
                        )
                        if not any(x.name == t_obs.name for x in asset.technologies):
                            asset.technologies.append(t_obs)

    def _ingest_tech_data(self, asset: NormalizedAsset, tech_data: Dict[str, Any]) -> None:
        detected = tech_data.get("detected", [])
        if isinstance(detected, list):
            for t in detected:
                if not isinstance(t, dict):
                    continue
                norm_t = normalize_technology_item(t)
                obs = TechObservation(
                    name=norm_t["name"],
                    normalized_name=norm_t["normalized_name"],
                    version=norm_t["version"],
                    confidence=norm_t["confidence"],
                    categories=norm_t["categories"],
                    website=norm_t.get("website"),
                    section=norm_t.get("section", "Other"),
                    evidence=norm_t["evidence"],
                )
                # Avoid duplicate names on same asset; prefer higher confidence or version
                existing = next((x for x in asset.technologies if x.name.lower() == obs.name.lower()), None)
                if existing:
                    if obs.version and not existing.version:
                        existing.version = obs.version
                    if obs.confidence > existing.confidence:
                        existing.confidence = obs.confidence
                    for ev in obs.evidence:
                        if ev not in existing.evidence:
                            existing.evidence.append(ev)
                else:
                    asset.technologies.append(obs)

    def _ingest_headers_data(self, asset: NormalizedAsset, headers_data: Dict[str, Any]) -> None:
        asset.headers = headers_data
        server_header = headers_data.get("server") or headers_data.get("raw_headers", {}).get("server")
        if server_header:
            parsed = parse_banner_or_header_technology(str(server_header))
            for pt in parsed:
                obs = TechObservation(
                    name=pt["name"],
                    normalized_name=pt["normalized_name"],
                    version=pt["version"],
                    confidence=pt["confidence"],
                    categories=pt["categories"],
                    evidence=[f"HTTP Server header: {server_header}"],
                )
                existing = next((x for x in asset.technologies if x.name.lower() == obs.name.lower()), None)
                if existing:
                    if obs.version and not existing.version:
                        existing.version = obs.version
                    for ev in obs.evidence:
                        if ev not in existing.evidence:
                            existing.evidence.append(ev)
                else:
                    asset.technologies.append(obs)

    def _ingest_ssl_data(self, asset: NormalizedAsset, ssl_data: Dict[str, Any]) -> None:
        asset.ssl = ssl_data
        # SANs (Subject Alternative Names) can discover additional assets!
        san_list = ssl_data.get("san", []) or ssl_data.get("subject_alternative_names", [])
        if isinstance(san_list, list):
            for san in san_list:
                cleaned_san = normalize_hostname(san)
                if cleaned_san and cleaned_san.endswith(self.root_target) and cleaned_san != asset.hostname:
                    discovered = self.get_or_create_asset(cleaned_san)
                    discovered.subdomain_sources.append("ssl_san")

    def build(self) -> List[NormalizedAsset]:
        """Returns sorted list of normalized assets (apex first, then subdomains)."""
        sorted_assets = sorted(
            self.assets_by_hostname.values(),
            key=lambda a: (a.hostname != self.root_target, a.hostname),
        )
        return sorted_assets
