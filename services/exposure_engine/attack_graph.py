"""
CyberShield Exposure Intelligence Engine - Attack Surface Graph
Builds nodes, edges, and passive Potential Exposure Paths representing the external perimeter.
"""

from typing import Any, Dict, List, Optional, Set

from .asset_model import NormalizedAsset


class AttackSurfaceGraphBuilder:
    def __init__(self, root_target: str):
        self.root_target = root_target.lower()
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.paths: List[Dict[str, Any]] = []
        self._node_ids: Set[str] = set()
        self._edge_ids: Set[str] = set()

    def add_node(self, node_id: str, label: str, node_type: str, severity: str = "INFO", data: Optional[Dict[str, Any]] = None) -> None:
        if node_id in self._node_ids:
            return
        self._node_ids.add(node_id)
        self.nodes.append({
            "id": node_id,
            "label": label,
            "type": node_type,
            "severity": severity,
            "data": data or {},
        })

    def add_edge(self, source_id: str, target_id: str, relation: str) -> None:
        edge_id = f"{source_id}->{relation}->{target_id}"
        if edge_id in self._edge_ids:
            return
        self._edge_ids.add(edge_id)
        self.edges.append({
            "id": edge_id,
            "source": source_id,
            "target": target_id,
            "label": relation,
        })

    def build_from_assets(self, assets: List[NormalizedAsset]) -> Dict[str, Any]:
        # 1. Internet Entrypoint Node
        internet_node_id = "internet"
        self.add_node(
            internet_node_id,
            "Public Internet",
            "Internet",
            severity="INFO",
            data={"description": "External unauthenticated attacker perspective"}
        )

        # 2. Apex / Root Domain Node
        root_node_id = f"domain:{self.root_target}"
        self.add_node(
            root_node_id,
            self.root_target,
            "Domain",
            severity="LOW",
            data={"root_domain": self.root_target}
        )
        self.add_edge(internet_node_id, root_node_id, "resolves_to")

        path_counter = 1

        for asset in assets:
            is_apex = asset.hostname == self.root_target
            host_node_id = root_node_id if is_apex else f"subdomain:{asset.hostname}"

            if not is_apex:
                host_sev = "HIGH" if asset.asset_criticality in ("high", "critical") else "LOW"
                self.add_node(
                    host_node_id,
                    asset.hostname,
                    "Subdomain",
                    severity=host_sev,
                    data={
                        "hostname": asset.hostname,
                        "criticality": asset.asset_criticality,
                        "criticality_reason": asset.criticality_reason,
                        "is_live": asset.is_live,
                    }
                )
                self.add_edge(root_node_id, host_node_id, "hosts")
                self.add_edge(internet_node_id, host_node_id, "resolves_to")

            # Link IP Addresses
            for ip in asset.ip_addresses:
                ip_node_id = f"ip:{ip}"
                self.add_node(
                    ip_node_id,
                    ip,
                    "IP",
                    severity="INFO",
                    data={"ip_address": ip, "version": "IPv4"}
                )
                self.add_edge(host_node_id, ip_node_id, "resolves_to")

                # Link Ports to IP/Host
                for port in asset.ports:
                    port_node_id = f"port:{asset.hostname}:{port}"
                    port_sev = "HIGH" if port in (21, 23, 445, 3389, 3306, 5432, 27017, 6379) else "LOW"
                    self.add_node(
                        port_node_id,
                        f"Port {port}",
                        "Port",
                        severity=port_sev,
                        data={"port": port, "protocol": "tcp", "hostname": asset.hostname}
                    )
                    self.add_edge(ip_node_id, port_node_id, "exposes")

            # Link SSL Certificate
            if asset.ssl and asset.ssl.get("issuer"):
                ssl_id = f"ssl:{asset.hostname}"
                ssl_sev = "HIGH" if asset.ssl.get("expired") else "LOW"
                self.add_node(
                    ssl_id,
                    f"TLS: {asset.ssl.get('issuer', 'CA')[:18]}",
                    "Certificate",
                    severity=ssl_sev,
                    data=asset.ssl
                )
                self.add_edge(host_node_id, ssl_id, "secured_by")

            # Link Technologies & Vulnerabilities
            for tech in asset.technologies:
                tech_node_id = f"tech:{asset.hostname}:{tech.normalized_name}"
                self.add_node(
                    tech_node_id,
                    f"{tech.name} {tech.version}".strip(),
                    "Technology",
                    severity="INFO",
                    data=tech.to_dict()
                )
                self.add_edge(host_node_id, tech_node_id, "runs")

            # Link Vulnerabilities & Build Potential Exposure Paths (Part 19)
            for vuln in asset.vulnerabilities:
                cve_node_id = f"cve:{vuln.cve_id}"
                cve_sev = "CRITICAL" if vuln.kev or vuln.cvss >= 9.0 else ("HIGH" if vuln.cvss >= 7.0 else "MEDIUM")
                self.add_node(
                    cve_node_id,
                    f"{vuln.cve_id} (CVSS {vuln.cvss})",
                    "CVE",
                    severity=cve_sev,
                    data=vuln.to_dict()
                )

                # Connect technology to CVE
                matching_tech_id = f"tech:{asset.hostname}:{tech.normalized_name}"
                self.add_edge(host_node_id, cve_node_id, "affected_by")

                # Generate Potential Exposure Path
                resolved_ip = asset.ip_addresses[0] if asset.ip_addresses else "Reachable Endpoint"
                primary_port = asset.ports[0] if asset.ports else 443
                self.paths.append({
                    "path_id": f"PATH-{path_counter}",
                    "title": f"External Exposure: {vuln.technology} ({vuln.cve_id})",
                    "severity": cve_sev,
                    "target_asset": asset.hostname,
                    "cve_id": vuln.cve_id,
                    "kev": vuln.kev,
                    "epss": vuln.epss,
                    "steps": [
                        {"step": 1, "title": "Internet Origin", "detail": "Public Internet Unauthenticated Request"},
                        {"step": 2, "title": "DNS Routing", "detail": f"Target Hostname: {asset.hostname}"},
                        {"step": 3, "title": "IP Reachability", "detail": f"Public IP Address: {resolved_ip}"},
                        {"step": 4, "title": "Service Access", "detail": f"Exposed Port {primary_port} (TCP)"},
                        {"step": 5, "title": "Software Stack", "detail": f"Running {vuln.technology} {vuln.detected_version or ''}".strip()},
                        {"step": 6, "title": "Known Vulnerability", "detail": f"{vuln.cve_id} (CVSS {vuln.cvss}{', CISA KEV Exploited' if vuln.kev else ''})"},
                    ],
                    "risk_summary": f"Potential exposure vector through internet-reachable service running {vuln.technology}.",
                })
                path_counter += 1

            # High Risk Port Paths
            risky_ports = [p for p in asset.ports if p in (21, 23, 445, 3389, 3306, 5432, 27017, 6379)]
            for rp in risky_ports:
                resolved_ip = asset.ip_addresses[0] if asset.ip_addresses else "Reachable Endpoint"
                self.paths.append({
                    "path_id": f"PATH-{path_counter}",
                    "title": f"Exposed Sensitive Service: Port {rp}",
                    "severity": "HIGH",
                    "target_asset": asset.hostname,
                    "steps": [
                        {"step": 1, "title": "Internet Origin", "detail": "Public Internet Network Scanner"},
                        {"step": 2, "title": "Host Resolution", "detail": f"{asset.hostname} -> {resolved_ip}"},
                        {"step": 3, "title": "Direct Port Ingress", "detail": f"Unrestricted Port {rp} Exposure"},
                        {"step": 4, "title": "Exposure Vector", "detail": "Direct authentication prompt or unauthenticated service protocol access"},
                    ],
                    "risk_summary": f"Port {rp} is directly accessible from the public internet without perimeter firewall restriction.",
                })
                path_counter += 1

        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "paths": self.paths,
            "metrics": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "potential_exposure_paths": len(self.paths),
            }
        }
