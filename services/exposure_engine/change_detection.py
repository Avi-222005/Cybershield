"""
CyberShield Exposure Intelligence Engine - Change Detection Engine
Detects perimeter drift and security changes between external scan snapshots.
"""

from typing import Any, Dict, List, Optional, Set

from .asset_model import NormalizedAsset


class ChangeDetectionEngine:
    def __init__(self):
        pass

    def compare_snapshots(
        self,
        target: str,
        current_assets: List[NormalizedAsset],
        current_score: int,
        previous_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compares current scan data against previous scan snapshot.
        If previous_data is None or empty, returns baseline state with has_changes=False.
        """
        if not previous_data:
            return {
                "target": target,
                "has_previous_scan": False,
                "has_changes": False,
                "score_delta": 0,
                "current_score": current_score,
                "previous_score": None,
                "new_subdomains": [],
                "removed_subdomains": [],
                "new_ips": [],
                "removed_ips": [],
                "new_ports": [],
                "closed_ports": [],
                "new_technologies": [],
                "changed_technologies": [],
                "new_vulnerabilities": [],
                "resolved_vulnerabilities": [],
                "new_exposures": [],
                "resolved_exposures": [],
                "summary": "Initial baseline scan. Future scans will track perimeter drift and security changes.",
            }

        prev_score = int(previous_data.get("overall_score") or previous_data.get("exposure_score") or 0)
        prev_assets = previous_data.get("assets", [])

        # Hostnames
        curr_hosts: Set[str] = {a.hostname.lower() for a in current_assets}
        prev_hosts: Set[str] = set()

        # IPs
        curr_ips: Set[str] = set()
        for a in current_assets:
            curr_ips.update(a.ip_addresses)
            curr_ips.update(a.ipv6_addresses)
        prev_ips: Set[str] = set()

        # Ports: (hostname, port)
        curr_ports: Set[str] = set()
        for a in current_assets:
            for p in a.ports:
                curr_ports.add(f"{a.hostname}:{p}")
        prev_ports: Set[str] = set()

        # Techs: (hostname, tech_name, version)
        curr_techs: Dict[str, str] = {}
        for a in current_assets:
            for t in a.technologies:
                curr_techs[f"{a.hostname}:{t.name}"] = t.version
        prev_techs: Dict[str, str] = {}

        # CVEs: (hostname, cve_id)
        curr_cves: Set[str] = set()
        for a in current_assets:
            for v in a.vulnerabilities:
                curr_cves.add(f"{a.hostname}:{v.cve_id}")
        prev_cves: Set[str] = set()

        # Exposures: (hostname, type)
        curr_exposures: Set[str] = set()
        for a in current_assets:
            for e in a.exposures:
                curr_exposures.add(f"{a.hostname}:{e.type}:{e.cve_id or ''}")
        prev_exposures: Set[str] = set()

        # Extract from previous assets
        for pa in prev_assets:
            if not isinstance(pa, dict):
                continue
            h = str(pa.get("hostname", "")).lower()
            if h:
                prev_hosts.add(h)
            for ip in pa.get("ip_addresses", []):
                prev_ips.add(str(ip))
            for p in pa.get("ports", []):
                prev_ports.add(f"{h}:{p}")
            for t in pa.get("technologies", []):
                if isinstance(t, dict):
                    t_name = t.get("name", "")
                    if t_name:
                        prev_techs[f"{h}:{t_name}"] = str(t.get("version", ""))
            for v in pa.get("vulnerabilities", []):
                if isinstance(v, dict) and v.get("cve_id"):
                    prev_cves.add(f"{h}:{v['cve_id']}")
            for e in pa.get("exposures", []):
                if isinstance(e, dict):
                    prev_exposures.add(f"{h}:{e.get('type')}:{e.get('cve_id', '')}")

        # Compute Diffs
        new_subdomains = sorted(list(curr_hosts - prev_hosts))
        removed_subdomains = sorted(list(prev_hosts - curr_hosts))

        new_ips = sorted(list(curr_ips - prev_ips))
        removed_ips = sorted(list(prev_ips - curr_ips))

        new_ports_raw = curr_ports - prev_ports
        closed_ports_raw = prev_ports - curr_ports

        new_ports = [{"host": item.split(":")[0], "port": int(item.split(":")[1])} for item in new_ports_raw if ":" in item]
        closed_ports = [{"host": item.split(":")[0], "port": int(item.split(":")[1])} for item in closed_ports_raw if ":" in item]

        # Tech changes
        new_technologies = []
        changed_technologies = []
        for key, curr_v in curr_techs.items():
            h, t_name = key.split(":", 1)
            if key not in prev_techs:
                new_technologies.append({"host": h, "technology": t_name, "version": curr_v})
            elif prev_techs[key] != curr_v:
                changed_technologies.append({
                    "host": h,
                    "technology": t_name,
                    "previous_version": prev_techs[key],
                    "current_version": curr_v,
                })

        new_vulns_raw = curr_cves - prev_cves
        resolved_vulns_raw = prev_cves - curr_cves
        new_vulnerabilities = [{"host": item.split(":")[0], "cve_id": item.split(":")[1]} for item in new_vulns_raw if ":" in item]
        resolved_vulnerabilities = [{"host": item.split(":")[0], "cve_id": item.split(":")[1]} for item in resolved_vulns_raw if ":" in item]

        new_exp_raw = curr_exposures - prev_exposures
        resolved_exp_raw = prev_exposures - curr_exposures
        new_exposures = [item for item in new_exp_raw]
        resolved_exposures = [item for item in resolved_exp_raw]

        score_delta = current_score - prev_score
        has_changes = any([
            new_subdomains,
            removed_subdomains,
            new_ips,
            removed_ips,
            new_ports,
            closed_ports,
            new_technologies,
            changed_technologies,
            new_vulnerabilities,
            resolved_vulnerabilities,
        ])

        summary_parts = []
        if new_subdomains:
            summary_parts.append(f"+{len(new_subdomains)} new subdomain(s)")
        if removed_subdomains:
            summary_parts.append(f"-{len(removed_subdomains)} removed subdomain(s)")
        if new_ports:
            summary_parts.append(f"+{len(new_ports)} newly opened port(s)")
        if closed_ports:
            summary_parts.append(f"-{len(closed_ports)} closed port(s)")
        if new_vulnerabilities:
            summary_parts.append(f"+{len(new_vulnerabilities)} new vulnerability(ies) detected")
        if resolved_vulnerabilities:
            summary_parts.append(f"-{len(resolved_vulnerabilities)} vulnerability(ies) resolved")
        if not summary_parts:
            summary_parts.append("Perimeter stable; no asset, port, or technology changes detected.")

        return {
            "target": target,
            "has_previous_scan": True,
            "has_changes": has_changes,
            "score_delta": score_delta,
            "current_score": current_score,
            "previous_score": prev_score,
            "new_subdomains": new_subdomains,
            "removed_subdomains": removed_subdomains,
            "new_ips": new_ips,
            "removed_ips": removed_ips,
            "new_ports": new_ports,
            "closed_ports": closed_ports,
            "new_technologies": new_technologies,
            "changed_technologies": changed_technologies,
            "new_vulnerabilities": new_vulnerabilities,
            "resolved_vulnerabilities": resolved_vulnerabilities,
            "new_exposures": new_exposures,
            "resolved_exposures": resolved_exposures,
            "summary": "; ".join(summary_parts),
        }
