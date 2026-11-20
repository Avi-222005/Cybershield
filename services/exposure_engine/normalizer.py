"""
CyberShield Exposure Intelligence Engine - Normalizer
Normalizes raw scanner outputs, hostnames, IPs, ports, technologies, and CVEs into standardized schemas.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

TECH_CANONICAL_NAMES = {
    "apache": "Apache HTTP Server",
    "apache http server": "Apache HTTP Server",
    "apache tomcat": "Apache Tomcat",
    "tomcat": "Apache Tomcat",
    "nginx": "nginx",
    "microsoft-iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "caddy": "Caddy",
    "lighttpd": "lighttpd",
    "cloudflare": "Cloudflare",
    "php": "PHP",
    "python": "Python",
    "node.js": "Node.js",
    "nodejs": "Node.js",
    "express": "Express",
    "react": "React",
    "vue.js": "Vue.js",
    "angular": "Angular",
    "next.js": "Next.js",
    "nuxt.js": "Nuxt.js",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "openssl": "OpenSSL",
    "openssh": "OpenSSH",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "tailwind css": "Tailwind CSS",
    "django": "Django",
    "flask": "Flask",
    "spring": "Spring Framework",
    "spring boot": "Spring Boot",
    "ruby on rails": "Ruby on Rails",
    "laravel": "Laravel",
}

TECH_ALIASES = {
    "apache": "Apache HTTP Server",
    "apache/": "Apache HTTP Server",
    "httpd": "Apache HTTP Server",
    "nginx": "nginx",
    "microsoft-iis/": "Microsoft IIS",
    "iis/": "Microsoft IIS",
    "openssl/": "OpenSSL",
    "php/": "PHP",
    "openssh_": "OpenSSH",
}


def normalize_hostname(target: str) -> str:
    """Strip protocol, port, paths, whitespace, and convert to lowercase."""
    raw = str(target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.netloc or parsed.path
    if "/" in raw:
        raw = raw.split("/")[0]
    if ":" in raw and not raw.startswith("["):
        # Port attached (e.g. host:8080)
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            raw = parts[0]
    return raw.strip().lower()


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def normalize_ip_address(value: str) -> Optional[Tuple[str, str]]:
    """Returns (ip_str, 'ipv4'|'ipv6') or None if invalid."""
    try:
        ip_obj = ipaddress.ip_address(str(value or "").strip())
        version = "ipv4" if ip_obj.version == 4 else "ipv6"
        return str(ip_obj), version
    except ValueError:
        return None


def normalize_cve_id(cve_input: str) -> Optional[str]:
    raw = str(cve_input or "").strip().upper()
    match = re.search(r"CVE-\d{4}-\d{4,8}", raw)
    if match:
        return match.group(0)
    return None


def clean_version_string(version_raw: str) -> str:
    """Cleans up version strings, removing extra build information or trailing characters."""
    v = str(version_raw or "").strip()
    if not v:
        return ""
    # Remove prefix v or V
    if v.startswith(("v", "V")) and len(v) > 1 and v[1].isdigit():
        v = v[1:]
    # Remove trailing parenthesis or metadata like (Ubuntu) or (Debian)
    v = re.split(r"[\s(+\-~]", v)[0]
    # Remove trailing dots or commas
    v = v.rstrip(".,;")
    # Ensure it looks like a version
    if re.match(r"^\d+(\.\d+)*", v):
        return v
    return ""


def parse_banner_or_header_technology(text: str) -> List[Dict[str, Any]]:
    """
    Parses server headers or service banners like:
    - 'Apache/2.4.49 (Unix) OpenSSL/1.1.1k'
    - 'nginx/1.24.0'
    - 'Microsoft-IIS/10.0'
    - 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5'
    """
    results: List[Dict[str, Any]] = []
    raw = str(text or "").strip()
    if not raw:
        return results

    # Pattern for Name/Version or Name_Version
    matches = re.finditer(r"([A-Za-z0-9_\-\.]+)[/_]([0-9]+(?:\.[0-9a-zA-Z\-_]+)*)", raw)
    for m in matches:
        name_part = m.group(1).strip()
        version_part = clean_version_string(m.group(2).strip())
        norm_name = TECH_CANONICAL_NAMES.get(name_part.lower(), name_part)

        results.append({
            "name": norm_name,
            "normalized_name": norm_name.lower().replace(" ", "-"),
            "version": version_part,
            "confidence": 95 if version_part else 80,
            "categories": ["Web Server" if "server" in norm_name.lower() or norm_name in ("nginx", "Apache HTTP Server", "Microsoft IIS") else "Service"],
            "evidence": [f"Header/Banner token: {m.group(0)}"],
        })

    return results


def normalize_technology_item(tech: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes a technology object from tech stack analyzer or headers."""
    raw_name = str(tech.get("name") or "").strip()
    raw_version = str(tech.get("version") or "").strip()
    confidence = int(tech.get("confidence", 0) or 0)
    categories = list(tech.get("categories") or [])
    section = str(tech.get("section") or "Other")
    signals = list(tech.get("signals") or tech.get("evidence") or [])

    # Canonical name
    canonical = TECH_CANONICAL_NAMES.get(raw_name.lower(), raw_name)
    cleaned_version = clean_version_string(raw_version)

    evidence_list = []
    if signals:
        for s in signals:
            if isinstance(s, dict):
                evidence_list.append(f"{s.get('type', 'signal')}: {s.get('detail') or s.get('match') or s.get('target', '')}")
            else:
                evidence_list.append(str(s))
    else:
        evidence_list.append(f"Detected as {canonical} (confidence: {confidence}%)")

    return {
        "name": canonical,
        "normalized_name": canonical.lower().replace(" ", "-"),
        "version": cleaned_version,
        "confidence": confidence,
        "categories": categories,
        "website": tech.get("website"),
        "section": section,
        "evidence": evidence_list,
    }


def normalize_ports_list(ports_input: Any) -> List[int]:
    """Takes a list or set of ports and returns sorted, unique integers in range 1-65535."""
    valid_ports = set()
    if isinstance(ports_input, (list, set, tuple)):
        for item in ports_input:
            try:
                p = int(item)
                if 1 <= p <= 65535:
                    valid_ports.add(p)
            except (ValueError, TypeError):
                continue
    return sorted(list(valid_ports))
