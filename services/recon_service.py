import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List
from urllib.parse import urlparse

import requests

from .domain_services import normalize_domain_input

try:
    import dns.resolver
except Exception:
    dns = None
else:
    dns = dns.resolver


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-Alt",
}

DEFAULT_SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "app",
    "blog",
    "cdn",
    "m",
    "shop",
    "webmail",
    "support",
]


def dns_lookup(domain_input: str) -> Dict:
    domain = normalize_domain_input(domain_input)
    if not domain:
        return {"error": "Invalid domain format. Enter a valid domain like example.com."}

    if dns is None:
        return {"error": "dnspython is not installed. Install package 'dnspython' to use DNS Lookup."}

    def resolve(record_type: str, target_domain: str = None) -> List[str]:
        query_domain = target_domain or domain
        try:
            answers = dns.resolve(query_domain, record_type)
            if record_type == "MX":
                return [f"{r.preference} {str(r.exchange).rstrip('.')}" for r in answers]
            if record_type == "TXT":
                output = []
                for r in answers:
                    output.append("".join(part.decode() for part in r.strings))
                return output
            if record_type == "SOA":
                output = []
                for r in answers:
                    output.append(
                        f"mname={str(r.mname).rstrip('.')}, rname={str(r.rname).rstrip('.')}, "
                        f"serial={r.serial}, refresh={r.refresh}, retry={r.retry}, "
                        f"expire={r.expire}, minimum={r.minimum}"
                    )
                return output
            if record_type == "CAA":
                output = []
                for r in answers:
                    output.append(f"flags={r.flags}, tag={r.tag.decode() if isinstance(r.tag, bytes) else r.tag}, value={r.value.decode() if isinstance(r.value, bytes) else r.value}")
                return output
            return [str(r).rstrip(".") for r in answers]
        except Exception:
            return []

    txt_records = resolve("TXT")
    dmarc_records = resolve("TXT", f"_dmarc.{domain}")
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    return {
        "domain": domain,
        "records": {
            "A": resolve("A"),
            "AAAA": resolve("AAAA"),
            "CNAME": resolve("CNAME"),
            "MX": resolve("MX"),
            "NS": resolve("NS"),
            "TXT": txt_records,
            "SOA": resolve("SOA"),
            "CAA": resolve("CAA"),
            "DMARC": dmarc_records,
            "SPF": spf_records,
        },
    }


def subdomain_scan(domain_input: str, wordlist: List[str] = None) -> Dict:
    domain = normalize_domain_input(domain_input)
    if not domain:
        return {"error": "Invalid domain format. Enter a valid domain like example.com."}

    candidates = wordlist or DEFAULT_SUBDOMAIN_WORDLIST
    discovered = []

    def probe(prefix: str):
        hostname = f"{prefix}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
            return {"subdomain": hostname, "ip": ip}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(probe, item) for item in candidates]
        for future in as_completed(futures):
            result = future.result()
            if result:
                discovered.append(result)

    discovered.sort(key=lambda x: x["subdomain"])
    return {"domain": domain, "found": discovered, "count": len(discovered)}


def port_scan(target: str) -> Dict:
    target = str(target or "").strip()
    if not target:
        return {"error": "IP address or domain is required."}

    host = normalize_domain_input(target) or target

    try:
        resolved_ip = socket.gethostbyname(host)
    except Exception:
        return {"error": "Could not resolve host/IP for scanning."}

    results = []
    for port in COMMON_PORTS:
        status = "closed"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.6)
                if sock.connect_ex((resolved_ip, port)) == 0:
                    status = "open"
        except Exception:
            status = "closed"
        results.append({"port": port, "status": status})

    open_ports = [p["port"] for p in results if p["status"] == "open"]
    return {"target": target, "resolved_ip": resolved_ip, "ports": results, "open_ports": open_ports}


def service_detection(target: str) -> Dict:
    scan = port_scan(target)
    if "error" in scan:
        return scan

    resolved_ip = scan["resolved_ip"]
    services = []

    for item in scan["ports"]:
        if item["status"] != "open":
            continue
        port = item["port"]
        service = PORT_SERVICE_MAP.get(port, "Unknown")
        banner = None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.2)
                sock.connect((resolved_ip, port))
                if port in (80, 8080):
                    sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
                elif port == 443:
                    service = "HTTPS"
                data = sock.recv(256)
                banner = data.decode(errors="ignore").strip() if data else None
        except Exception:
            banner = None

        services.append({"port": port, "service": service, "banner": banner})

    return {"target": target, "resolved_ip": resolved_ip, "services": services}


def header_analysis(url_input: str) -> Dict:
    raw = str(url_input or "").strip()
    if not raw:
        return {"error": "URL is required."}

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if not parsed.netloc:
        return {"error": "Invalid URL format."}

    url = raw if "://" in raw else f"https://{raw}"

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as exc:
        return {"error": f"Request failed: {str(exc)}"}

    headers = dict(response.headers.items())
    lower_map = {k.lower(): v for k, v in headers.items()}

    required_security_headers = [
        "content-security-policy",
        "x-frame-options",
        "x-xss-protection",
        "strict-transport-security",
    ]
    missing = [h for h in required_security_headers if h not in lower_map]

    return {
        "url": response.url,
        "status_code": response.status_code,
        "headers": headers,
        "missing_security_headers": missing,
    }
