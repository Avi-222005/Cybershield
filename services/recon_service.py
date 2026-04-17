import socket
import os
import threading
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urlunparse, urljoin
import ipaddress
import re
import ssl
import time
import json
import random
import string
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

from .domain_services import normalize_domain_input

try:
    import dns.resolver as dns_resolver
    import dns.reversename as dns_reversename
except Exception:
    dns = None
    dns_reversename = None
else:
    dns = dns_resolver


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

ADVANCED_QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
ADVANCED_WEB_PORTS = [80, 443, 8080, 8443]
MAX_SCAN_PORTS = 1024
SCAN_TIMEOUT_SECONDS = 1.0

ADVANCED_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

RISKY_PORT_ISSUES = {
    21: "Port 21 open -> FTP transmits credentials in plaintext.",
    23: "Port 23 open -> Telnet insecure service exposed.",
    445: "Port 445 open -> SMB exposed.",
    3389: "Port 3389 open -> RDP exposed.",
}

VERSION_PATTERNS = [
    (re.compile(r"Apache/?([0-9][0-9A-Za-z._-]*)", re.IGNORECASE), "Apache"),
    (re.compile(r"nginx/?([0-9][0-9A-Za-z._-]*)", re.IGNORECASE), "Nginx"),
    (re.compile(r"OpenSSH[_/ ]([0-9][0-9A-Za-z._-]*)", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"Microsoft-IIS/?([0-9][0-9A-Za-z._-]*)", re.IGNORECASE), "Microsoft IIS"),
    (re.compile(r"Postfix[ /]([0-9][0-9A-Za-z._-]*)", re.IGNORECASE), "Postfix"),
    (re.compile(r"Exim[ /]([0-9][0-9A-Za-z._-]*)", re.IGNORECASE), "Exim"),
    (re.compile(r"ESMTP", re.IGNORECASE), "SMTP"),
]

SECURITY_HEADER_NAMES = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]

LEAKY_HEADER_NAMES = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-runtime",
    "via",
]

HEADER_AUDIT_TIMEOUT_SECONDS = 5

SUBDOMAIN_SCAN_MODE_CONFIG = {
    "light": {
        "use_crtsh": True,
        "use_otx": True,
        "use_hackertarget": False,
        "use_js": False,
        "use_wordlist": True,
        "use_mutation": False,
        "use_reverse_hints": False,
        "wordlist_size": 100,
        "mutation_size": 0,
        "max_results": 500,
        "max_live_checks": 120,
        "include_historical": False,
    },
    "standard": {
        "use_crtsh": True,
        "use_otx": True,
        "use_hackertarget": True,
        "use_js": True,
        "use_wordlist": True,
        "use_mutation": True,
        "use_reverse_hints": False,
        "wordlist_size": 1000,
        "mutation_size": 600,
        "max_results": 1600,
        "max_live_checks": 260,
        "include_historical": False,
    },
    "deep": {
        "use_crtsh": True,
        "use_otx": True,
        "use_hackertarget": True,
        "use_js": True,
        "use_wordlist": True,
        "use_mutation": True,
        "use_reverse_hints": True,
        "wordlist_size": 2400,
        "mutation_size": 1500,
        "max_results": 3200,
        "max_live_checks": 420,
        "include_historical": True,
    },
}

SUBDOMAIN_WORDLIST_CORE = [
    "admin", "dev", "test", "api", "auth", "stage", "beta", "portal", "dashboard",
    "mail", "vpn", "crm", "hr", "cdn", "img", "static", "old", "legacy",
]

SUBDOMAIN_WORDLIST_AUX = [
    "www", "app", "m", "gateway", "edge", "internal", "docs", "status", "assets",
    "api2", "uat", "preprod", "prod", "staging", "web", "secure", "sso", "files",
]

SUBDOMAIN_MUTATION_TEMPLATES = [
    "api-v2", "dev-api", "old-admin", "portal-test", "stage-auth", "app-prod", "beta-login",
]

SUBDOMAIN_MAX_RESULTS = 3200
SUBDOMAIN_MAX_LIVE_CHECKS = 420
SUBDOMAIN_HTTP_TIMEOUT = 4
SUBDOMAIN_SOURCE_TIMEOUT = (5, 20)
SUBDOMAIN_SOURCE_MAX_RETRIES = 3

SUBDOMAIN_CACHE_TTL_SECONDS = 300
_SUBDOMAIN_CACHE_LOCK = threading.Lock()
_SUBDOMAIN_CACHE: Dict[str, Dict[str, Any]] = {}

SUBDOMAIN_RISK_KEYWORDS = {
    "admin": "HIGH",
    "dashboard": "HIGH",
    "login": "HIGH",
    "vpn": "HIGH",
    "internal": "HIGH",
    "dev": "MEDIUM",
    "test": "MEDIUM",
    "beta": "MEDIUM",
    "old": "MEDIUM",
    "legacy": "MEDIUM",
    "stage": "MEDIUM",
    "staging": "MEDIUM",
}

SUBDOMAIN_TAKEOVER_SUFFIXES = [
    ".github.io",
    ".herokudns.com",
    ".azurewebsites.net",
    ".trafficmanager.net",
    ".cloudfront.net",
    ".fastly.net",
    ".zendesk.com",
    ".surge.sh",
    ".bitbucket.io",
    ".readthedocs.io",
    ".pantheonsite.io",
]

SUBDOMAIN_TAKEOVER_FINGERPRINTS = [
    "There isn't a GitHub Pages site here",
    "No such app",
    "Sorry, this shop is currently unavailable",
    "The specified bucket does not exist",
    "project not found",
    "No settings were found for this company",
]

SUBDOMAIN_GENERATED_SOURCES = {"wordlist", "mutation"}
SUBDOMAIN_PASSIVE_SOURCES = {"crt.sh", "OTX", "HackerTarget", "JS", "reverse-dns"}

OTX_API_KEY = os.getenv("OTX_API_KEY")


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


def _dns_make_resolver() -> Any:
    resolver = dns.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 4.0
    return resolver


def _normalize_dns_target(target_input: str) -> Dict[str, str]:
    raw = str(target_input or "").strip().lower()
    if not raw:
        return {"error": "Target is required."}

    candidate = raw
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.netloc or parsed.path
    else:
        parsed = urlparse(f"https://{candidate}")
        candidate = parsed.netloc or parsed.path

    candidate = candidate.split("/")[0].split(":")[0].strip().rstrip(".")
    candidate = re.sub(r"\.+", ".", candidate)
    if candidate.startswith("www."):
        candidate = candidate[4:]

    if not candidate or len(candidate) > 253:
        return {"error": "Invalid domain target."}

    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    labels = candidate.split(".")
    if len(labels) < 2 or any(not label_pattern.match(label) for label in labels):
        return {"error": "Invalid domain format. Enter a valid domain like example.com."}

    compound_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "co.in", "org.in", "ac.in", "gov.in",
        "com.au", "net.au", "org.au",
        "co.jp", "com.br",
    }

    suffix2 = ".".join(labels[-2:])
    if suffix2 in compound_suffixes and len(labels) >= 3:
        root_domain = ".".join(labels[-3:])
    else:
        root_domain = ".".join(labels[-2:])

    return {
        "input_target": str(target_input or "").strip(),
        "normalized_domain": candidate,
        "root_domain": root_domain,
    }


def _resolve_dns_records(resolver: Any, name: str, record_type: str) -> List[str]:
    try:
        answers = resolver.resolve(name, record_type, raise_on_no_answer=False)
    except Exception:
        return []

    if not answers:
        return []

    rows: List[str] = []
    for ans in answers:
        if record_type == "MX":
            rows.append(f"{ans.preference} {str(ans.exchange).rstrip('.').lower()}")
        elif record_type == "TXT":
            if hasattr(ans, "strings") and ans.strings:
                rows.append("".join(p.decode() if isinstance(p, bytes) else str(p) for p in ans.strings))
            else:
                rows.append(str(ans).strip('"'))
        elif record_type == "SOA":
            rows.append(
                "mname={mname}, rname={rname}, serial={serial}, refresh={refresh}, retry={retry}, expire={expire}, minimum={minimum}".format(
                    mname=str(ans.mname).rstrip('.').lower(),
                    rname=str(ans.rname).rstrip('.').lower(),
                    serial=getattr(ans, "serial", ""),
                    refresh=getattr(ans, "refresh", ""),
                    retry=getattr(ans, "retry", ""),
                    expire=getattr(ans, "expire", ""),
                    minimum=getattr(ans, "minimum", ""),
                )
            )
        elif record_type == "CAA":
            tag = ans.tag.decode() if isinstance(ans.tag, bytes) else str(ans.tag)
            value = ans.value.decode() if isinstance(ans.value, bytes) else str(ans.value)
            rows.append(f"flags={ans.flags}, tag={tag}, value={value}")
        else:
            rows.append(str(ans).rstrip('.').lower())

    return rows


def _extract_policy(parts: List[str], key: str) -> Optional[str]:
    key_lower = f"{key}="
    for part in parts:
        p = part.strip().lower()
        if p.startswith(key_lower):
            return p.split("=", 1)[1].strip()
    return None


def _analyze_spf(spf_records: List[str]) -> Dict[str, Any]:
    if not spf_records:
        return {
            "present": False,
            "record": None,
            "policy": "missing",
            "risk": "High",
            "includes": 0,
            "issues": ["No SPF record found"],
        }

    record = spf_records[0]
    lowered = record.lower()
    includes = len(re.findall(r"\binclude:", lowered))

    policy = "unknown"
    risk = "Moderate"
    issues: List[str] = []

    if "+all" in lowered:
        policy = "+all"
        risk = "High"
        issues.append("SPF uses +all (dangerous allow-all policy)")
    elif "-all" in lowered:
        policy = "-all"
        risk = "Low"
    elif "~all" in lowered:
        policy = "~all"
        risk = "Moderate"
        issues.append("SPF uses soft fail (~all)")
    elif "?all" in lowered:
        policy = "?all"
        risk = "Moderate"
        issues.append("SPF uses neutral policy (?all)")
    else:
        issues.append("SPF record missing explicit all mechanism")

    if includes > 8:
        issues.append("SPF has many include mechanisms; may exceed DNS lookup limits")

    return {
        "present": True,
        "record": record,
        "policy": policy,
        "risk": risk,
        "includes": includes,
        "issues": issues,
    }


def _analyze_dmarc(dmarc_records: List[str]) -> Dict[str, Any]:
    if not dmarc_records:
        return {
            "present": False,
            "record": None,
            "policy": "missing",
            "enforcement": "Weak",
            "rua": None,
            "ruf": None,
            "pct": None,
            "issues": ["No DMARC record found"],
        }

    record = dmarc_records[0]
    parts = [p.strip() for p in record.split(";") if p.strip()]
    policy = _extract_policy(parts, "p") or "none"
    rua = _extract_policy(parts, "rua")
    ruf = _extract_policy(parts, "ruf")
    pct = _extract_policy(parts, "pct")

    if policy == "reject":
        enforcement = "Strong"
    elif policy == "quarantine":
        enforcement = "Moderate"
    else:
        enforcement = "Weak"

    issues: List[str] = []
    if policy == "none":
        issues.append("DMARC policy is none (monitoring only)")
    if not rua:
        issues.append("DMARC rua aggregate reporting not configured")

    return {
        "present": True,
        "record": record,
        "policy": policy,
        "enforcement": enforcement,
        "rua": rua,
        "ruf": ruf,
        "pct": pct,
        "issues": issues,
    }


def _detect_dkim_common_selectors(resolver: Any, root_domain: str) -> Dict[str, Any]:
    selectors = ["default", "selector1", "google", "k1"]
    found: List[str] = []

    for selector in selectors:
        fqdn = f"{selector}._domainkey.{root_domain}"
        txt_values = _resolve_dns_records(resolver, fqdn, "TXT")
        if any("v=dkim1" in value.lower() for value in txt_values):
            found.append(selector)

    return {
        "status": "Likely Configured" if found else "Not Detected with common selectors",
        "selectors_found": found,
    }


def _analyze_mx(mx_records: List[str]) -> Dict[str, Any]:
    parsed: List[Dict[str, Any]] = []
    providers: Set[str] = set()

    for row in mx_records:
        parts = row.split()
        if len(parts) < 2:
            continue
        try:
            priority = int(parts[0])
        except ValueError:
            priority = 0
        host = parts[1].lower()
        parsed.append({"priority": priority, "host": host})

        if any(k in host for k in ("google", "googlemail", "gmail")):
            providers.add("Google Workspace")
        elif any(k in host for k in ("outlook", "protection.outlook", "office365")):
            providers.add("Microsoft 365")
        elif "zoho" in host:
            providers.add("Zoho")
        elif "yandex" in host:
            providers.add("Yandex")
        else:
            providers.add("Custom/Other")

    parsed.sort(key=lambda x: x["priority"])

    issues: List[str] = []
    if not parsed:
        issues.append("No MX record found")
    elif len(parsed) == 1:
        issues.append("Single MX server detected (low redundancy)")

    return {
        "count": len(parsed),
        "records": parsed,
        "providers": sorted(providers),
        "issues": issues,
    }


def _analyze_ns(ns_records: List[str]) -> Dict[str, Any]:
    providers: Set[str] = set()
    for host in ns_records:
        h = host.lower()
        if "cloudflare" in h:
            providers.add("Cloudflare")
        elif any(k in h for k in ("awsdns", "route53")):
            providers.add("AWS Route53")
        elif any(k in h for k in ("azure", "trafficmanager")):
            providers.add("Azure DNS")
        elif any(k in h for k in ("googledomains", "google")):
            providers.add("Google DNS")
        else:
            providers.add("Custom/Other")

    issues: List[str] = []
    if len(ns_records) == 0:
        issues.append("No NS record found")
    elif len(ns_records) == 1:
        issues.append("Single NS detected (single point of failure)")

    return {
        "count": len(ns_records),
        "records": ns_records,
        "providers": sorted(providers),
        "issues": issues,
    }


def _analyze_caa(caa_records: List[str]) -> Dict[str, Any]:
    issues: List[str] = []
    authorized_cas: List[str] = []

    for row in caa_records:
        match = re.search(r"value=([^,]+)$", row)
        if match:
            authorized_cas.append(match.group(1).strip().strip('"'))

    if not caa_records:
        issues.append("No CAA record found (any CA may issue certificate)")

    return {
        "present": len(caa_records) > 0,
        "records": caa_records,
        "authorized_cas": authorized_cas,
        "issues": issues,
    }


def _analyze_soa(soa_records: List[str]) -> Dict[str, Any]:
    if not soa_records:
        return {
            "present": False,
            "record": None,
            "issues": ["No SOA record found"],
        }

    row = soa_records[0]
    parsed = {
        "primary_ns": "",
        "responsible": "",
        "serial": "",
        "refresh": "",
        "retry": "",
        "expire": "",
        "minimum": "",
    }

    for token in [t.strip() for t in row.split(",") if "=" in t]:
        key, value = token.split("=", 1)
        k = key.strip().lower()
        v = value.strip()
        if k == "mname":
            parsed["primary_ns"] = v
        elif k == "rname":
            parsed["responsible"] = v
        elif k in parsed:
            parsed[k] = v

    issues: List[str] = []
    try:
        refresh = int(parsed["refresh"]) if parsed["refresh"] else 0
        retry = int(parsed["retry"]) if parsed["retry"] else 0
        expire = int(parsed["expire"]) if parsed["expire"] else 0
        if refresh > 172800:
            issues.append("SOA refresh is high; slower zone propagation")
        if retry > refresh and refresh > 0:
            issues.append("SOA retry greater than refresh may be suboptimal")
        if expire and expire < 604800:
            issues.append("SOA expire value is low")
    except ValueError:
        pass

    return {
        "present": True,
        "record": parsed,
        "issues": issues,
    }


def _detect_dnssec(resolver: Any, root_domain: str) -> Dict[str, Any]:
    ds_records = _resolve_dns_records(resolver, root_domain, "DS")
    dnskey_records = _resolve_dns_records(resolver, root_domain, "DNSKEY")

    ds_present = len(ds_records) > 0
    dnskey_present = len(dnskey_records) > 0

    return {
        "enabled": ds_present and dnskey_present,
        "ds_present": ds_present,
        "dnskey_present": dnskey_present,
        "ds_records": ds_records,
        "dnskey_count": len(dnskey_records),
    }


def _resolve_ptr_records(a_records: List[str], aaaa_records: List[str]) -> List[str]:
    ptr_values: List[str] = []
    candidate_ips = (a_records + aaaa_records)[:3]

    for ip in candidate_ips:
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            if host:
                ptr_values.append(host.rstrip('.').lower())
                continue
        except Exception:
            pass

        if dns_reversename is not None and dns is not None:
            try:
                resolver = _dns_make_resolver()
                rev_name = dns_reversename.from_address(ip)
                ptr_values.extend(_resolve_dns_records(resolver, str(rev_name), "PTR"))
            except Exception:
                continue

    return sorted(list(dict.fromkeys(ptr_values)))


def _infra_provider_guess(ns_records: List[str], ptr_records: List[str], a_records: List[str]) -> str:
    haystack = " ".join(ns_records + ptr_records).lower()
    if "cloudflare" in haystack:
        return "Cloudflare"
    if any(k in haystack for k in ("aws", "amazon", "route53")):
        return "Amazon Web Services"
    if any(k in haystack for k in ("azure", "microsoft")):
        return "Microsoft Azure"
    if "google" in haystack:
        return "Google Cloud"
    if a_records:
        return "Custom/Unknown Hosting"
    return "Unknown"


def _collect_dns_issues(
    dnssec: Dict[str, Any],
    spf: Dict[str, Any],
    dmarc: Dict[str, Any],
    dkim: Dict[str, Any],
    mx: Dict[str, Any],
    ns: Dict[str, Any],
    caa: Dict[str, Any],
    records: Dict[str, List[str]],
    soa: Dict[str, Any],
) -> List[str]:
    issues: List[str] = []

    if not dnssec.get("enabled"):
        issues.append("DNSSEC not enabled")

    issues.extend(spf.get("issues", []))
    issues.extend(dmarc.get("issues", []))
    if dkim.get("status", "").lower().startswith("not"):
        issues.append("DKIM not detected with common selectors")
    issues.extend(mx.get("issues", []))
    issues.extend(ns.get("issues", []))
    issues.extend(caa.get("issues", []))
    issues.extend(soa.get("issues", []))

    if not records.get("AAAA"):
        issues.append("No AAAA record found")

    return list(dict.fromkeys(issues))


def _dns_grade(
    dnssec: Dict[str, Any],
    spf: Dict[str, Any],
    dmarc: Dict[str, Any],
    dkim: Dict[str, Any],
    mx: Dict[str, Any],
    ns: Dict[str, Any],
    caa: Dict[str, Any],
    issues: List[str],
) -> Tuple[str, int]:
    score = 100

    if not dnssec.get("enabled"):
        score -= 15

    if not spf.get("present"):
        score -= 15
    elif spf.get("policy") == "+all":
        score -= 20
    elif spf.get("policy") == "~all":
        score -= 6

    if not dmarc.get("present"):
        score -= 20
    elif dmarc.get("policy") == "none":
        score -= 12
    elif dmarc.get("policy") == "quarantine":
        score -= 4

    if dkim.get("status", "").lower().startswith("not"):
        score -= 6

    if not caa.get("present"):
        score -= 8

    if mx.get("count", 0) == 1:
        score -= 5
    if ns.get("count", 0) == 1:
        score -= 5

    score -= min(20, max(0, len(issues) - 2) * 2)
    score = max(0, min(100, score))

    if score >= 97:
        return "A+", score
    if score >= 90:
        return "A", score
    if score >= 80:
        return "B", score
    if score >= 70:
        return "C", score
    if score >= 60:
        return "D", score
    return "F", score


def _dns_recommendations(
    dnssec: Dict[str, Any],
    spf: Dict[str, Any],
    dmarc: Dict[str, Any],
    dkim: Dict[str, Any],
    mx: Dict[str, Any],
    ns: Dict[str, Any],
    caa: Dict[str, Any],
    records: Dict[str, List[str]],
) -> List[str]:
    recs: List[str] = []

    if not dnssec.get("enabled"):
        recs.append("Enable DNSSEC (publish DS and DNSKEY records) to protect DNS integrity.")

    if not spf.get("present"):
        recs.append("Add an SPF TXT record and restrict authorized mail senders.")
    elif spf.get("policy") == "+all":
        recs.append("Replace SPF +all with -all after validating all legitimate senders.")
    elif spf.get("policy") == "~all":
        recs.append("Move SPF from soft fail (~all) to hard fail (-all) after validation.")

    if not dmarc.get("present"):
        recs.append("Publish a DMARC record with p=quarantine or p=reject.")
    elif dmarc.get("policy") == "none":
        recs.append("Change DMARC policy from p=none to p=quarantine/reject for enforcement.")

    if dkim.get("status", "").lower().startswith("not"):
        recs.append("Configure DKIM signing and publish selector TXT records.")

    if not caa.get("present"):
        recs.append("Add CAA records to restrict which certificate authorities can issue certificates.")

    if mx.get("count", 0) == 1:
        recs.append("Add secondary MX server for mail delivery redundancy.")
    if ns.get("count", 0) == 1:
        recs.append("Add at least one additional nameserver for DNS redundancy.")
    if not records.get("AAAA"):
        recs.append("Add AAAA records to improve IPv6 compatibility.")

    normalized = json.loads(json.dumps(recs))
    return list(dict.fromkeys(normalized))


def dns_lookup_pro(target_input: str) -> Dict[str, Any]:
    if dns is None:
        return {"error": "dnspython is not installed. Install package 'dnspython' to use DNS Lookup Pro."}

    normalized = _normalize_dns_target(target_input)
    if "error" in normalized:
        return normalized

    root_domain = normalized["root_domain"]
    resolver = _dns_make_resolver()

    records = {
        "A": _resolve_dns_records(resolver, root_domain, "A"),
        "AAAA": _resolve_dns_records(resolver, root_domain, "AAAA"),
        "CNAME": _resolve_dns_records(resolver, root_domain, "CNAME"),
        "MX": _resolve_dns_records(resolver, root_domain, "MX"),
        "NS": _resolve_dns_records(resolver, root_domain, "NS"),
        "TXT": _resolve_dns_records(resolver, root_domain, "TXT"),
        "SOA": _resolve_dns_records(resolver, root_domain, "SOA"),
        "CAA": _resolve_dns_records(resolver, root_domain, "CAA"),
        "DMARC": _resolve_dns_records(resolver, f"_dmarc.{root_domain}", "TXT"),
    }
    records["SPF"] = [r for r in records["TXT"] if r.lower().startswith("v=spf1")]
    records["PTR"] = _resolve_ptr_records(records["A"], records["AAAA"])

    dnssec = _detect_dnssec(resolver, root_domain)
    spf = _analyze_spf(records["SPF"])
    dmarc = _analyze_dmarc(records["DMARC"])
    dkim = _detect_dkim_common_selectors(resolver, root_domain)
    mx_analysis = _analyze_mx(records["MX"])
    ns_analysis = _analyze_ns(records["NS"])
    caa_analysis = _analyze_caa(records["CAA"])
    soa_analysis = _analyze_soa(records["SOA"])

    infra = {
        "provider_guess": _infra_provider_guess(records["NS"], records["PTR"], records["A"]),
        "a_count": len(records["A"]),
        "aaaa_count": len(records["AAAA"]),
        "ptr_count": len(records["PTR"]),
    }

    issues = _collect_dns_issues(
        dnssec,
        spf,
        dmarc,
        dkim,
        mx_analysis,
        ns_analysis,
        caa_analysis,
        records,
        soa_analysis,
    )
    grade, score = _dns_grade(dnssec, spf, dmarc, dkim, mx_analysis, ns_analysis, caa_analysis, issues)
    recommendations = _dns_recommendations(
        dnssec,
        spf,
        dmarc,
        dkim,
        mx_analysis,
        ns_analysis,
        caa_analysis,
        records,
    )

    return {
        "target": normalized["input_target"],
        "normalized_domain": normalized["normalized_domain"],
        "root_domain": root_domain,
        "grade": grade,
        "score": score,
        "dnssec": dnssec,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "mx": mx_analysis,
        "ns": ns_analysis,
        "caa": caa_analysis,
        "soa": soa_analysis,
        "infrastructure": infra,
        "records": records,
        "issues": issues,
        "recommendations": recommendations,
        "generated_at": datetime.now(timezone.utc).isoformat(),
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


def _normalize_subdomain_candidate(host: str, root_domain: str) -> Optional[str]:
    if not host:
        return None

    candidate = str(host).strip().lower().rstrip(".")
    if not candidate:
        return None

    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]
    if candidate.startswith("."):
        candidate = candidate[1:]

    if candidate == root_domain:
        return None
    if not candidate.endswith(f".{root_domain}"):
        return None
    if ".." in candidate:
        return None
    if not re.match(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", candidate):
        return None

    return candidate


def _extract_subdomains_from_text(blob: str, root_domain: str) -> Set[str]:
    if not blob:
        return set()

    pattern = re.compile(
        rf"\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{re.escape(root_domain)}\b",
        re.IGNORECASE,
    )

    found: Set[str] = set()
    for match in pattern.findall(blob):
        normalized = _normalize_subdomain_candidate(match, root_domain)
        if normalized:
            found.add(normalized)
    return found


def _normalize_scan_mode(scan_mode_input: str) -> str:
    mode = str(scan_mode_input or "standard").strip().lower()
    if mode not in SUBDOMAIN_SCAN_MODE_CONFIG:
        return "standard"
    return mode


def _subdomain_cache_get(cache_key: str) -> Optional[Dict[str, Any]]:
    now = time.time()
    with _SUBDOMAIN_CACHE_LOCK:
        cached = _SUBDOMAIN_CACHE.get(cache_key)
        if not cached:
            return None

        expires_at = cached.get("expires_at", 0)
        if now > expires_at:
            _SUBDOMAIN_CACHE.pop(cache_key, None)
            return None

        data = cached.get("data")
        if not isinstance(data, dict):
            return None

        return json.loads(json.dumps(data))


def _subdomain_cache_set(cache_key: str, data: Dict[str, Any]) -> None:
    with _SUBDOMAIN_CACHE_LOCK:
        _SUBDOMAIN_CACHE[cache_key] = {
            "expires_at": time.time() + SUBDOMAIN_CACHE_TTL_SECONDS,
            "data": json.loads(json.dumps(data)),
        }


def _is_valid_subdomain_label(label: str) -> bool:
    if not label:
        return False
    if len(label) > 63:
        return False
    return bool(re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label))


def _build_smart_wordlist(root_domain: str, desired_count: int) -> List[str]:
    desired = max(10, int(desired_count or 0))
    labels: List[str] = []
    seen: Set[str] = set()

    def add_label(value: str) -> None:
        label = str(value or "").strip().lower().replace("_", "-")
        if label in seen:
            return
        if not _is_valid_subdomain_label(label):
            return
        seen.add(label)
        labels.append(label)

    for base in SUBDOMAIN_WORDLIST_CORE + SUBDOMAIN_WORDLIST_AUX:
        add_label(base)

    root_token = root_domain.split(".", 1)[0]
    for token in re.split(r"[^a-z0-9]+", root_token):
        if not token:
            continue
        add_label(token)
        add_label(f"{token}-api")
        add_label(f"api-{token}")
        add_label(f"{token}-dev")

    suffixes = ["", "-dev", "-test", "-stage", "-staging", "-beta", "-old", "-legacy", "-v2", "-prod"]
    for token, suffix in itertools.product(SUBDOMAIN_WORDLIST_CORE, suffixes):
        add_label(f"{token}{suffix}")
        if len(labels) >= desired:
            return labels[:desired]

    for left, right in itertools.permutations(SUBDOMAIN_WORDLIST_CORE, 2):
        add_label(f"{left}-{right}")
        if len(labels) >= desired:
            return labels[:desired]

    for idx in range(1, 10):
        for token in SUBDOMAIN_WORDLIST_CORE:
            add_label(f"{token}{idx}")
            if len(labels) >= desired:
                return labels[:desired]

    return labels[:desired]


def _build_mutation_labels(root_domain: str, observed_hosts: Set[str], desired_count: int) -> List[str]:
    desired = max(0, int(desired_count or 0))
    if desired == 0:
        return []

    labels: List[str] = []
    seen: Set[str] = set()

    def add_label(value: str) -> None:
        label = str(value or "").strip().lower().replace("_", "-")
        if label in seen:
            return
        if not _is_valid_subdomain_label(label):
            return
        seen.add(label)
        labels.append(label)

    for template in SUBDOMAIN_MUTATION_TEMPLATES:
        add_label(template)

    seed_tokens: Set[str] = set(SUBDOMAIN_WORDLIST_CORE)
    root_token = root_domain.split(".", 1)[0]
    for token in re.split(r"[^a-z0-9]+", root_token):
        if token:
            seed_tokens.add(token)

    for host in observed_hosts:
        first_label = host.split(".", 1)[0]
        for token in re.split(r"[^a-z0-9]+", first_label):
            if 2 <= len(token) <= 20:
                seed_tokens.add(token)

    compact_tokens = sorted(token for token in seed_tokens if _is_valid_subdomain_label(token))[:80]

    for left, right in itertools.islice(itertools.permutations(compact_tokens, 2), 0, 3500):
        add_label(f"{left}-{right}")
        add_label(f"{left}{right}")
        add_label(f"{left}-{right}-v2")
        add_label(f"{left}-{right}-prod")
        if len(labels) >= desired:
            break

    return labels[:desired]


def _discover_subdomains_label_dns(
    root_domain: str,
    labels: List[str],
    source_name: str,
    max_workers: int = 100,
    include_unresolved: bool = False,
) -> Tuple[Set[str], Set[str], Optional[str]]:
    if dns is None:
        return set(), set(), "dnspython unavailable for DNS label discovery"

    resolved: Set[str] = set()
    unresolved: Set[str] = set()

    def probe(label: str) -> Tuple[str, bool]:
        host = f"{label}.{root_domain}"
        resolver = _dns_make_resolver()
        a_records = _resolve_dns_records(resolver, host, "A")
        aaaa_records = _resolve_dns_records(resolver, host, "AAAA")
        return host, bool(a_records or aaaa_records)

    workers = max(1, min(100, int(max_workers)))
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(probe, label) for label in labels]
            for future in as_completed(futures):
                try:
                    host, is_resolved = future.result()
                    normalized = _normalize_subdomain_candidate(host, root_domain)
                    if not normalized:
                        continue
                    if is_resolved:
                        resolved.add(normalized)
                    elif include_unresolved:
                        unresolved.add(normalized)
                except Exception:
                    continue
    except Exception as exc:
        return resolved, unresolved, f"{source_name} discovery failed: {exc}"

    return resolved, unresolved, None


def _discover_subdomains_reverse_hints(root_domain: str) -> Tuple[Set[str], Optional[str]]:
    if dns is None:
        return set(), "dnspython unavailable for reverse DNS hints"

    resolver = _dns_make_resolver()
    a_records = _resolve_dns_records(resolver, root_domain, "A")
    aaaa_records = _resolve_dns_records(resolver, root_domain, "AAAA")
    if not a_records and not aaaa_records:
        return set(), "Root domain has no A/AAAA records for reverse DNS hints"

    ptr_hosts = _resolve_ptr_records(a_records, aaaa_records)
    results: Set[str] = set()

    for ptr in ptr_hosts:
        normalized = _normalize_subdomain_candidate(ptr, root_domain)
        if normalized:
            results.add(normalized)

    hint_labels: Set[str] = set()
    for ptr in ptr_hosts:
        left = ptr.split(".", 1)[0]
        for token in re.split(r"[^a-z0-9]+", left.lower()):
            if 3 <= len(token) <= 20 and _is_valid_subdomain_label(token):
                hint_labels.add(token)

    if hint_labels:
        discovered, _, _ = _discover_subdomains_label_dns(
            root_domain=root_domain,
            labels=sorted(hint_labels)[:100],
            source_name="reverse-dns",
            max_workers=40,
            include_unresolved=False,
        )
        results.update(discovered)

    return results, None


def _request_with_retries(
    url: str,
    source_name: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: Tuple[int, int] = SUBDOMAIN_SOURCE_TIMEOUT,
    max_retries: int = SUBDOMAIN_SOURCE_MAX_RETRIES,
) -> Tuple[Optional[requests.Response], Optional[str]]:
    wait_seconds = 1.2
    last_error: Optional[str] = None

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                if attempt < max_retries:
                    if retry_after and retry_after.isdigit():
                        sleep_for = max(1.0, min(10.0, float(retry_after)))
                    else:
                        sleep_for = min(8.0, wait_seconds)
                    time.sleep(sleep_for)
                    wait_seconds *= 1.8
                    continue

                hint = ""
                if source_name == "OTX" and not OTX_API_KEY:
                    hint = " (set OTX_API_KEY to reduce rate-limit errors)"
                return None, f"{source_name} request returned status 429 (rate limited){hint}"

            if response.status_code >= 500:
                if attempt < max_retries:
                    time.sleep(min(8.0, wait_seconds))
                    wait_seconds *= 1.8
                    continue
                return None, f"{source_name} request returned status {response.status_code}"

            if response.status_code >= 400:
                return None, f"{source_name} request returned status {response.status_code}"

            return response, None
        except requests.Timeout:
            last_error = f"{source_name} timed out"
            if attempt < max_retries:
                time.sleep(min(8.0, wait_seconds))
                wait_seconds *= 1.8
                continue
        except requests.RequestException as exc:
            last_error = f"{source_name} request failed: {exc}"
            if attempt < max_retries:
                time.sleep(min(8.0, wait_seconds))
                wait_seconds *= 1.8
                continue

    return None, last_error or f"{source_name} request failed"


def _discover_subdomains_crtsh(root_domain: str) -> Tuple[Set[str], Optional[str]]:
    url = f"https://crt.sh/?q=%25.{root_domain}&output=json&deduplicate=Y"
    headers = {
        "User-Agent": "CyberShieldSubdomainPro/1.0",
        "Accept": "application/json,text/plain,*/*",
    }
    try:
        response, fetch_error = _request_with_retries(
            url=url,
            source_name="crt.sh",
            headers=headers,
        )
        if fetch_error or response is None:
            return set(), fetch_error or "crt.sh query failed"

        rows = response.json()
        if not isinstance(rows, list):
            return set(), "crt.sh returned an unexpected response format"

        results: Set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key in ("common_name", "name_value"):
                value = row.get(key)
                if not value:
                    continue
                for part in str(value).splitlines():
                    normalized = _normalize_subdomain_candidate(part, root_domain)
                    if normalized:
                        results.add(normalized)
        return results, None
    except Exception as exc:
        return set(), f"crt.sh query failed: {exc}"


def _discover_subdomains_otx(root_domain: str) -> Tuple[Set[str], Optional[str]]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{root_domain}/passive_dns"
    headers = {
        "User-Agent": "CyberShieldSubdomainPro/1.0",
        "Accept": "application/json,text/plain,*/*",
    }
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY

    try:
        response, fetch_error = _request_with_retries(
            url=url,
            source_name="OTX",
            headers=headers,
        )
        if fetch_error or response is None:
            return set(), fetch_error or "OTX query failed"

        payload = response.json()
        rows = payload.get("passive_dns", []) if isinstance(payload, dict) else []

        results: Set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            hostname = row.get("hostname") or row.get("host") or row.get("address")
            normalized = _normalize_subdomain_candidate(hostname, root_domain) if hostname else None
            if normalized:
                results.add(normalized)
        return results, None
    except Exception as exc:
        return set(), f"OTX query failed: {exc}"


def _discover_subdomains_hackertarget(root_domain: str) -> Tuple[Set[str], Optional[str]]:
    url = f"https://api.hackertarget.com/hostsearch/?q={root_domain}"
    headers = {
        "User-Agent": "CyberShieldSubdomainPro/1.0",
        "Accept": "text/plain,*/*",
    }
    try:
        response, fetch_error = _request_with_retries(
            url=url,
            source_name="HackerTarget",
            headers=headers,
            timeout=(4, 12),
            max_retries=2,
        )
        if fetch_error or response is None:
            return set(), fetch_error or "HackerTarget query failed"

        text = response.text or ""
        if "error" in text.lower() and "api" in text.lower():
            return set(), "HackerTarget API limit reached or request denied"

        results: Set[str] = set()
        for line in text.splitlines():
            host = line.split(",", 1)[0].strip() if line else ""
            normalized = _normalize_subdomain_candidate(host, root_domain)
            if normalized:
                results.add(normalized)
        return results, None
    except Exception as exc:
        return set(), f"HackerTarget query failed: {exc}"


def _discover_subdomains_js_assets(root_domain: str) -> Tuple[Set[str], Optional[str]]:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "CyberShieldSubdomainPro/1.0",
        "Accept": "text/html,application/javascript,*/*;q=0.8",
    })

    homepage_url = f"https://{root_domain}"
    homepage_html = ""

    for candidate in (f"https://{root_domain}", f"http://{root_domain}"):
        try:
            response = session.get(candidate, timeout=SUBDOMAIN_HTTP_TIMEOUT, allow_redirects=True)
            if response.status_code < 500 and response.text:
                homepage_url = response.url or candidate
                homepage_html = response.text
                break
        except Exception:
            continue

    if not homepage_html:
        return set(), "Homepage fetch failed for JS asset discovery"

    script_pattern = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
    href_pattern = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"']", re.IGNORECASE)
    img_pattern = re.compile(r"<img[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
    endpoint_pattern = re.compile(r"[\"'](?:https?:)?//([^\"'/]+)[^\"']*[\"']", re.IGNORECASE)

    asset_urls: List[str] = []
    for raw in script_pattern.findall(homepage_html) + href_pattern.findall(homepage_html) + img_pattern.findall(homepage_html):
        full = urljoin(homepage_url, raw.strip())
        if full.startswith("http://") or full.startswith("https://"):
            asset_urls.append(full)

    asset_urls = list(dict.fromkeys(asset_urls))[:25]

    results = _extract_subdomains_from_text(homepage_html, root_domain)
    for endpoint_host in endpoint_pattern.findall(homepage_html):
        normalized = _normalize_subdomain_candidate(endpoint_host, root_domain)
        if normalized:
            results.add(normalized)

    for asset_url in asset_urls:
        try:
            response = session.get(asset_url, timeout=SUBDOMAIN_HTTP_TIMEOUT)
            if response.status_code >= 400:
                continue
            body = (response.text or "")[:500000]
            results.update(_extract_subdomains_from_text(body, root_domain))
            for endpoint_host in endpoint_pattern.findall(body):
                normalized = _normalize_subdomain_candidate(endpoint_host, root_domain)
                if normalized:
                    results.add(normalized)
        except Exception:
            continue

    return results, None


def _discover_subdomains_wordlist(
    root_domain: str,
    wordlist_size: int,
    include_unresolved: bool,
) -> Tuple[Set[str], Set[str], Optional[str]]:
    labels = _build_smart_wordlist(root_domain, wordlist_size)
    return _discover_subdomains_label_dns(
        root_domain=root_domain,
        labels=labels,
        source_name="wordlist",
        max_workers=100,
        include_unresolved=include_unresolved,
    )


def _discover_subdomains_mutation(
    root_domain: str,
    observed_hosts: Set[str],
    mutation_size: int,
    include_unresolved: bool,
) -> Tuple[Set[str], Set[str], Optional[str]]:
    labels = _build_mutation_labels(root_domain, observed_hosts, mutation_size)
    return _discover_subdomains_label_dns(
        root_domain=root_domain,
        labels=labels,
        source_name="mutation",
        max_workers=100,
        include_unresolved=include_unresolved,
    )


def _check_wildcard_dns(root_domain: str) -> bool:
    if dns is None:
        return False

    random_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
    probe_host = f"{random_label}.{root_domain}"
    resolver = _dns_make_resolver()
    return any(
        [
            _resolve_dns_records(resolver, probe_host, "A"),
            _resolve_dns_records(resolver, probe_host, "AAAA"),
            _resolve_dns_records(resolver, probe_host, "CNAME"),
        ]
    )


def _dns_record_fingerprint(a_records: List[str], aaaa_records: List[str], cname_records: List[str]) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
    def normalize(values: List[str]) -> Tuple[str, ...]:
        cleaned = []
        for value in values or []:
            text = str(value).strip().lower().rstrip(".")
            if text:
                cleaned.append(text)
        return tuple(sorted(set(cleaned)))

    return (normalize(a_records), normalize(aaaa_records), normalize(cname_records))


def _collect_wildcard_dns_fingerprints(root_domain: str, sample_count: int = 3) -> Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]]:
    fingerprints: Set[Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]] = set()
    if dns is None:
        return fingerprints

    resolver = _dns_make_resolver()
    for _ in range(max(1, sample_count)):
        random_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        probe_host = f"{random_label}.{root_domain}"
        a_records = _resolve_dns_records(resolver, probe_host, "A")
        aaaa_records = _resolve_dns_records(resolver, probe_host, "AAAA")
        cname_records = _resolve_dns_records(resolver, probe_host, "CNAME")

        if a_records or aaaa_records or cname_records:
            fingerprints.add(_dns_record_fingerprint(a_records, aaaa_records, cname_records))

    return fingerprints


def _validate_subdomain(host: str) -> Dict[str, Any]:
    resolver = _dns_make_resolver()
    a_records = _resolve_dns_records(resolver, host, "A")
    aaaa_records = _resolve_dns_records(resolver, host, "AAAA")
    cname_records = _resolve_dns_records(resolver, host, "CNAME")
    dns_alive = bool(a_records or aaaa_records or cname_records)

    ip_value = None
    if a_records:
        ip_value = a_records[0]
    elif aaaa_records:
        ip_value = aaaa_records[0]

    return {
        "host": host,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "cname_records": cname_records,
        "dns_alive": dns_alive,
        "ip": ip_value,
    }


def _extract_title_from_html(html: str) -> str:
    if not html:
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:120]


def _fingerprint_technologies(server_header: str, powered_header: str, html: str) -> List[str]:
    tech: Set[str] = set()
    source = f"{server_header} {powered_header}".lower()

    if "apache" in source:
        tech.add("Apache")
    if "nginx" in source:
        tech.add("Nginx")
    if "iis" in source or "microsoft" in source:
        tech.add("Microsoft IIS")
    if "cloudflare" in source:
        tech.add("Cloudflare")
    if "php" in source:
        tech.add("PHP")
    if "express" in source:
        tech.add("Express")

    lowered_html = (html or "").lower()
    if "wp-content" in lowered_html:
        tech.add("WordPress")
    if "react" in lowered_html:
        tech.add("React")
    if "__next" in lowered_html:
        tech.add("Next.js")

    return sorted(tech)


def _check_subdomain_liveness(host: str) -> Dict[str, Any]:
    timeout_seen = False
    headers = {"User-Agent": "CyberShieldSubdomainPro/1.0"}

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            response = requests.get(
                url,
                timeout=SUBDOMAIN_HTTP_TIMEOUT,
                allow_redirects=True,
                headers=headers,
            )
            html = (response.text or "")[:300000]
            title = _extract_title_from_html(html)
            server_header = (response.headers.get("Server") or "").strip()
            powered_header = (response.headers.get("X-Powered-By") or "").strip()
            status = "Redirect" if response.history else "Live"
            if response.status_code >= 400:
                status = "Dead"

            return {
                "status": status,
                "http_code": int(response.status_code),
                "title": title,
                "server": server_header,
                "tech": _fingerprint_technologies(server_header, powered_header, html),
                "final_url": response.url,
                "body": html[:4000],
            }
        except requests.Timeout:
            timeout_seen = True
        except requests.RequestException:
            continue

    if timeout_seen:
        return {
            "status": "Timeout",
            "http_code": None,
            "title": "",
            "server": "",
            "tech": [],
            "final_url": "",
            "body": "",
        }

    return {
        "status": "Dead",
        "http_code": None,
        "title": "",
        "server": "",
        "tech": [],
        "final_url": "",
        "body": "",
    }


def _check_subdomain_takeover(cname_records: List[str], response_body: str) -> List[str]:
    issues: List[str] = []
    resolver = _dns_make_resolver() if dns is not None else None

    for cname_target in cname_records:
        lowered = cname_target.lower().rstrip(".")

        likely_saas = any(lowered.endswith(suffix) for suffix in SUBDOMAIN_TAKEOVER_SUFFIXES)
        unresolved = False
        if resolver is not None:
            unresolved = not (
                _resolve_dns_records(resolver, lowered, "A")
                or _resolve_dns_records(resolver, lowered, "AAAA")
            )

        if likely_saas and unresolved:
            issues.append(f"Possible subdomain takeover (dangling CNAME -> {cname_target})")

    lowered_body = (response_body or "").lower()
    for fingerprint in SUBDOMAIN_TAKEOVER_FINGERPRINTS:
        if fingerprint.lower() in lowered_body:
            issues.append("Possible subdomain takeover fingerprint detected")
            break

    return list(dict.fromkeys(issues))


def _classify_subdomain_risk(host: str, title: str, takeover_issues: List[str]) -> Tuple[str, List[str]]:
    lowered_host = host.lower()
    lowered_title = (title or "").lower()

    issues: List[str] = []
    risk_weight = 0

    for keyword, severity in SUBDOMAIN_RISK_KEYWORDS.items():
        if keyword not in lowered_host:
            continue

        if keyword in ("admin", "dashboard"):
            issues.append("Admin Panel")
        elif keyword in ("dev", "test", "beta", "old", "staging"):
            issues.append("Exposed Development Host")
        elif keyword in ("login",):
            issues.append("Login Portal")
        elif keyword in ("vpn", "internal"):
            issues.append("Internal Service Exposure")

        if severity == "HIGH":
            risk_weight += 3
        elif severity == "MEDIUM":
            risk_weight += 2

    if any(token in lowered_title for token in ("login", "sign in", "authentication")):
        issues.append("Login Portal")
        risk_weight += 2
    if any(token in lowered_title for token in ("admin", "dashboard")):
        issues.append("Admin Panel")
        risk_weight += 3

    if takeover_issues:
        issues.append("Possible Subdomain Takeover")
        risk_weight += 4

    if risk_weight >= 5:
        risk = "HIGH"
    elif risk_weight >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, list(dict.fromkeys(issues))


def _subdomain_grade(
    total_found: int,
    validated: int,
    live_hosts: int,
    high_risk: int,
    takeover_count: int,
    wildcard_dns: bool,
) -> Tuple[str, int, str]:
    return _subdomain_grade_with_context(
        total_found=total_found,
        validated=validated,
        live_hosts=live_hosts,
        high_risk=high_risk,
        takeover_count=takeover_count,
        wildcard_dns=wildcard_dns,
        historical_unresolved=0,
        public_dev_hosts=0,
    )


def _subdomain_grade_with_context(
    total_found: int,
    validated: int,
    live_hosts: int,
    high_risk: int,
    takeover_count: int,
    wildcard_dns: bool,
    historical_unresolved: int,
    public_dev_hosts: int,
) -> Tuple[str, int, str]:
    score = 100

    score -= min(34, high_risk * 8)
    score -= min(28, takeover_count * 14)
    score -= min(16, historical_unresolved * 2)
    score -= min(18, public_dev_hosts * 3)

    if wildcard_dns:
        score -= 8

    if validated > 0:
        live_ratio = live_hosts / validated
        if live_ratio > 0.7:
            score -= 6
        elif live_ratio > 0.4:
            score -= 3

    if total_found > 200:
        score -= 10
    elif total_found > 80:
        score -= 6
    elif total_found > 40:
        score -= 4

    score = max(0, min(100, score))

    if score >= 96:
        return "A+", score, "Minimal Surface"
    if score >= 85:
        return "B", score, "Controlled"
    if score >= 70:
        return "C", score, "Moderate"
    if score >= 55:
        return "D", score, "Broad Exposure"
    return "F", score, "Critical"


def _subdomain_recommendations(
    high_risk: int,
    dead_hosts: int,
    takeover_count: int,
    wildcard_dns: bool,
    historical_unresolved: int,
    public_dev_hosts: int,
) -> List[str]:
    recommendations: List[str] = []

    if high_risk > 0:
        recommendations.append("Restrict admin, login, VPN, and internal subdomains with strict access controls.")
    if public_dev_hosts > 0:
        recommendations.append("Restrict public staging/dev/test hosts behind authentication or IP allowlisting.")
    if dead_hosts > 0:
        recommendations.append("Remove dead assets from DNS to reduce stale attack surface and confusion.")
    if historical_unresolved > 0:
        recommendations.append("Review historical unresolved hosts and remove stale DNS references.")
    if takeover_count > 0:
        recommendations.append("Review takeover candidates and reclaim or remove dangling CNAME records immediately.")
    if wildcard_dns:
        recommendations.append("Review wildcard DNS configuration and limit broad catch-all records where possible.")

    if not recommendations:
        recommendations.append("Maintain continuous monitoring and periodic attack surface reviews for new subdomain exposure.")

    return list(dict.fromkeys(recommendations))


def subdomain_finder_pro(target_input: str, scan_mode: str = "standard") -> Dict[str, Any]:
    if dns is None:
        return {"error": "dnspython is not installed. Install package 'dnspython' to use Subdomain Finder Pro."}

    normalized = _normalize_dns_target(target_input)
    if "error" in normalized:
        return normalized

    mode = _normalize_scan_mode(scan_mode)
    config = SUBDOMAIN_SCAN_MODE_CONFIG[mode]

    root_domain = normalized["root_domain"]
    wildcard_dns = _check_wildcard_dns(root_domain)
    cache_key = f"v2:{root_domain}:{mode}"
    cached = _subdomain_cache_get(cache_key)
    if cached:
        cached["cached"] = True
        return cached

    source_errors: Dict[str, str] = {}
    source_host_map: Dict[str, Set[str]] = {}

    if config["use_crtsh"]:
        source_host_map["crt.sh"] = set()
    if config["use_otx"]:
        source_host_map["OTX"] = set()
    if config["use_hackertarget"]:
        source_host_map["HackerTarget"] = set()
    if config["use_js"]:
        source_host_map["JS"] = set()
    if config["use_wordlist"]:
        source_host_map["wordlist"] = set()
    if config["use_mutation"]:
        source_host_map["mutation"] = set()
    if config["use_reverse_hints"]:
        source_host_map["reverse-dns"] = set()

    unresolved_source_map: Dict[str, Set[str]] = {}

    passive_tasks: Dict[str, Any] = {}
    if config["use_crtsh"]:
        passive_tasks["crt.sh"] = _discover_subdomains_crtsh
    if config["use_otx"]:
        passive_tasks["OTX"] = _discover_subdomains_otx
    if config["use_hackertarget"]:
        passive_tasks["HackerTarget"] = _discover_subdomains_hackertarget
    if config["use_js"]:
        passive_tasks["JS"] = _discover_subdomains_js_assets

    if passive_tasks:
        with ThreadPoolExecutor(max_workers=min(6, max(1, len(passive_tasks)))) as executor:
            future_map = {
                executor.submit(fn, root_domain): source_name
                for source_name, fn in passive_tasks.items()
            }
            for future in as_completed(future_map):
                source_name = future_map[future]
                try:
                    hosts, error = future.result()
                    source_host_map[source_name] = hosts or set()
                    if error:
                        source_errors[source_name] = error
                except Exception as exc:
                    source_errors[source_name] = f"{source_name} failed: {exc}"

    include_historical = bool(config["include_historical"])

    if config["use_wordlist"] and not wildcard_dns:
        resolved, unresolved, discovery_error = _discover_subdomains_wordlist(
            root_domain=root_domain,
            wordlist_size=int(config["wordlist_size"]),
            include_unresolved=False,
        )
        source_host_map["wordlist"] = resolved
        if discovery_error:
            source_errors["wordlist"] = discovery_error
    elif config["use_wordlist"] and wildcard_dns:
        source_errors["wordlist"] = "Skipped active wordlist expansion because wildcard DNS is enabled for this target."

    observed_hosts = set().union(*source_host_map.values()) if source_host_map else set()
    if config["use_mutation"] and not wildcard_dns:
        resolved, unresolved, discovery_error = _discover_subdomains_mutation(
            root_domain=root_domain,
            observed_hosts=observed_hosts,
            mutation_size=int(config["mutation_size"]),
            include_unresolved=False,
        )
        source_host_map["mutation"] = resolved
        if discovery_error:
            source_errors["mutation"] = discovery_error
    elif config["use_mutation"] and wildcard_dns:
        source_errors["mutation"] = "Skipped mutation engine because wildcard DNS is enabled for this target."

    if config["use_reverse_hints"]:
        reverse_hosts, reverse_error = _discover_subdomains_reverse_hints(root_domain)
        source_host_map["reverse-dns"] = reverse_hosts
        if reverse_error:
            source_errors["reverse-dns"] = reverse_error

    merged_source_tags: Dict[str, Set[str]] = {}
    for source_name, hosts in source_host_map.items():
        for host in hosts:
            normalized_host = _normalize_subdomain_candidate(host, root_domain)
            if not normalized_host:
                continue
            merged_source_tags.setdefault(normalized_host, set()).add(source_name)

    if include_historical:
        for source_name, hosts in unresolved_source_map.items():
            for host in hosts:
                normalized_host = _normalize_subdomain_candidate(host, root_domain)
                if not normalized_host:
                    continue
                merged_source_tags.setdefault(normalized_host, set()).add(source_name)

    result_limit = min(SUBDOMAIN_MAX_RESULTS, int(config["max_results"]))
    all_hosts = sorted(merged_source_tags.keys())[:result_limit]

    validation_rows: List[Dict[str, Any]] = []
    validated_rows: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=36) as executor:
        futures = [executor.submit(_validate_subdomain, host) for host in all_hosts]
        for future in as_completed(futures):
            try:
                row = future.result()
                validation_rows.append(row)
                if row.get("dns_alive"):
                    validated_rows.append(row)
            except Exception:
                continue

    validation_rows.sort(key=lambda x: x.get("host", ""))
    validated_rows.sort(key=lambda x: x["host"])

    unresolved_rows = [row for row in validation_rows if not row.get("dns_alive")]

    liveness_map: Dict[str, Dict[str, Any]] = {}
    max_live = min(SUBDOMAIN_MAX_LIVE_CHECKS, int(config["max_live_checks"]))
    hosts_for_liveness = [row["host"] for row in validated_rows[:max_live]]
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_map = {
            executor.submit(_check_subdomain_liveness, host): host
            for host in hosts_for_liveness
        }
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                liveness_map[host] = future.result()
            except Exception:
                liveness_map[host] = {
                    "status": "Dead",
                    "http_code": None,
                    "title": "",
                    "server": "",
                    "tech": [],
                    "final_url": "",
                    "body": "",
                }

    wildcard_fingerprints = _collect_wildcard_dns_fingerprints(root_domain) if wildcard_dns else set()

    subdomain_rows: List[Dict[str, Any]] = []
    high_risk = 0
    live_hosts = 0
    dead_hosts = 0
    takeover_count = 0
    public_dev_hosts = 0

    for row in validated_rows:
        host = row["host"]
        host_sources = sorted(merged_source_tags.get(host, set()))
        host_source_set = set(host_sources)

        live_data = liveness_map.get(
            host,
            {
                "status": "Dead",
                "http_code": None,
                "title": "",
                "server": "",
                "tech": [],
                "final_url": "",
                "body": "",
            },
        )

        if wildcard_dns and wildcard_fingerprints:
            host_fp = _dns_record_fingerprint(
                row.get("a_records", []),
                row.get("aaaa_records", []),
                row.get("cname_records", []),
            )
            generated_only = bool(host_source_set & SUBDOMAIN_GENERATED_SOURCES) and not bool(host_source_set & SUBDOMAIN_PASSIVE_SOURCES)
            likely_wildcard_false_positive = (
                generated_only
                and host_fp in wildcard_fingerprints
                and live_data.get("status") in ("Dead", "Timeout")
                and live_data.get("http_code") in (None, 404, 410)
            )
            if likely_wildcard_false_positive:
                continue

        takeover_issues = _check_subdomain_takeover(row.get("cname_records", []), live_data.get("body", ""))
        risk, risk_issues = _classify_subdomain_risk(host, live_data.get("title", ""), takeover_issues)
        issues = list(dict.fromkeys(risk_issues + takeover_issues))

        if risk == "HIGH":
            high_risk += 1
        if any(keyword in host for keyword in ("dev", "test", "stage", "staging", "old", "legacy", "beta")):
            public_dev_hosts += 1
        if live_data.get("status") in ("Live", "Redirect"):
            live_hosts += 1
        elif live_data.get("status") in ("Dead", "Timeout"):
            dead_hosts += 1
        if takeover_issues:
            takeover_count += 1

        subdomain_rows.append(
            {
                "host": host,
                "ip": row.get("ip"),
                "status": live_data.get("status", "Dead"),
                "http_code": live_data.get("http_code"),
                "title": live_data.get("title", ""),
                "server": live_data.get("server", ""),
                "tech": live_data.get("tech", []),
                "redirect": live_data.get("status") == "Redirect",
                "final_url": live_data.get("final_url", ""),
                "risk": risk,
                "issues": issues,
                "sources": host_sources,
                "dns": {
                    "a": row.get("a_records", []),
                    "aaaa": row.get("aaaa_records", []),
                    "cname": row.get("cname_records", []),
                },
                "takeover_possible": bool(takeover_issues),
            }
        )

    subdomain_rows.sort(key=lambda x: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["risk"], 3), x["host"]))

    historical_candidates: List[Dict[str, Any]] = []
    for row in unresolved_rows:
        host = row.get("host")
        if not host:
            continue
        risk, issues = _classify_subdomain_risk(host, "", [])
        historical_candidates.append(
            {
                "host": host,
                "sources": sorted(merged_source_tags.get(host, set())),
                "risk": risk,
                "issues": issues or ["Historical unresolved candidate"],
                "reason": "No active DNS A/AAAA/CNAME resolution",
            }
        )

    historical_candidates.sort(key=lambda x: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["risk"], 3), x["host"]))

    grade, score, grade_label = _subdomain_grade_with_context(
        total_found=len(all_hosts),
        validated=len(subdomain_rows),
        live_hosts=live_hosts,
        high_risk=high_risk,
        takeover_count=takeover_count,
        wildcard_dns=wildcard_dns,
        historical_unresolved=len(unresolved_rows),
        public_dev_hosts=public_dev_hosts,
    )

    recommendations = _subdomain_recommendations(
        high_risk=high_risk,
        dead_hosts=dead_hosts,
        takeover_count=takeover_count,
        wildcard_dns=wildcard_dns,
        historical_unresolved=len(unresolved_rows),
        public_dev_hosts=public_dev_hosts,
    )

    used_sources = [
        source_name
        for source_name, hosts in source_host_map.items()
        if hosts
    ]

    source_stats = {source: len(hosts) for source, hosts in source_host_map.items()}

    result = {
        "target": root_domain,
        "scan_mode": mode,
        "grade": grade,
        "grade_label": grade_label,
        "score": score,
        "sources_used": used_sources,
        "source_stats": source_stats,
        "total_found": len(all_hosts),
        "validated": len(subdomain_rows),
        "historical_unresolved": len(unresolved_rows),
        "live_hosts": live_hosts,
        "high_risk": high_risk,
        "wildcard_dns": wildcard_dns,
        "subdomains": subdomain_rows,
        "historical_candidates": historical_candidates[:500],
        "recommendations": recommendations,
        "source_errors": source_errors,
        "cached": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    _subdomain_cache_set(cache_key, result)
    return result


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
    # Backward-compatible wrapper over the advanced HTTP header audit.
    audit = http_header_audit(url_input)
    if "error" in audit:
        return audit

    weak_names = [item.get("header", "") for item in audit.get("weak_headers", []) if item.get("header")]
    return {
        "url": audit.get("final_url"),
        "status_code": audit.get("status_code"),
        "headers": audit.get("headers", {}),
        "missing_security_headers": audit.get("headers_missing", []) + weak_names,
    }


def _normalize_header_audit_target(target_input: str) -> Dict[str, Any]:
    raw = str(target_input or "").strip()
    if not raw:
        return {"error": "Target is required."}

    has_scheme = "://" in raw

    if has_scheme:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return {"error": "Invalid URL format. Use domain, http://, or https:// target."}

        path = parsed.path or "/"
        https_url = urlunparse(("https", parsed.netloc, path, parsed.params, parsed.query, ""))
        http_url = urlunparse(("http", parsed.netloc, path, parsed.params, parsed.query, ""))

        return {
            "target": raw,
            "input_had_scheme": True,
            "primary_url": raw,
            "https_url": https_url,
            "http_url": http_url,
        }

    normalized = raw.lstrip("/")
    parsed = urlparse(f"https://{normalized}")
    if not parsed.netloc:
        return {"error": "Invalid target format."}

    path = parsed.path or "/"
    https_url = urlunparse(("https", parsed.netloc, path, parsed.params, parsed.query, ""))
    http_url = urlunparse(("http", parsed.netloc, path, parsed.params, parsed.query, ""))

    return {
        "target": raw,
        "input_had_scheme": False,
        "primary_url": https_url,
        "https_url": https_url,
        "http_url": http_url,
    }


def _fetch_header_response(url: str) -> Tuple[requests.Response, int]:
    started = time.perf_counter()
    response = requests.get(
        url,
        timeout=HEADER_AUDIT_TIMEOUT_SECONDS,
        allow_redirects=True,
        headers={"User-Agent": "CyberShield-HeaderAudit/1.0"},
    )
    response_time_ms = int((time.perf_counter() - started) * 1000)
    return response, response_time_ms


def _collect_set_cookie_headers(response: requests.Response) -> List[str]:
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values = raw_headers.getlist("Set-Cookie")
        return [v for v in values if v]

    fallback = response.headers.get("Set-Cookie")
    if not fallback:
        return []
    return [fallback]


def _cookie_expiry_days(attrs: Dict[str, str]) -> Optional[float]:
    max_age = attrs.get("max-age")
    if max_age:
        try:
            return int(max_age) / 86400.0
        except ValueError:
            return None

    expires = attrs.get("expires")
    if expires:
        try:
            expires_dt = parsedate_to_datetime(expires)
            if not expires_dt:
                return None
            return (expires_dt.timestamp() - time.time()) / 86400.0
        except Exception:
            return None

    return None


def _analyze_cookie_security(set_cookie_values: List[str]) -> List[Dict[str, Any]]:
    cookie_results: List[Dict[str, Any]] = []

    for raw_cookie in set_cookie_values:
        parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue

        cookie_name = parts[0].split("=", 1)[0].strip()

        attrs: Dict[str, str] = {}
        attr_flags: Set[str] = set()
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                attrs[key.strip().lower()] = value.strip()
            else:
                attr_flags.add(part.strip().lower())

        has_httponly = "httponly" in attr_flags
        has_secure = "secure" in attr_flags
        same_site = attrs.get("samesite", "")
        expiry_days = _cookie_expiry_days(attrs)
        session_cookie = expiry_days is None
        long_expiry = expiry_days is not None and expiry_days > 90

        risks: List[str] = []
        if not has_httponly:
            risks.append("Missing HttpOnly flag")
        if not has_secure:
            risks.append("Missing Secure flag")
        if not same_site:
            risks.append("Missing SameSite attribute")
        if same_site.lower() == "none" and not has_secure:
            risks.append("SameSite=None without Secure")
        if long_expiry:
            risks.append("Long-lived cookie expiry")

        cookie_results.append(
            {
                "cookie_name": cookie_name,
                "httponly": has_httponly,
                "secure": has_secure,
                "samesite": same_site or "Not Set",
                "session_cookie": session_cookie,
                "long_expiry": long_expiry,
                "risk": "; ".join(risks) if risks else "None",
            }
        )

    return cookie_results


def _analyze_security_headers(lower_headers: Dict[str, str]) -> Dict[str, Any]:
    present: List[str] = []
    missing: List[str] = []
    weak: List[Dict[str, str]] = []
    table: List[Dict[str, str]] = []

    for header in SECURITY_HEADER_NAMES:
        key = header.lower()
        value = lower_headers.get(key)

        if not value:
            missing.append(header)
            table.append({"header": header, "status": "Missing", "notes": "Header not present"})
            continue

        present.append(header)
        status = "Present"
        notes = "Configured"
        value_lower = value.lower()

        if header == "Content-Security-Policy":
            if "unsafe-inline" in value_lower or "unsafe-eval" in value_lower:
                status = "Weak"
                notes = "Contains unsafe-inline or unsafe-eval"
            elif "default-src" not in value_lower:
                status = "Weak"
                notes = "Missing default-src directive"
        elif header == "Strict-Transport-Security":
            max_age_match = re.search(r"max-age\s*=\s*(\d+)", value_lower)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            if max_age < 31536000:
                status = "Weak"
                notes = "HSTS max-age lower than 31536000"
            elif "includesubdomains" not in value_lower:
                status = "Weak"
                notes = "Missing includeSubDomains"
        elif header == "X-Frame-Options":
            if value_upper := value.upper().strip():
                if value_upper not in ("DENY", "SAMEORIGIN"):
                    status = "Weak"
                    notes = "Use DENY or SAMEORIGIN"
        elif header == "X-Content-Type-Options":
            if value_lower.strip() != "nosniff":
                status = "Weak"
                notes = "Use nosniff"
        elif header == "Referrer-Policy":
            strong_values = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
            if value_lower.strip() not in strong_values:
                status = "Weak"
                notes = "Use strict-origin-when-cross-origin or stricter"
        elif header == "Permissions-Policy":
            if "*" in value_lower:
                status = "Weak"
                notes = "Wildcard permissions reduce isolation"
        elif header == "Cross-Origin-Opener-Policy":
            if value_lower.strip() not in ("same-origin", "same-origin-allow-popups"):
                status = "Weak"
                notes = "Use same-origin for stronger process isolation"
        elif header == "Cross-Origin-Embedder-Policy":
            if value_lower.strip() not in ("require-corp", "credentialless"):
                status = "Weak"
                notes = "Use require-corp or credentialless"
        elif header == "Cross-Origin-Resource-Policy":
            if value_lower.strip() not in ("same-origin", "same-site", "cross-origin"):
                status = "Weak"
                notes = "Unexpected CORP value"

        if status == "Weak":
            weak.append({"header": header, "reason": notes, "value": value})

        table.append({"header": header, "status": status, "notes": notes})

    return {
        "headers_present": present,
        "headers_missing": missing,
        "weak_headers": weak,
        "security_headers": table,
    }


def _detect_information_leaks(lower_headers: Dict[str, str]) -> List[str]:
    leaks: List[str] = []

    for header in LEAKY_HEADER_NAMES:
        if header not in lower_headers:
            continue
        value = lower_headers.get(header, "").strip()
        if not value:
            continue

        if re.search(r"\d", value):
            leaks.append(f"{header.title()} version disclosure: {value}")
        else:
            leaks.append(f"{header.title()} header exposed: {value}")

    return leaks


def _analyze_cache_security(lower_headers: Dict[str, str]) -> Dict[str, Any]:
    cache_control = lower_headers.get("cache-control", "")
    pragma = lower_headers.get("pragma", "")
    expires = lower_headers.get("expires", "")

    issues: List[str] = []

    cache_lower = cache_control.lower()
    pragma_lower = pragma.lower()

    if not cache_control:
        issues.append("Missing Cache-Control header.")
    else:
        if "public" in cache_lower and "no-store" not in cache_lower and "private" not in cache_lower:
            issues.append("Cache-Control allows public caching; sensitive data could be cached.")
        if "no-store" in cache_lower and "public" in cache_lower:
            issues.append("Conflicting Cache-Control directives (no-store with public).")

    if pragma and "no-cache" in pragma_lower and "public" in cache_lower:
        issues.append("Pragma no-cache conflicts with public cache directive.")

    if expires and "no-store" in cache_lower and expires.strip() not in ("0", "-1"):
        issues.append("Expires header may conflict with no-store cache policy.")

    return {
        "cache_control": cache_control or "Not Set",
        "pragma": pragma or "Not Set",
        "expires": expires or "Not Set",
        "issues": issues,
    }


def _check_https_posture(targets: Dict[str, Any], final_response: requests.Response) -> Dict[str, Any]:
    final_scheme = urlparse(final_response.url).scheme.lower()
    https_supported = final_scheme == "https"
    redirect_from_http = False
    redirect_note = ""

    try:
        http_response, _ = _fetch_header_response(targets["http_url"])
        redirect_from_http = bool(http_response.history) and urlparse(http_response.url).scheme.lower() == "https"
        if not https_supported and urlparse(http_response.url).scheme.lower() == "https":
            https_supported = True
    except requests.RequestException as exc:
        # If HTTP endpoint is unavailable but HTTPS works, treat as enforced posture.
        redirect_note = str(exc)
        if https_supported:
            redirect_from_http = True

    if not https_supported:
        try:
            https_probe, _ = _fetch_header_response(targets["https_url"])
            https_supported = https_probe.status_code < 500
        except requests.RequestException:
            https_supported = False

    return {
        "https_supported": https_supported,
        "https_enforced": https_supported and redirect_from_http,
        "redirect_from_http": redirect_from_http,
        "note": redirect_note,
    }


def _build_security_grade(
    missing_headers: List[str],
    weak_headers: List[Dict[str, str]],
    cookie_risk_count: int,
    leaks: List[str],
    cache_issues: List[str],
    https_enforced: bool,
    protocol_used: str,
) -> Tuple[str, int]:
    score = 100
    score -= len(missing_headers) * 8
    score -= len(weak_headers) * 5
    score -= cookie_risk_count * 4
    score -= len(leaks) * 5
    score -= len(cache_issues) * 3

    if not https_enforced:
        score -= 15
    if protocol_used != "https":
        score -= 10

    score = max(0, min(100, score))

    if score >= 97:
        return "A+", score
    if score >= 90:
        return "A", score
    if score >= 80:
        return "B", score
    if score >= 70:
        return "C", score
    if score >= 60:
        return "D", score
    return "F", score


def _build_recommendations(
    missing_headers: List[str],
    weak_headers: List[Dict[str, str]],
    cookies: List[Dict[str, Any]],
    leaks: List[str],
    cache_issues: List[str],
    https_enforced: bool,
) -> List[str]:
    recommendations: List[str] = []

    for header in missing_headers:
        recommendations.append(f"Add {header} header.")

    for weak in weak_headers:
        recommendations.append(f"Strengthen {weak.get('header')}: {weak.get('reason')}.")

    for cookie in cookies:
        risk_text = str(cookie.get("risk", "None"))
        if risk_text != "None":
            recommendations.append(f"Harden cookie {cookie.get('cookie_name')}: {risk_text}.")

    if leaks:
        recommendations.append("Remove or sanitize Server/X-Powered-By style headers to reduce fingerprinting.")

    if cache_issues:
        recommendations.append("Review cache policy. Use Cache-Control: no-store for sensitive responses.")

    if not https_enforced:
        recommendations.append("Enforce HTTP to HTTPS redirection and deploy HSTS with strong max-age.")

    # Normalize through JSON (ensures plain serializable output) and keep insertion order unique.
    normalized = json.loads(json.dumps(recommendations))
    return list(dict.fromkeys(normalized))


def http_header_audit(target_input: str) -> Dict[str, Any]:
    targets = _normalize_header_audit_target(target_input)
    if "error" in targets:
        return targets

    attempts: List[str] = [targets["primary_url"]]
    if not targets.get("input_had_scheme"):
        attempts.append(targets["http_url"])

    response: Optional[requests.Response] = None
    response_time_ms = 0
    attempt_errors: List[str] = []

    for url in list(dict.fromkeys(attempts)):
        try:
            response, response_time_ms = _fetch_header_response(url)
            break
        except requests.RequestException as exc:
            attempt_errors.append(f"{url}: {str(exc)}")

    if response is None:
        return {
            "error": "Could not fetch target headers.",
            "details": attempt_errors,
        }

    headers = dict(response.headers.items())
    lower_headers = {k.lower(): v for k, v in headers.items()}

    header_analysis_result = _analyze_security_headers(lower_headers)
    cookies = _analyze_cookie_security(_collect_set_cookie_headers(response))
    leaks = _detect_information_leaks(lower_headers)
    cache_review = _analyze_cache_security(lower_headers)
    https_posture = _check_https_posture(targets, response)

    cookie_risk_count = sum(1 for c in cookies if c.get("risk") and c.get("risk") != "None")

    protocol_used = urlparse(response.url).scheme.lower()
    grade, score = _build_security_grade(
        header_analysis_result["headers_missing"],
        header_analysis_result["weak_headers"],
        cookie_risk_count,
        leaks,
        cache_review["issues"],
        https_posture["https_enforced"],
        protocol_used,
    )

    issues: List[str] = []
    issues.extend([f"Missing header: {name}" for name in header_analysis_result["headers_missing"]])
    issues.extend([f"Weak header {item['header']}: {item['reason']}" for item in header_analysis_result["weak_headers"]])
    issues.extend([f"Cookie {c['cookie_name']}: {c['risk']}" for c in cookies if c.get("risk") and c.get("risk") != "None"])
    issues.extend(leaks)
    issues.extend(cache_review["issues"])
    if not https_posture["https_enforced"]:
        issues.append("No forced HTTP to HTTPS redirect detected.")

    recommendations = _build_recommendations(
        header_analysis_result["headers_missing"],
        header_analysis_result["weak_headers"],
        cookies,
        leaks,
        cache_review["issues"],
        https_posture["https_enforced"],
    )

    redirect_chain = [hist.url for hist in response.history] + [response.url]

    return {
        "target": str(target_input).strip(),
        "final_url": response.url,
        "redirected_url": response.url if response.history else None,
        "redirect_chain": redirect_chain,
        "protocol_used": protocol_used,
        "status_code": response.status_code,
        "response_time_ms": response_time_ms,
        "grade": grade,
        "score": score,
        "https_enforced": https_posture["https_enforced"],
        "headers_present": header_analysis_result["headers_present"],
        "headers_missing": header_analysis_result["headers_missing"],
        "weak_headers": header_analysis_result["weak_headers"],
        "security_headers": header_analysis_result["security_headers"],
        "cookies": cookies,
        "cookie_risk_count": cookie_risk_count,
        "leaks": leaks,
        "cache_security": cache_review,
        "issues": list(dict.fromkeys(issues)),
        "recommendations": recommendations,
        "headers": headers,
    }


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_advanced_target(target_input: str) -> Dict:
    target = str(target_input or "").strip()
    if not target:
        return {"error": "Target is required."}

    # Validate IPs directly first (IPv4/IPv6)
    if _is_ip_address(target):
        return {"target": target, "resolved_ip": target}

    host = normalize_domain_input(target) or target

    # Requirement: use gethostbyname for resolution check
    resolved_ipv4 = None
    try:
        resolved_ipv4 = socket.gethostbyname(host)
    except Exception:
        resolved_ipv4 = None

    # Prefer the first stream-resolvable address (supports IPv6 where available)
    try:
        addrinfo = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = [item[4][0] for item in addrinfo if item and item[4]]
        if not addresses and not resolved_ipv4:
            return {"error": "Invalid target. Enter a valid domain, IPv4, or IPv6."}
        resolved_ip = addresses[0] if addresses else resolved_ipv4
    except Exception:
        if not resolved_ipv4:
            return {"error": "Invalid target. Enter a valid domain, IPv4, or IPv6."}
        resolved_ip = resolved_ipv4

    return {"target": host, "resolved_ip": resolved_ip}


def _parse_custom_range(custom_range: str) -> List[int]:
    text = str(custom_range or "").strip()
    if not text:
        return []

    valid_chars = set("0123456789,- ")
    if any(ch not in valid_chars for ch in text):
        return []

    ports: Set[int] = set()
    for chunk in [c.strip() for c in text.split(",") if c.strip()]:
        if "-" in chunk:
            parts = chunk.split("-", 1)
            if len(parts) != 2:
                return []
            try:
                start = int(parts[0].strip())
                end = int(parts[1].strip())
            except ValueError:
                return []
            if start > end or start < 1 or end > 65535:
                return []
            for port in range(start, end + 1):
                ports.add(port)
        else:
            try:
                port = int(chunk)
            except ValueError:
                return []
            if port < 1 or port > 65535:
                return []
            ports.add(port)

    return sorted(ports)


def _ports_for_scan_profile(scan_type: str, custom_range: str = "") -> Tuple[List[int], Optional[str]]:
    normalized = str(scan_type or "quick").strip().lower()

    if normalized == "quick":
        ports = ADVANCED_QUICK_PORTS
    elif normalized == "full":
        ports = list(range(1, 1025))
    elif normalized == "web":
        ports = ADVANCED_WEB_PORTS
    elif normalized == "custom":
        ports = _parse_custom_range(custom_range)
        if not ports:
            return [], "Invalid custom range. Use formats like 80,443 or 1000-2000."
    else:
        return [], "Invalid scan_type. Use quick, full, web, or custom."

    if len(ports) > MAX_SCAN_PORTS:
        return [], f"Too many ports requested. Maximum allowed is {MAX_SCAN_PORTS}."

    return ports, None


def _detect_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp").upper()
    except Exception:
        return ADVANCED_SERVICE_MAP.get(port, "Unknown")


def _decode_banner(data: bytes) -> str:
    if not data:
        return ""
    return data.decode("utf-8", errors="ignore").strip().replace("\x00", "")


def _grab_banner(sock: socket.socket, target_host: str, port: int) -> str:
    try:
        if port in (443, 8443):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            server_name = target_host if not _is_ip_address(target_host) else None
            with context.wrap_socket(sock, server_hostname=server_name) as tls_sock:
                tls_sock.settimeout(SCAN_TIMEOUT_SECONDS)
                tls_sock.sendall(
                    f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode()
                )
                return _decode_banner(tls_sock.recv(1024))

        if port in (80, 8080):
            sock.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode()
            )
            return _decode_banner(sock.recv(1024))

        # For banner-first protocols (FTP/SMTP/SSH/etc.), read greeting first
        try:
            greeting = _decode_banner(sock.recv(1024))
            if greeting:
                return greeting
        except Exception:
            pass

        # Generic fallback
        try:
            sock.sendall(b"\r\n")
            return _decode_banner(sock.recv(1024))
        except Exception:
            return ""
    except Exception:
        return ""


def _extract_service_version(banner: str) -> Tuple[Optional[str], Optional[str]]:
    if not banner:
        return None, None

    for pattern, product in VERSION_PATTERNS:
        match = pattern.search(banner)
        if match:
            version = match.group(1) if match.lastindex else None
            return product, version

    return None, None


def _scan_single_port(resolved_ip: str, target_host: str, port: int) -> Dict:
    service = _detect_service_name(port)
    status = "closed"
    banner = ""
    product = None
    version = None

    try:
        with socket.create_connection((resolved_ip, port), timeout=SCAN_TIMEOUT_SECONDS) as sock:
            sock.settimeout(SCAN_TIMEOUT_SECONDS)
            status = "open"
            banner = _grab_banner(sock, target_host, port)
    except socket.timeout:
        status = "filtered"
    except ConnectionRefusedError:
        status = "closed"
    except OSError as exc:
        if getattr(exc, "errno", None) in (110, 60, 10060, 113, 101):
            status = "filtered"
        else:
            status = "closed"

    if status == "open":
        detected_product, detected_version = _extract_service_version(banner)
        if detected_product:
            product = detected_product
        if detected_version:
            version = detected_version

    issue = RISKY_PORT_ISSUES.get(port) if status == "open" else None

    return {
        "port": port,
        "status": status,
        "service": service,
        "banner": banner or None,
        "product": product,
        "version": version,
        "risky": bool(issue),
        "issue": issue,
    }


def _guess_os_from_scan(open_results: List[Dict]) -> str:
    if not open_results:
        return "Unknown"

    open_ports = {item.get("port") for item in open_results}
    banner_blob = " ".join((item.get("banner") or "") for item in open_results).lower()

    if any(port in open_ports for port in (3389, 445, 139)) or "microsoft-iis" in banner_blob:
        return "Windows (Approximate)"

    if "openssh" in banner_blob and ("apache" in banner_blob or "nginx" in banner_blob):
        return "Linux (Approximate)"

    if "openssh" in banner_blob or "postfix" in banner_blob or "exim" in banner_blob:
        return "Linux/Unix (Approximate)"

    return "Unknown"


def _compute_risk_level(open_results: List[Dict], issues: List[str]) -> str:
    open_count = len(open_results)
    high_risk_ports = {23, 445, 3389}
    open_port_set = {item.get("port") for item in open_results}

    if any(port in open_port_set for port in high_risk_ports):
        return "HIGH"

    if open_count >= 10:
        return "MEDIUM"

    if issues:
        return "MEDIUM"

    return "LOW"


def advanced_network_scan(target_input: str, scan_type: str = "quick", custom_range: str = "") -> Dict:
    """
    Advanced, web-safe network scanner with scan profiles, service detection,
    banner/version parsing, OS guess, and risk summary.
    """
    resolved = _resolve_advanced_target(target_input)
    if "error" in resolved:
        return resolved

    ports, error = _ports_for_scan_profile(scan_type, custom_range)
    if error:
        return {"error": error}

    target = resolved["target"]
    resolved_ip = resolved["resolved_ip"]
    started = time.perf_counter()

    max_workers = min(100, max(1, len(ports)))
    results: List[Dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_scan_single_port, resolved_ip, target, port) for port in ports]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x["port"])

    open_results = [item for item in results if item["status"] == "open"]
    closed_count = sum(1 for item in results if item["status"] == "closed")
    filtered_count = sum(1 for item in results if item["status"] == "filtered")
    issues = [item["issue"] for item in open_results if item.get("issue")]
    os_guess = _guess_os_from_scan(open_results)
    risk_level = _compute_risk_level(open_results, issues)
    services = sorted({item["service"] for item in open_results if item.get("service")})

    duration_ms = int((time.perf_counter() - started) * 1000)
    summary = (
        f"Scanned {len(ports)} ports on {target}. "
        f"Open: {len(open_results)}, Closed: {closed_count}, Filtered: {filtered_count}. "
        f"Risk: {risk_level}."
    )

    return {
        "target": target,
        "resolved_ip": resolved_ip,
        "scan_type": str(scan_type).lower(),
        "ports_scanned": len(ports),
        "open_ports": len(open_results),
        "closed_ports": closed_count,
        "filtered_ports": filtered_count,
        "services": services,
        "os_guess": os_guess,
        "risk_level": risk_level,
        "issues": issues,
        "summary": summary,
        "warning": "Use this scanner only on authorized systems. Unauthorized scanning may be illegal.",
        "duration_ms": duration_ms,
        "results": results,
        "open_port_details": open_results,
    }
