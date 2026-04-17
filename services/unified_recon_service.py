import ipaddress
import json
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .domain_services import normalize_domain_input
from .recon_service import (
    advanced_network_scan,
    dns_lookup,
    dns_lookup_pro,
    http_header_audit,
    subdomain_finder_pro,
)
from .ssl_service import check_ssl_certificate
from .tech_stack_service import analyze_tech_stack
from .whois_service import get_whois_info

UNIFIED_RECON_CACHE_TTL_SECONDS = 300
_UNIFIED_RECON_CACHE_LOCK = threading.Lock()
_UNIFIED_RECON_CACHE: Dict[str, Dict[str, Any]] = {}

MODULE_WEIGHTS = {
    "dns": 20,
    "headers": 20,
    "ssl": 15,
    "ports": 20,
    "subdomains": 15,
    "tech": 10,
}

SEVERITY_RANK = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}

RISKY_PORT_PENALTIES = {
    21: 12,
    23: 18,
    445: 15,
    3389: 14,
}


def _is_ip_target(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _normalize_web_target(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        return raw
    if "://" in raw:
        return raw
    return f"https://{raw}"


def _parse_iso_date(value: Any):
    if value in (None, "", "N/A"):
        return None
    text = str(value)
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _is_likely_login_target(target: str) -> bool:
    lowered = str(target or "").lower()
    return any(token in lowered for token in ("login", "signin", "auth", "account"))


def _cache_get(cache_key: str) -> Optional[Dict[str, Any]]:
    now = time.time()
    with _UNIFIED_RECON_CACHE_LOCK:
        entry = _UNIFIED_RECON_CACHE.get(cache_key)
        if not entry:
            return None
        if now > entry.get("expires_at", 0):
            _UNIFIED_RECON_CACHE.pop(cache_key, None)
            return None
        data = entry.get("data")
        if not isinstance(data, dict):
            return None
        return json.loads(json.dumps(data))


def _cache_set(cache_key: str, data: Dict[str, Any]) -> None:
    with _UNIFIED_RECON_CACHE_LOCK:
        _UNIFIED_RECON_CACHE[cache_key] = {
            "expires_at": time.time() + UNIFIED_RECON_CACHE_TTL_SECONDS,
            "data": json.loads(json.dumps(data)),
        }


def _module_result(ok: bool, duration_ms: int, data: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> Dict[str, Any]:
    return {
        "ok": ok,
        "duration_ms": duration_ms,
        "data": data or {},
        "error": error,
    }


def _run_module(name: str, fn) -> Tuple[str, Dict[str, Any]]:
    started = time.perf_counter()
    try:
        result = fn()
        duration_ms = int((time.perf_counter() - started) * 1000)

        if isinstance(result, dict) and "error" in result:
            return name, _module_result(False, duration_ms, data=result, error=str(result.get("error")))

        return name, _module_result(True, duration_ms, data=result if isinstance(result, dict) else {"result": result})
    except Exception as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        return name, _module_result(
            False,
            duration_ms,
            data={"traceback": traceback.format_exc(limit=4)},
            error=str(exc),
        )


def _grade_from_risk_score(score: int) -> Tuple[str, str]:
    if score <= 15:
        return "A+", "Excellent"
    if score <= 25:
        return "A", "Strong"
    if score <= 40:
        return "B", "Good"
    if score <= 55:
        return "C", "Moderate"
    if score <= 70:
        return "D", "Risky"
    return "F", "Critical"


def _risk_level_from_score(score: int) -> str:
    if score <= 20:
        return "Excellent"
    if score <= 40:
        return "Good"
    if score <= 60:
        return "Moderate"
    if score <= 80:
        return "Risky"
    return "Critical"


def _score_band_label(score: int) -> str:
    if score <= 20:
        return "Minimal Exposure"
    if score <= 40:
        return "Controlled"
    if score <= 60:
        return "Watchlist"
    if score <= 80:
        return "Elevated"
    return "Urgent"


def _executive_summary(target: str, risk_level: str) -> str:
    if risk_level in ("Excellent", "Good"):
        return "This target demonstrates a generally strong external posture with minor web hardening opportunities."
    if risk_level == "Moderate":
        return "This target has moderate exposure with a few missing protections and some publicly reachable assets."
    if risk_level == "Risky":
        return "This target presents elevated risk due to exposed services and multiple weak security controls."
    return "This target shows severe exposure requiring urgent remediation across multiple categories."


def _module_scorecard(risk_score: int, weight: int) -> Dict[str, Any]:
    score = max(0, min(100, int(risk_score)))
    grade, _grade_label = _grade_from_risk_score(score)
    return {
        "risk_score": score,
        "weight": weight,
        "grade": grade,
        "risk_level": _risk_level_from_score(score),
    }


def _add_finding(
    findings: List[Dict[str, Any]],
    module: str,
    severity: str,
    title: str,
    points: int,
    detail: str = "",
) -> None:
    if not title:
        return
    findings.append(
        {
            "module": module,
            "severity": severity,
            "title": title,
            "detail": detail,
            "points": int(points),
        }
    )


def _merge_recommendation(recommendations: List[Tuple[int, str]], priority: int, text: str) -> None:
    if text:
        recommendations.append((priority, text))


def _compute_unified_risk(
    target: str,
    mode: str,
    modules: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    recommendations_ranked: List[Tuple[int, str]] = []
    module_scores: Dict[str, Dict[str, Any]] = {}
    module_views: Dict[str, Dict[str, Any]] = {}

    exposed_admin_count = 0
    risky_ports_count = 0
    takeover_candidates = 0
    expired_ssl = False
    no_https_enforced = False
    login_target = _is_likely_login_target(target)

    dns_grade = "N/A"
    header_grade = "N/A"
    ssl_status = "Unknown"
    open_ports: List[int] = []
    tech_list: List[str] = []
    subdomains_found = 0

    dns_mod = modules.get("dns", {})
    if dns_mod.get("ok"):
        dns_data = dns_mod.get("data", {})
        dns_risk = 22
        dns_issues: List[str] = []

        dnssec_enabled = bool(dns_data.get("dnssec", {}).get("enabled"))
        spf_data = dns_data.get("spf", {}) if isinstance(dns_data.get("spf"), dict) else {}
        dmarc_data = dns_data.get("dmarc", {}) if isinstance(dns_data.get("dmarc"), dict) else {}

        spf_present = bool(spf_data.get("present"))
        spf_policy = str(spf_data.get("policy", "missing")).lower()
        dmarc_present = bool(dmarc_data.get("present"))
        dmarc_policy = str(dmarc_data.get("policy", "missing")).lower()

        dns_grade = str(dns_data.get("grade", "N/A"))

        if dnssec_enabled:
            dns_risk -= 4
        else:
            dns_risk += 6
            dns_issues.append("DNSSEC disabled")
            _add_finding(findings, "dns", "Medium", "DNSSEC is disabled", 6)
            _merge_recommendation(recommendations_ranked, 9, "Enable DNSSEC with DS/DNSKEY records.")

        if not spf_present:
            dns_risk += 10
            dns_issues.append("SPF missing")
            _add_finding(findings, "dns", "High", "SPF record missing", 10)
            _merge_recommendation(recommendations_ranked, 8, "Publish an SPF record and restrict senders.")
        elif spf_policy == "~all":
            dns_risk += 6
            dns_issues.append("SPF uses soft fail (~all)")
            _add_finding(findings, "dns", "Medium", "SPF policy is weak (~all)", 6)
        elif spf_policy == "+all":
            dns_risk += 12
            dns_issues.append("SPF uses allow-all (+all)")
            _add_finding(findings, "dns", "High", "SPF policy allows all senders (+all)", 12)

        if not dmarc_present:
            dns_risk += 10
            dns_issues.append("DMARC missing")
            _add_finding(findings, "dns", "High", "DMARC record missing", 10)
            _merge_recommendation(recommendations_ranked, 9, "Publish a DMARC policy with reporting.")
        elif dmarc_policy == "none":
            dns_risk += 8
            dns_issues.append("DMARC policy set to none")
            _add_finding(findings, "dns", "Medium", "DMARC policy is set to none", 8)
        elif dmarc_policy == "quarantine":
            dns_risk += 4
        elif dmarc_policy == "reject":
            dns_risk -= 6

        mx_count = _safe_int(dns_data.get("mx", {}).get("count"))
        ns_count = _safe_int(dns_data.get("ns", {}).get("count"))

        if ns_count <= 1:
            dns_risk += 3
            dns_issues.append("Low NS redundancy")

        dns_issues.extend([str(issue) for issue in dns_data.get("issues", [])[:5]])
        dns_recommendations = [str(rec) for rec in dns_data.get("recommendations", [])[:6]]

        spf_status = "Missing"
        if spf_present and spf_policy in ("-all", "hardfail"):
            spf_status = "Strong"
        elif spf_present:
            spf_status = "Weak"

        dmarc_status = "Missing"
        if dmarc_present and dmarc_policy == "reject":
            dmarc_status = "Reject"
        elif dmarc_present and dmarc_policy == "quarantine":
            dmarc_status = "Quarantine"
        elif dmarc_present:
            dmarc_status = "None"

        module_views["dns"] = {
            "dns_grade": dns_grade,
            "dnssec_enabled": dnssec_enabled,
            "spf_status": spf_status,
            "dmarc_policy": dmarc_status,
            "mx_count": mx_count,
            "ns_count": ns_count,
            "key_issues": list(dict.fromkeys(dns_issues))[:6],
            "recommendations": dns_recommendations,
        }
        module_scores["dns"] = _module_scorecard(dns_risk, MODULE_WEIGHTS["dns"])
    else:
        module_views["dns"] = {
            "dns_grade": "N/A",
            "dnssec_enabled": False,
            "spf_status": "Missing",
            "dmarc_policy": "Missing",
            "mx_count": 0,
            "ns_count": 0,
            "key_issues": ["DNS intelligence module failed"],
            "recommendations": ["Re-run scan and validate DNS resolution for target."],
        }
        module_scores["dns"] = _module_scorecard(55, MODULE_WEIGHTS["dns"])
        _add_finding(findings, "dns", "Medium", "DNS intelligence did not complete", 12)

    sub_mod = modules.get("subdomains", {})
    if sub_mod.get("ok"):
        sub_data = sub_mod.get("data", {})
        sub_risk = 20

        subdomains_found = _safe_int(sub_data.get("total_found"))
        live_hosts = _safe_int(sub_data.get("live_hosts"))
        high_risk_hosts = _safe_int(sub_data.get("high_risk"))
        sub_rows = sub_data.get("subdomains", []) if isinstance(sub_data.get("subdomains"), list) else []

        risky_rows = [row for row in sub_rows if str(row.get("risk", "")).upper() == "HIGH"]
        risky_rows_sorted = sorted(
            risky_rows,
            key=lambda row: (row.get("status") != "Live", row.get("host", "")),
        )
        top_risky = [
            {
                "host": str(row.get("host", "")),
                "status": str(row.get("status", "Unknown")),
                "risk": str(row.get("risk", "LOW")),
                "title": str(row.get("title", "") or "-")[:90],
            }
            for row in risky_rows_sorted[:8]
        ]

        if subdomains_found > 120:
            sub_risk += 8
        elif subdomains_found > 60:
            sub_risk += 4

        if high_risk_hosts > 0:
            sub_risk += min(18, high_risk_hosts * 3)
            _add_finding(findings, "subdomains", "High", f"{high_risk_hosts} high-risk subdomains exposed", min(18, high_risk_hosts * 3))

        public_dev_hosts = 0
        admin_panels = 0
        takeover_candidates = sum(1 for row in sub_rows if row.get("takeover_possible"))

        for row in sub_rows:
            host = str(row.get("host", "")).lower()
            status = str(row.get("status", ""))
            if status in ("Live", "Redirect") and any(token in host for token in ("dev", "test", "stage", "staging", "beta")):
                public_dev_hosts += 1
            issues = [str(issue).lower() for issue in row.get("issues", [])]
            if "admin panel" in issues or "admin" in host:
                admin_panels += 1

        exposed_admin_count = admin_panels

        if public_dev_hosts > 0:
            sub_risk += 8
            _add_finding(findings, "subdomains", "Medium", "Public development/staging host detected", 8)
            _merge_recommendation(recommendations_ranked, 8, "Restrict public development and staging subdomains.")

        if admin_panels > 0:
            sub_risk += 15
            _add_finding(findings, "subdomains", "High", "Exposed admin subdomain detected", 15)

        if takeover_candidates > 0:
            sub_risk += 28
            _add_finding(findings, "subdomains", "Critical", "Potential subdomain takeover candidate identified", 28)
            _merge_recommendation(recommendations_ranked, 10, "Investigate and remediate dangling CNAME records immediately.")

        module_views["subdomains"] = {
            "total_found": subdomains_found,
            "live_hosts": live_hosts,
            "high_risk_hosts": high_risk_hosts,
            "top_risky_subdomains": top_risky,
            "takeover_candidates": takeover_candidates,
            "public_dev_hosts": public_dev_hosts,
            "key_issues": [str(issue) for issue in sub_data.get("recommendations", [])[:4]],
            "recommendations": [str(rec) for rec in sub_data.get("recommendations", [])[:6]],
        }
        module_scores["subdomains"] = _module_scorecard(sub_risk, MODULE_WEIGHTS["subdomains"])
    elif mode != "quick":
        module_views["subdomains"] = {
            "total_found": 0,
            "live_hosts": 0,
            "high_risk_hosts": 0,
            "top_risky_subdomains": [],
            "takeover_candidates": 0,
            "public_dev_hosts": 0,
            "key_issues": ["Subdomain module failed"],
            "recommendations": ["Re-run subdomain discovery and inspect resolver availability."],
        }
        module_scores["subdomains"] = _module_scorecard(50, MODULE_WEIGHTS["subdomains"])
        _add_finding(findings, "subdomains", "Medium", "Subdomain discovery module failed", 10)

    head_mod = modules.get("headers", {})
    if head_mod.get("ok"):
        head_data = head_mod.get("data", {})
        header_risk = 24

        header_grade = str(head_data.get("grade", "N/A"))
        missing_headers = [str(h) for h in head_data.get("headers_missing", [])]
        missing_lower = {h.lower() for h in missing_headers}
        cookie_risk_count = _safe_int(head_data.get("cookie_risk_count"))
        leaks = [str(x) for x in head_data.get("leaks", [])]

        penalty_map = {
            "referrer-policy": 2,
            "permissions-policy": 2,
            "x-frame-options": 3,
            "content-security-policy": 8,
            "strict-transport-security": 8,
            "x-content-type-options": 4,
        }

        for header_name, points in penalty_map.items():
            if header_name not in missing_lower:
                continue

            header_risk += points
            severity = "Low" if points <= 3 else "Medium"
            _add_finding(
                findings,
                "headers",
                severity,
                f"Missing {header_name}",
                points,
            )

        if "content-security-policy" not in missing_lower:
            header_risk -= 5
        if "strict-transport-security" not in missing_lower and bool(head_data.get("https_enforced")):
            header_risk -= 4

        if cookie_risk_count > 0:
            points = min(12, cookie_risk_count * 3)
            header_risk += points
            _add_finding(findings, "headers", "Medium", "Cookie security weaknesses detected", points)

        if leaks:
            points = min(10, len(leaks) * 2)
            header_risk += points
            _add_finding(findings, "headers", "Low", "Information leakage headers exposed", points)

        no_https_enforced = not bool(head_data.get("https_enforced"))
        if no_https_enforced:
            header_risk += 8
            _add_finding(findings, "headers", "High", "HTTPS is not fully enforced", 8)
            _merge_recommendation(recommendations_ranked, 9, "Force HTTPS redirects and enable strong HSTS policy.")

        module_views["headers"] = {
            "header_grade": header_grade,
            "missing_security_headers": missing_headers,
            "cookie_security": "Weak" if cookie_risk_count > 0 else "Strong",
            "cookie_risk_count": cookie_risk_count,
            "information_leakage": leaks,
            "hsts_status": "Enabled" if "strict-transport-security" not in missing_lower else "Missing",
            "https_enforced": not no_https_enforced,
            "key_issues": [str(i) for i in head_data.get("issues", [])[:6]],
            "recommendations": [str(rec) for rec in head_data.get("recommendations", [])[:6]],
        }
        module_scores["headers"] = _module_scorecard(header_risk, MODULE_WEIGHTS["headers"])
    else:
        module_views["headers"] = {
            "header_grade": "N/A",
            "missing_security_headers": [],
            "cookie_security": "Unknown",
            "cookie_risk_count": 0,
            "information_leakage": [],
            "hsts_status": "Unknown",
            "https_enforced": False,
            "key_issues": ["HTTP header audit module failed"],
            "recommendations": ["Re-run scan and confirm target URL accessibility."],
        }
        module_scores["headers"] = _module_scorecard(52, MODULE_WEIGHTS["headers"])
        _add_finding(findings, "headers", "Medium", "HTTP header audit unavailable", 10)

    ssl_mod = modules.get("ssl", {})
    if ssl_mod.get("ok"):
        ssl_data = ssl_mod.get("data", {})
        ssl_risk = 18

        ssl_valid = bool(ssl_data.get("is_valid"))
        ssl_status = str(ssl_data.get("status", "Unknown"))
        issuer = str(ssl_data.get("issuer", "N/A"))
        expires_in_days = _safe_int(ssl_data.get("days_until_expiry"), -1)

        if not ssl_valid:
            ssl_risk += 20
            expired_ssl = expires_in_days < 0
            _add_finding(findings, "ssl", "High", "SSL certificate is invalid or expired", 20)
            _merge_recommendation(recommendations_ranked, 10, "Reissue SSL certificate and validate chain/trust settings.")
        else:
            if expires_in_days < 30:
                ssl_risk += 8
                _add_finding(findings, "ssl", "Medium", "SSL certificate expires in less than 30 days", 8)
            elif expires_in_days < 90:
                ssl_risk += 4
            elif expires_in_days >= 180:
                ssl_risk -= 4

        module_views["ssl"] = {
            "valid": ssl_valid,
            "status": ssl_status,
            "issuer": issuer,
            "expires_in_days": expires_in_days,
            "cipher_strength": str(ssl_data.get("cipher_strength", "Unknown")),
            "key_issues": [str(ssl_data.get("message", ""))] if ssl_data.get("message") else [],
            "recommendations": [
                "Renew certificate before expiry and monitor certificate lifetime continuously."
            ] if expires_in_days < 45 else [],
        }
        module_scores["ssl"] = _module_scorecard(ssl_risk, MODULE_WEIGHTS["ssl"])
    else:
        module_views["ssl"] = {
            "valid": False,
            "status": "Unknown",
            "issuer": "N/A",
            "expires_in_days": -1,
            "cipher_strength": "Unknown",
            "key_issues": ["SSL certificate check failed"],
            "recommendations": ["Verify target domain and TLS connectivity, then re-run scan."],
        }
        module_scores["ssl"] = _module_scorecard(58, MODULE_WEIGHTS["ssl"])
        _add_finding(findings, "ssl", "Medium", "SSL module failed to complete", 12)

    port_mod = modules.get("ports", {})
    if port_mod.get("ok"):
        port_data = port_mod.get("data", {})
        ports_risk = 18

        open_details = port_data.get("open_port_details", []) if isinstance(port_data.get("open_port_details"), list) else []
        if not open_details:
            open_details = port_data.get("results", []) if isinstance(port_data.get("results"), list) else []

        open_services_table: List[Dict[str, Any]] = []
        risky_notes: List[str] = []
        open_ports = []

        for row in open_details:
            status = str(row.get("status", "closed"))
            if status != "open":
                continue

            port = _safe_int(row.get("port"), -1)
            if port <= 0:
                continue
            open_ports.append(port)

            penalty = RISKY_PORT_PENALTIES.get(port, 0)
            risk_label = "Low"
            note = str(row.get("issue", "") or "")

            if penalty >= 15:
                risk_label = "High"
            elif penalty >= 8:
                risk_label = "Medium"

            if penalty > 0:
                ports_risk += penalty
                risky_ports_count += 1
                title = f"Risky service exposed on port {port}"
                severity = "High" if penalty >= 15 else "Medium"
                _add_finding(findings, "ports", severity, title, penalty)
                if note:
                    risky_notes.append(note)

            open_services_table.append(
                {
                    "port": port,
                    "service": str(row.get("service", "Unknown")),
                    "risk": risk_label,
                    "notes": note or "-",
                }
            )

        if len(open_ports) > 12:
            ports_risk += 10
            _add_finding(findings, "ports", "Medium", "Large number of open ports detected", 10)
        elif len(open_ports) > 6:
            ports_risk += 5

        if open_ports and set(open_ports).issubset({80, 443}):
            ports_risk -= 5

        module_views["ports"] = {
            "open_ports_count": len(open_ports),
            "risky_ports_count": risky_ports_count,
            "services_table": open_services_table[:30],
            "key_issues": list(dict.fromkeys(risky_notes))[:6],
            "recommendations": [
                "Close or restrict unnecessary externally exposed services.",
                "Apply network ACLs/firewall restrictions for high-risk ports.",
            ] if risky_ports_count > 0 else ["Maintain least-exposure network perimeter policy."],
        }
        module_scores["ports"] = _module_scorecard(ports_risk, MODULE_WEIGHTS["ports"])
    else:
        module_views["ports"] = {
            "open_ports_count": 0,
            "risky_ports_count": 0,
            "services_table": [],
            "key_issues": ["Port exposure module failed"],
            "recommendations": ["Re-run scan and verify target reachability."],
        }
        module_scores["ports"] = _module_scorecard(50, MODULE_WEIGHTS["ports"])
        _add_finding(findings, "ports", "Medium", "Port exposure module failed", 10)

    tech_mod = modules.get("tech", {})
    if tech_mod.get("ok"):
        tech_data = tech_mod.get("data", {})
        tech_risk = 16

        tech_list = [str(item) for item in tech_data.get("technologies", [])]
        categorized = tech_data.get("categorized", {}) if isinstance(tech_data.get("categorized"), dict) else {}

        lowered = [item.lower() for item in tech_list]
        outdated_hits = [item for item in lowered if any(token in item for token in ("jquery", "wordpress", "php", "apache", "drupal"))]
        if outdated_hits:
            points = min(16, len(outdated_hits) * 4)
            tech_risk += points
            _add_finding(findings, "tech", "Medium", "Potentially outdated technology stack hints detected", points)
            _merge_recommendation(recommendations_ranked, 5, "Review patch levels and lifecycle status for internet-exposed technologies.")
        else:
            tech_risk -= 2

        module_views["tech"] = {
            "server": categorized.get("Server", []),
            "frameworks": categorized.get("Framework", []),
            "cms": categorized.get("CMS", []),
            "cdn": categorized.get("CDN", []),
            "language": categorized.get("Language", []),
            "all_technologies": tech_list[:20],
        }
        module_scores["tech"] = _module_scorecard(tech_risk, MODULE_WEIGHTS["tech"])
    elif mode != "quick":
        module_views["tech"] = {
            "server": [],
            "frameworks": [],
            "cms": [],
            "cdn": [],
            "language": [],
            "all_technologies": [],
        }
        module_scores["tech"] = _module_scorecard(45, MODULE_WEIGHTS["tech"])

    whois_mod = modules.get("whois", {})
    whois_data = whois_mod.get("data", {}) if whois_mod.get("ok") else {}
    created = _parse_iso_date(whois_data.get("createdDate"))
    expiry = _parse_iso_date(whois_data.get("expiresDate"))
    age_days = _safe_int(whois_data.get("estimatedDomainAge"), -1)
    if age_days < 0 and created:
        age_days = (datetime.utcnow() - created).days

    whois_recs: List[str] = []
    if expiry:
        expiry_days = (expiry - datetime.utcnow()).days
        if expiry_days < 45:
            whois_recs.append("Renew domain registration before upcoming expiry window.")
    else:
        expiry_days = -1

    module_views["whois"] = {
        "registrar": str(whois_data.get("registrarName", "N/A")),
        "domain_age_days": age_days if age_days >= 0 else None,
        "expiry_date": str(whois_data.get("expiresDate", "N/A")),
        "registrant_country": str(whois_data.get("registrant", {}).get("country", "N/A")) if isinstance(whois_data.get("registrant"), dict) else "N/A",
        "recommendations": whois_recs,
    }

    # Critical combinations and realism tuning.
    combo_penalty = 0
    if risky_ports_count >= 2 and exposed_admin_count > 0 and expired_ssl:
        combo_penalty += 15
        _add_finding(
            findings,
            "combined",
            "Critical",
            "Risky ports + exposed admin + expired SSL combined exposure",
            15,
        )

    if takeover_candidates > 0:
        combo_penalty += 12

    if no_https_enforced and login_target:
        combo_penalty += 20
        _add_finding(
            findings,
            "headers",
            "Critical",
            "No HTTPS enforcement on a likely authentication target",
            20,
        )

    weighted_scores = [
        (name, scorecard)
        for name, scorecard in module_scores.items()
        if scorecard.get("weight", 0) > 0
    ]

    weight_total = sum(item[1]["weight"] for item in weighted_scores)
    if weight_total <= 0:
        aggregate_risk_score = 50
    else:
        aggregate_risk_score = int(
            round(
                sum(item[1]["risk_score"] * item[1]["weight"] for item in weighted_scores) / weight_total
            )
        )

    aggregate_risk_score = max(0, min(100, aggregate_risk_score + combo_penalty))

    findings_sorted = sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity", "Low")), 1),
            -_safe_int(item.get("points"), 0),
            str(item.get("title", "")),
        ),
    )

    top_findings = findings_sorted[:5]

    dedup_recs: List[str] = []
    for _, rec in sorted(recommendations_ranked, key=lambda x: x[0], reverse=True):
        if rec not in dedup_recs:
            dedup_recs.append(rec)
        if len(dedup_recs) >= 8:
            break

    if not dedup_recs:
        dedup_recs = [
            "Maintain continuous attack surface monitoring and patch management hygiene.",
            "Review external exposure monthly and after major infrastructure changes.",
        ]

    grade, grade_label = _grade_from_risk_score(aggregate_risk_score)
    risk_level = _risk_level_from_score(aggregate_risk_score)

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    for item in top_findings:
        sev = str(item.get("severity", "Low"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    highlights = {
        "subdomains_found": subdomains_found,
        "open_ports": sorted(set(open_ports)),
        "dns_grade": dns_grade,
        "header_grade": header_grade,
        "ssl_status": ssl_status,
        "tech": tech_list[:8],
    }

    return {
        "overall_score": aggregate_risk_score,
        "risk_score": aggregate_risk_score,
        "grade": grade,
        "grade_label": _score_band_label(aggregate_risk_score),
        "risk_level": risk_level,
        "summary": _executive_summary(target, risk_level),
        "highlights": highlights,
        "issues": [str(item.get("title", "")) for item in top_findings],
        "findings": top_findings,
        "recommendations": dedup_recs,
        "risk_distribution": {
            "critical": severity_counts.get("Critical", 0),
            "high": severity_counts.get("High", 0),
            "medium": severity_counts.get("Medium", 0),
            "low": severity_counts.get("Low", 0),
        },
        "module_scores": module_scores,
        "module_views": module_views,
    }


def unified_recon_scan(target_input: str, scan_mode: str = "standard") -> Dict[str, Any]:
    target = str(target_input or "").strip()
    if not target:
        return {"error": "Target is required."}

    mode = str(scan_mode or "standard").strip().lower()
    if mode not in ("quick", "standard", "deep"):
        mode = "standard"

    cache_key = f"{target.lower()}::{mode}"
    cached = _cache_get(cache_key)
    if cached:
        cached["cached"] = True
        return cached

    started = time.perf_counter()

    is_ip = _is_ip_target(target)
    domain = None if is_ip else normalize_domain_input(target)
    web_target = _normalize_web_target(target)

    tasks: Dict[str, Any] = {
        "headers": lambda: http_header_audit(web_target),
        "ports": lambda: advanced_network_scan(target, "quick" if mode in ("quick", "standard") else "full", ""),
    }

    if mode == "quick":
        tasks["dns"] = (lambda: dns_lookup(domain)) if domain else (lambda: {"error": "DNS summary requires a domain target."})
        tasks["ssl"] = (lambda: check_ssl_certificate(domain)) if domain else (lambda: {"error": "SSL scan requires a domain target."})
    else:
        tasks["dns"] = (lambda: dns_lookup_pro(domain)) if domain else (lambda: {"error": "DNS audit requires a domain target."})
        tasks["ssl"] = (lambda: check_ssl_certificate(domain)) if domain else (lambda: {"error": "SSL scan requires a domain target."})
        tasks["subdomains"] = (
            (lambda: subdomain_finder_pro(domain, "deep" if mode == "deep" else "standard"))
            if domain
            else (lambda: {"error": "Subdomain discovery requires a domain target."})
        )
        tasks["tech"] = lambda: analyze_tech_stack(web_target)
        tasks["whois"] = (lambda: get_whois_info(domain)) if domain else (lambda: {"error": "WHOIS requires a domain target."})

    modules: Dict[str, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(tasks)))) as executor:
        future_map = {executor.submit(_run_module, name, fn): name for name, fn in tasks.items()}
        for future in as_completed(future_map):
            module_name = future_map[future]
            try:
                name, result = future.result()
                modules[name] = result
            except Exception as exc:
                modules[module_name] = _module_result(
                    False,
                    0,
                    data={"traceback": traceback.format_exc(limit=4)},
                    error=str(exc),
                )

    for key in tasks:
        modules.setdefault(key, _module_result(False, 0, data={}, error="Module did not return results."))

    risk = _compute_unified_risk(target, mode, modules)

    response = {
        "target": target,
        "normalized_domain": domain,
        "scan_mode": mode,
        "overall_score": risk["overall_score"],
        "risk_score": risk["risk_score"],
        "grade": risk["grade"],
        "grade_label": risk["grade_label"],
        "risk_level": risk["risk_level"],
        "summary": risk["summary"],
        "highlights": risk["highlights"],
        "issues": risk["issues"],
        "findings": risk["findings"],
        "recommendations": risk["recommendations"],
        "risk_distribution": risk["risk_distribution"],
        "module_scores": risk["module_scores"],
        "module_views": risk["module_views"],
        "modules": modules,
        "scan_duration_ms": int((time.perf_counter() - started) * 1000),
        "cached": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    _cache_set(cache_key, response)
    return response
