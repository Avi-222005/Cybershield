import ipaddress
import re
from email import message_from_string
from email.utils import parseaddr, parsedate_to_datetime
from typing import Dict, List, Optional, Tuple

from phishing_detector import analyze_url_for_phishing
from .threat_intel import check_ip_reputation


AUTH_VALUE_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)\b", re.IGNORECASE)
SPF_DOMAIN_RE = re.compile(r"\b(?:smtp\.mailfrom|envelope-from|mailfrom)\s*=\s*([^\s;]+)", re.IGNORECASE)
DKIM_DOMAIN_RE = re.compile(r"\bheader\.d\s*=\s*([^\s;]+)", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SUBJECT_PHISHING_KEYWORDS = ["urgent", "verify", "login", "password", "bank", "account", "suspend", "security", "alert"]
HIGH_RISK_TLDS = (
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".work",
    ".loan",
    ".win",
    ".bid",
)


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _extract_email_value(header_value: str) -> str:
    if not header_value:
        return ""
    _, addr = parseaddr(header_value)
    return (addr or header_value).strip().strip("<>")


def _extract_domain(email_value: str) -> str:
    if "@" not in email_value:
        return ""
    return email_value.split("@", 1)[1].lower().strip()


def _normalize_auth_value(value: str) -> str:
    val = (value or "").lower()
    if val in {"pass", "fail", "softfail", "none", "neutral", "temperror", "permerror"}:
        return val
    return "missing"


def _extract_authentication(auth_headers: List[str]) -> Dict[str, str]:
    authentication = {"spf": "missing", "dkim": "missing", "dmarc": "missing", "spf_domain": "", "dkim_domain": ""}
    merged = " ".join(auth_headers or [])

    for key, value in AUTH_VALUE_RE.findall(merged):
        authentication[key.lower()] = _normalize_auth_value(value)

    spf_domain_match = SPF_DOMAIN_RE.search(merged)
    if spf_domain_match:
        authentication["spf_domain"] = spf_domain_match.group(1).lower().strip().strip(">")

    dkim_domain_match = DKIM_DOMAIN_RE.search(merged)
    if dkim_domain_match:
        authentication["dkim_domain"] = dkim_domain_match.group(1).lower().strip().strip(">")

    return authentication


def _extract_received_ips(received_headers: List[str]) -> List[str]:
    route: List[str] = []
    seen = set()
    for received in received_headers or []:
        for match in IPV4_RE.findall(received):
            if _is_valid_ipv4(match) and match not in seen:
                seen.add(match)
                route.append(match)
    return route


def _extract_received_datetimes(received_headers: List[str]) -> List:
    timestamps = []
    for received in received_headers or []:
        if ";" not in received:
            continue
        date_part = received.rsplit(";", 1)[-1].strip()
        try:
            dt = parsedate_to_datetime(date_part)
            if dt:
                timestamps.append(dt)
        except Exception:
            continue
    return timestamps


def _analyze_delay(received_headers: List[str]) -> Dict:
    timestamps = _extract_received_datetimes(received_headers)
    if len(timestamps) < 2:
        return {
            "hop_delays_seconds": [],
            "max_delay_seconds": 0,
            "suspicious": False,
            "notes": "Insufficient timestamped Received headers for delay analysis.",
        }

    delays: List[int] = []
    for i in range(len(timestamps) - 1):
        delta = abs(int((timestamps[i] - timestamps[i + 1]).total_seconds()))
        delays.append(delta)

    max_delay = max(delays) if delays else 0
    suspicious = max_delay > 1800
    return {
        "hop_delays_seconds": delays,
        "max_delay_seconds": max_delay,
        "suspicious": suspicious,
        "notes": "Unusual hop delay detected." if suspicious else "No unusual relay delay detected.",
    }


def _is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
        return not (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_reserved
            or parsed.is_link_local
            or parsed.is_multicast
        )
    except ValueError:
        return False


def _map_ip_status(vt_status: str, vendor_data: Dict) -> str:
    status = (vt_status or "").lower()
    if "malicious" in status or vendor_data.get("malicious_count", 0) > 0:
        return "malicious"
    if "suspicious" in status or vendor_data.get("suspicious_count", 0) > 0:
        return "suspicious"
    if status == "safe":
        return "clean"
    return "unknown"


def _analyze_ip_route(ip_route: List[str], max_lookup: int = 5) -> Tuple[List[Dict], List[str]]:
    analysis: List[Dict] = []
    issues: List[str] = []

    for ip in ip_route[:max_lookup]:
        if not _is_public_ip(ip):
            analysis.append({"ip": ip, "status": "private/internal"})
            continue

        vt_status, _, vendor_data = check_ip_reputation(ip)
        mapped = _map_ip_status(vt_status, vendor_data or {})
        entry = {
            "ip": ip,
            "status": mapped,
            "malicious_count": (vendor_data or {}).get("malicious_count", 0),
            "suspicious_count": (vendor_data or {}).get("suspicious_count", 0),
        }
        analysis.append(entry)

        if mapped == "malicious":
            issues.append(f"Malicious IP detected in route: {ip}.")
        elif mapped == "suspicious":
            issues.append(f"Suspicious IP detected in route: {ip}.")

    return analysis, issues


def _detect_spoofing(from_domain: str, return_path_domain: str, reply_to_domain: str) -> List[str]:
    checks: List[str] = []
    if from_domain and return_path_domain and from_domain != return_path_domain:
        checks.append("Return-Path mismatch -> possible spoofing.")
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        checks.append("Reply-To mismatch -> phishing attempt.")
    return checks


def _subject_phishing_indicators(subject: str) -> List[str]:
    subject_lower = (subject or "").lower()
    found = [kw for kw in SUBJECT_PHISHING_KEYWORDS if kw in subject_lower]
    return [f'Suspicious keyword in subject: "{kw}"' for kw in found]


def _sender_domain_indicators(sender_domain: str) -> List[str]:
    indicators: List[str] = []
    if not sender_domain:
        return indicators

    if sender_domain.startswith("xn--"):
        indicators.append("Sender domain uses punycode encoding.")
    if sender_domain.endswith(HIGH_RISK_TLDS):
        indicators.append("Sender domain uses a high-risk TLD.")
    if sender_domain.count("-") >= 3:
        indicators.append("Sender domain contains excessive hyphens.")
    if re.search(r"\d{4,}", sender_domain):
        indicators.append("Sender domain contains unusual numeric pattern.")
    return indicators


def _analyze_sender_domain(sender_domain: str) -> Tuple[str, bool]:
    if not sender_domain:
        return "Sender domain unavailable for analysis.", False

    try:
        result = analyze_url_for_phishing(f"https://{sender_domain}", "Unknown", "")
    except Exception as exc:
        return f"Sender domain analysis failed: {str(exc)}", False

    verdict = str(result.get("verdict", "UNKNOWN")).upper()
    score = int(result.get("final_score", 0))
    if verdict in {"SUSPICIOUS", "MALICIOUS"} or score >= 60:
        return f"Sender domain flagged as suspicious ({verdict}, score {score}).", True
    return f"Sender domain appears lower risk ({verdict}, score {score}).", False


def _risk_level_from_score(score: int) -> str:
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _compute_risk(authentication: Dict, spoofing_checks: List[str], ip_analysis: List[Dict], phishing_indicators: List[str], domain_flagged: bool, delay_suspicious: bool, has_auth_results: bool) -> int:
    score = 0

    if not has_auth_results:
        score += 12

    if authentication.get("spf") in {"fail", "softfail", "permerror", "temperror"}:
        score += 16
    if authentication.get("dkim") in {"fail", "permerror", "temperror"}:
        score += 16
    if authentication.get("dmarc") in {"fail", "permerror", "temperror"}:
        score += 20

    score += min(24, len(spoofing_checks) * 12)
    score += min(18, len(phishing_indicators) * 6)

    malicious_ips = sum(1 for entry in ip_analysis if entry.get("status") == "malicious")
    suspicious_ips = sum(1 for entry in ip_analysis if entry.get("status") == "suspicious")
    score += min(30, malicious_ips * 20 + suspicious_ips * 8)

    if domain_flagged:
        score += 12
    if delay_suspicious:
        score += 8

    return min(100, score)


def _parse_email_header(raw_header: str) -> Tuple[Optional[object], Optional[str]]:
    header_text = (raw_header or "").strip()
    if not header_text:
        return None, "Raw email header is required."
    if ":" not in header_text:
        return None, "Invalid header format. Paste complete raw email headers."
    try:
        return message_from_string(header_text), None
    except Exception as exc:
        return None, f"Could not parse email headers: {str(exc)}"


def analyze_email_header(raw_header: str) -> Dict:
    parsed, error = _parse_email_header(raw_header)
    if error:
        return {"error": error}

    from_value = _extract_email_value(parsed.get("From", ""))
    to_value = _extract_email_value(parsed.get("To", ""))
    return_path_value = _extract_email_value(parsed.get("Return-Path", ""))
    subject_value = (parsed.get("Subject", "") or "").strip()
    date_value = (parsed.get("Date", "") or "").strip()
    message_id_value = (parsed.get("Message-ID", "") or "").strip()

    auth_headers = parsed.get_all("Authentication-Results", [])
    authentication = _extract_authentication(auth_headers)
    ip_route = _extract_received_ips(parsed.get_all("Received", []))

    issues = []
    if not auth_headers:
        issues.append("Authentication-Results header missing -> unable to verify SPF/DKIM/DMARC.")
    if authentication["spf"] == "fail":
        issues.append("SPF failed -> possible spoofing risk.")
    if authentication["dkim"] == "fail":
        issues.append("DKIM failed -> message integrity issue.")
    if authentication["dmarc"] == "fail":
        issues.append("DMARC failed -> policy violation and possible spoofing.")
    from_domain = _extract_domain(from_value)
    return_path_domain = _extract_domain(return_path_value)
    if from_domain and return_path_domain and from_domain != return_path_domain:
        issues.append("From and Return-Path domains do not match -> possible sender spoofing.")

    return {
        "basic_info": {
            "from": from_value,
            "to": to_value,
            "subject": subject_value,
            "date": date_value,
            "return_path": return_path_value,
            "message_id": message_id_value,
        },
        "authentication": {
            "spf": authentication["spf"],
            "dkim": authentication["dkim"],
            "dmarc": authentication["dmarc"],
        },
        "ip_route": ip_route,
        "issues": issues,
    }


def analyze_email_header_advanced(raw_header: str) -> Dict:
    parsed, error = _parse_email_header(raw_header)
    if error:
        return {"error": error}

    received_headers = parsed.get_all("Received", [])
    auth_headers = parsed.get_all("Authentication-Results", [])

    basic_info = {
        "from": _extract_email_value(parsed.get("From", "")),
        "to": _extract_email_value(parsed.get("To", "")),
        "subject": (parsed.get("Subject", "") or "").strip(),
        "date": (parsed.get("Date", "") or "").strip(),
        "return_path": _extract_email_value(parsed.get("Return-Path", "")),
        "reply_to": _extract_email_value(parsed.get("Reply-To", "")),
        "message_id": (parsed.get("Message-ID", "") or "").strip(),
    }

    from_domain = _extract_domain(basic_info["from"])
    return_path_domain = _extract_domain(basic_info["return_path"])
    reply_to_domain = _extract_domain(basic_info["reply_to"])

    authentication = _extract_authentication(auth_headers)
    ip_route = _extract_received_ips(received_headers)
    spoofing_checks = _detect_spoofing(from_domain, return_path_domain, reply_to_domain)
    ip_analysis, ip_issues = _analyze_ip_route(ip_route)

    phishing_indicators = []
    phishing_indicators.extend(_subject_phishing_indicators(basic_info["subject"]))
    phishing_indicators.extend(_sender_domain_indicators(from_domain))

    domain_analysis, domain_flagged = _analyze_sender_domain(from_domain)
    delay_analysis = _analyze_delay(received_headers)

    issues = []
    if not auth_headers:
        issues.append("Authentication-Results header missing.")
    if authentication["spf"] in {"fail", "softfail", "permerror", "temperror"}:
        issues.append("SPF validation failed or is unreliable.")
    if authentication["dkim"] in {"fail", "permerror", "temperror"}:
        issues.append("DKIM validation failed.")
    if authentication["dmarc"] in {"fail", "permerror", "temperror"}:
        issues.append("DMARC validation failed.")
    issues.extend(spoofing_checks)
    issues.extend(ip_issues)
    issues.extend(phishing_indicators)
    if domain_flagged:
        issues.append("Sender domain flagged as suspicious.")
    if delay_analysis["suspicious"]:
        issues.append("Unusual relay delay observed in Received headers.")

    risk_score = _compute_risk(
        authentication=authentication,
        spoofing_checks=spoofing_checks,
        ip_analysis=ip_analysis,
        phishing_indicators=phishing_indicators,
        domain_flagged=domain_flagged,
        delay_suspicious=delay_analysis["suspicious"],
        has_auth_results=bool(auth_headers),
    )

    return {
        "basic_info": basic_info,
        "authentication": authentication,
        "spoofing_checks": spoofing_checks,
        "ip_route": ip_route,
        "ip_analysis": ip_analysis,
        "phishing_indicators": phishing_indicators,
        "domain_analysis": domain_analysis,
        "time_delay_analysis": delay_analysis,
        "issues": issues,
        "risk_level": _risk_level_from_score(risk_score),
        "risk_score": risk_score,
    }
