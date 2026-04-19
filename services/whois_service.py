from datetime import datetime, timezone
import ipaddress
import re
import socket

import requests

from .domain_services import WHOISXML_API_KEY, get_domain_info, normalize_domain_input

try:
    import whois as python_whois
except Exception:
    python_whois = None


CONTACT_FIELDS = [
    "name",
    "organization",
    "email",
    "phone",
    "country",
    "city",
    "state",
    "postalCode",
    "address",
]

PRIVACY_KEYWORDS = (
    "redacted",
    "privacy",
    "whoisguard",
    "proxy",
    "contact privacy",
    "gdpr masked",
    "private registration",
)

WHOIS_SERVER_BY_TLD = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "io": "whois.nic.io",
}


def _is_empty(value):
    if value is None:
        return True
    if isinstance(value, str):
        stripped = value.strip()
        return stripped == "" or stripped.upper() in ("N/A", "NONE", "NULL")
    if isinstance(value, (list, tuple, set)):
        return len(value) == 0 or all(_is_empty(v) for v in value)
    if isinstance(value, dict):
        return len(value) == 0 or all(_is_empty(v) for v in value.values())
    return False


def _safe_pick(value, default="N/A"):
    if _is_empty(value):
        return default
    if isinstance(value, list):
        for item in value:
            if not _is_empty(item):
                return item
        return default
    return value


def _unique_strings(values):
    unique = []
    seen = set()
    for value in values or []:
        if _is_empty(value):
            continue
        text = str(value).strip()
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(text)
    return unique


def _merge_status(primary, secondary):
    chunks = []
    for src in (primary, secondary):
        if _is_empty(src):
            continue
        if isinstance(src, (list, tuple, set)):
            chunks.extend([str(item) for item in src if not _is_empty(item)])
        else:
            chunks.extend([part.strip() for part in str(src).split("|") if part.strip()])
    merged = _unique_strings(chunks)
    return " | ".join(merged) if merged else "N/A"


def _domain_extension(domain):
    return "." + domain.split(".")[-1] if "." in domain else ""


def _to_iso_string(value):
    if _is_empty(value):
        return "N/A"

    if isinstance(value, (list, tuple)):
        for item in value:
            parsed = _to_iso_string(item)
            if parsed != "N/A":
                return parsed
        return "N/A"

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip()
        dt = None

        iso_candidate = text.replace("Z", "+00:00") if text.endswith("Z") else text
        try:
            dt = datetime.fromisoformat(iso_candidate)
        except Exception:
            dt = None

        if dt is None:
            known_formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
                "%d-%b-%Y",
                "%Y.%m.%d",
                "%Y/%m/%d",
                "%Y%m%d",
                "%d/%m/%Y",
            ]
            for fmt in known_formats:
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except Exception:
                    continue

        if dt is None:
            return text
    else:
        return str(value)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _compute_domain_age(created_date):
    if _is_empty(created_date) or str(created_date) == "N/A":
        return "N/A"

    try:
        created = datetime.strptime(str(created_date), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return "N/A"

    delta = datetime.now(timezone.utc) - created
    return max(delta.days, 0)


def _default_contact():
    return {
        "name": "N/A",
        "organization": "N/A",
        "email": "N/A",
        "phone": "N/A",
        "country": "N/A",
        "city": "N/A",
        "state": "N/A",
        "postalCode": "N/A",
        "address": "N/A",
    }


def _merge_contact(primary, secondary):
    primary = primary if isinstance(primary, dict) else {}
    secondary = secondary if isinstance(secondary, dict) else {}
    merged = _default_contact()

    for field in CONTACT_FIELDS:
        primary_value = primary.get(field)
        secondary_value = secondary.get(field)
        if not _is_empty(primary_value):
            merged[field] = str(primary_value)
        elif not _is_empty(secondary_value):
            merged[field] = str(secondary_value)

    return merged


def _contact_has_meaningful_data(contact):
    if not isinstance(contact, dict):
        return False
    for field in CONTACT_FIELDS:
        if field not in contact:
            continue
        value = contact.get(field)
        if not _is_empty(value):
            return True
    return False


def _detect_privacy_protection(registrant, technical, administrative, contact_email, status):
    signals = []
    for item in (registrant, technical, administrative):
        if isinstance(item, dict):
            signals.extend([str(v) for v in item.values() if not _is_empty(v)])

    if not _is_empty(contact_email):
        signals.append(str(contact_email))
    if not _is_empty(status):
        signals.append(str(status))

    signal_text = " ".join(signals).lower()
    if any(keyword in signal_text for keyword in PRIVACY_KEYWORDS):
        return "Likely Protected"

    if _contact_has_meaningful_data(registrant) or _contact_has_meaningful_data(technical) or _contact_has_meaningful_data(administrative):
        return "No Privacy Detected"

    return "Unknown"


def _normalize_name_servers(name_servers):
    normalized = []
    for ns in name_servers or []:
        if _is_empty(ns):
            continue
        text = str(ns).strip().lower().rstrip(".")
        if not text:
            continue
        if text not in normalized:
            normalized.append(text)
    return normalized


def _safe_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except Exception:
        return None


def _resolve_host_ips(host):
    if _is_empty(host):
        return []
    try:
        addrinfo = socket.getaddrinfo(str(host), None)
    except Exception:
        return []

    ips = []
    for info in addrinfo:
        if not info or len(info) < 5:
            continue
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_value = _safe_ip(sockaddr[0])
        if ip_value:
            ips.append(ip_value)

    return _unique_strings(ips)


def _resolve_nameserver_ips(name_servers):
    details = {}
    for ns in (name_servers or [])[:20]:
        details[ns] = _resolve_host_ips(ns)
    return details


def _normalize_result(domain, source_data, source_name):
    source_data = source_data if isinstance(source_data, dict) else {}

    created_date = _to_iso_string(source_data.get("createdDate", "N/A"))
    updated_date = _to_iso_string(source_data.get("updatedDate", "N/A"))
    expires_date = _to_iso_string(source_data.get("expiresDate", "N/A"))
    status = _merge_status(source_data.get("status", "N/A"), None)

    registrant = _merge_contact(source_data.get("registrant", {}), {})
    technical = _merge_contact(source_data.get("technicalContact", {}), {})
    administrative = _merge_contact(source_data.get("administrativeContact", {}), {})

    contact_email = source_data.get("contactEmail", "N/A")
    if _is_empty(contact_email):
        contact_email = _safe_pick([
            registrant.get("email"),
            technical.get("email"),
            administrative.get("email"),
        ])

    normalized = {
        "domainName": str(source_data.get("domainName") or domain),
        "domainNameExt": str(source_data.get("domainNameExt") or _domain_extension(domain)),
        "createdDate": created_date,
        "updatedDate": updated_date,
        "expiresDate": expires_date,
        "registrarName": str(source_data.get("registrarName") or "N/A"),
        "registrarIANAID": str(source_data.get("registrarIANAID") or "N/A"),
        "registrarURL": str(source_data.get("registrarURL") or "N/A"),
        "whoisServer": str(source_data.get("whoisServer") or "N/A"),
        "status": status,
        "dnssec": str(source_data.get("dnssec") or "N/A"),
        "nameServers": _normalize_name_servers(source_data.get("nameServers", [])),
        "nameServerIPs": source_data.get("nameServerIPs", {}) if isinstance(source_data.get("nameServerIPs", {}), dict) else {},
        "registrant": registrant,
        "technicalContact": technical,
        "administrativeContact": administrative,
        "estimatedDomainAge": source_data.get("estimatedDomainAge", _compute_domain_age(created_date)),
        "ips": _unique_strings(source_data.get("ips", [])),
        "domainAvailability": str(source_data.get("domainAvailability") or "N/A"),
        "contactEmail": str(contact_email or "N/A"),
        "audit": source_data.get("audit", {"createdDate": "N/A", "updatedDate": "N/A"}),
        "privacyProtection": str(source_data.get("privacyProtection") or "Unknown"),
        "lookupSources": _unique_strings([source_name] + list(source_data.get("lookupSources", []) or [])),
    }

    return normalized


def _merge_whois_results(primary, secondary):
    if not primary:
        return secondary
    if not secondary:
        return primary

    merged = dict(primary)
    scalar_fields = [
        "domainName",
        "domainNameExt",
        "createdDate",
        "updatedDate",
        "expiresDate",
        "registrarName",
        "registrarIANAID",
        "registrarURL",
        "whoisServer",
        "dnssec",
        "domainAvailability",
        "contactEmail",
    ]

    for field in scalar_fields:
        primary_value = primary.get(field)
        secondary_value = secondary.get(field)
        merged[field] = primary_value if not _is_empty(primary_value) else secondary_value

    merged["status"] = _merge_status(primary.get("status"), secondary.get("status"))
    merged["nameServers"] = _normalize_name_servers((primary.get("nameServers") or []) + (secondary.get("nameServers") or []))
    merged["ips"] = _unique_strings((primary.get("ips") or []) + (secondary.get("ips") or []))
    merged["lookupSources"] = _unique_strings((primary.get("lookupSources") or []) + (secondary.get("lookupSources") or []))

    merged["registrant"] = _merge_contact(primary.get("registrant", {}), secondary.get("registrant", {}))
    merged["technicalContact"] = _merge_contact(primary.get("technicalContact", {}), secondary.get("technicalContact", {}))
    merged["administrativeContact"] = _merge_contact(primary.get("administrativeContact", {}), secondary.get("administrativeContact", {}))

    primary_ns_ips = primary.get("nameServerIPs", {}) if isinstance(primary.get("nameServerIPs", {}), dict) else {}
    secondary_ns_ips = secondary.get("nameServerIPs", {}) if isinstance(secondary.get("nameServerIPs", {}), dict) else {}
    merged_ns_ips = {}
    for ns in _normalize_name_servers(list(primary_ns_ips.keys()) + list(secondary_ns_ips.keys()) + merged["nameServers"]):
        merged_ns_ips[ns] = _unique_strings((primary_ns_ips.get(ns) or []) + (secondary_ns_ips.get(ns) or []))
    merged["nameServerIPs"] = merged_ns_ips

    merged["estimatedDomainAge"] = _compute_domain_age(_to_iso_string(merged.get("createdDate", "N/A")))
    merged["privacyProtection"] = _detect_privacy_protection(
        merged.get("registrant", {}),
        merged.get("technicalContact", {}),
        merged.get("administrativeContact", {}),
        merged.get("contactEmail", "N/A"),
        merged.get("status", "N/A"),
    )
    merged["audit"] = {
        "createdDate": _to_iso_string(merged.get("createdDate", "N/A")),
        "updatedDate": _to_iso_string(merged.get("updatedDate", "N/A")),
    }

    return merged


def _safe_attr_or_key(data, *keys):
    for key in keys:
        value = None
        try:
            value = getattr(data, key)
        except Exception:
            value = None

        if _is_empty(value):
            try:
                value = data.get(key)
            except Exception:
                value = None

        if not _is_empty(value):
            return value
    return None


def _python_whois_lookup(domain):
    if python_whois is None:
        return None, "python-whois library not installed"

    try:
        data = python_whois.whois(domain)
    except Exception as exc:
        return None, f"WHOIS query failed: {str(exc)}"

    if not data:
        return None, "No WHOIS data found for this domain"

    if _is_empty(_safe_attr_or_key(data, "domain_name")) and _is_empty(_safe_attr_or_key(data, "registrar")):
        return None, "No WHOIS data found for this domain"

    name_servers = _normalize_name_servers(_safe_attr_or_key(data, "name_servers") or [])
    status = _safe_attr_or_key(data, "status") or "N/A"
    emails = _safe_attr_or_key(data, "emails")
    registrant_email = _safe_pick(emails, "N/A")

    registrant_contact = _merge_contact(
        {
            "name": _safe_attr_or_key(data, "name", "registrant_name"),
            "organization": _safe_attr_or_key(data, "org", "organization", "registrant_organization"),
            "email": registrant_email,
            "phone": _safe_attr_or_key(data, "phone", "registrant_phone"),
            "country": _safe_attr_or_key(data, "country", "registrant_country"),
            "city": _safe_attr_or_key(data, "city", "registrant_city"),
            "state": _safe_attr_or_key(data, "state", "registrant_state"),
            "postalCode": _safe_attr_or_key(data, "zipcode", "registrant_postal_code"),
            "address": _safe_attr_or_key(data, "address", "registrant_address"),
        },
        {},
    )

    technical_contact = _merge_contact(
        {
            "name": _safe_attr_or_key(data, "tech_name"),
            "organization": _safe_attr_or_key(data, "tech_organization", "tech_org"),
            "email": _safe_attr_or_key(data, "tech_email"),
            "phone": _safe_attr_or_key(data, "tech_phone"),
            "country": _safe_attr_or_key(data, "tech_country"),
            "city": _safe_attr_or_key(data, "tech_city"),
            "state": _safe_attr_or_key(data, "tech_state"),
            "postalCode": _safe_attr_or_key(data, "tech_postal_code", "tech_zipcode"),
            "address": _safe_attr_or_key(data, "tech_address"),
        },
        {},
    )

    administrative_contact = _merge_contact(
        {
            "name": _safe_attr_or_key(data, "admin_name"),
            "organization": _safe_attr_or_key(data, "admin_organization", "admin_org"),
            "email": _safe_attr_or_key(data, "admin_email"),
            "phone": _safe_attr_or_key(data, "admin_phone"),
            "country": _safe_attr_or_key(data, "admin_country"),
            "city": _safe_attr_or_key(data, "admin_city"),
            "state": _safe_attr_or_key(data, "admin_state"),
            "postalCode": _safe_attr_or_key(data, "admin_postal_code", "admin_zipcode"),
            "address": _safe_attr_or_key(data, "admin_address"),
        },
        {},
    )

    mapped = {
        "domainName": domain,
        "domainNameExt": _domain_extension(domain),
        "createdDate": _to_iso_string(_safe_attr_or_key(data, "creation_date")),
        "updatedDate": _to_iso_string(_safe_attr_or_key(data, "updated_date")),
        "expiresDate": _to_iso_string(_safe_attr_or_key(data, "expiration_date", "expiry_date")),
        "registrarName": _safe_pick(_safe_attr_or_key(data, "registrar"), "N/A"),
        "registrarIANAID": _safe_pick(_safe_attr_or_key(data, "registrar_iana_id"), "N/A"),
        "registrarURL": _safe_pick(_safe_attr_or_key(data, "registrar_url"), "N/A"),
        "whoisServer": _safe_pick(_safe_attr_or_key(data, "whois_server"), "N/A"),
        "status": status,
        "dnssec": _safe_pick(_safe_attr_or_key(data, "dnssec"), "N/A"),
        "nameServers": name_servers,
        "registrant": registrant_contact,
        "technicalContact": technical_contact,
        "administrativeContact": administrative_contact,
        "ips": _resolve_host_ips(domain),
        "domainAvailability": "N/A",
        "contactEmail": registrant_email,
        "audit": {"createdDate": "N/A", "updatedDate": "N/A"},
    }

    result = _normalize_result(domain, mapped, "python_whois")
    return result, None


def _iter_entities(entities):
    for entity in entities or []:
        if not isinstance(entity, dict):
            continue
        yield entity
        yield from _iter_entities(entity.get("entities", []))


def _parse_rdap_vcard(vcard):
    contact = _default_contact()
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return contact

    for entry in vcard[1]:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        key = str(entry[0]).lower()
        value = entry[3]

        if key == "fn" and not _is_empty(value):
            contact["name"] = str(value)
        elif key == "org" and not _is_empty(value):
            contact["organization"] = value[0] if isinstance(value, list) and value else str(value)
        elif key == "email" and not _is_empty(value):
            contact["email"] = str(value)
        elif key == "tel" and not _is_empty(value):
            contact["phone"] = str(value)
        elif key == "adr" and isinstance(value, list):
            if len(value) > 2 and value[2]:
                contact["address"] = str(value[2])
            if len(value) > 3 and value[3]:
                contact["city"] = str(value[3])
            if len(value) > 4 and value[4]:
                contact["state"] = str(value[4])
            if len(value) > 5 and value[5]:
                contact["postalCode"] = str(value[5])
            if len(value) > 6 and value[6]:
                contact["country"] = str(value[6])
        elif key == "label" and not _is_empty(value):
            contact["address"] = str(value)

    return contact


def _extract_iana_id(entity):
    if not isinstance(entity, dict):
        return "N/A"

    for public_id in entity.get("publicIds", []) or []:
        if not isinstance(public_id, dict):
            continue
        id_type = str(public_id.get("type", "")).lower()
        identifier = public_id.get("identifier")
        if "iana" in id_type and not _is_empty(identifier):
            return str(identifier)

    handle = entity.get("handle")
    return str(handle) if not _is_empty(handle) else "N/A"


def _rdap_lookup(domain):
    rdap_url = f"https://rdap.org/domain/{domain}"
    response = requests.get(
        rdap_url,
        timeout=15,
        headers={"Accept": "application/rdap+json, application/json"},
    )
    if response.status_code != 200:
        return None, f"RDAP lookup failed ({response.status_code})"

    data = response.json()

    event_map = {}
    for event in data.get("events", []) or []:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).strip().lower()
        event_date = event.get("eventDate")
        if action and event_date and action not in event_map:
            event_map[action] = event_date

    created_date = event_map.get("registration") or event_map.get("created")
    updated_date = (
        event_map.get("last changed")
        or event_map.get("last update of rdap database")
        or event_map.get("last update of rdap database content")
    )
    expires_date = event_map.get("expiration") or event_map.get("expiry")

    nameservers = []
    for ns in data.get("nameservers", []) or []:
        if not isinstance(ns, dict):
            continue
        if ns.get("ldhName"):
            nameservers.append(ns.get("ldhName"))

    registrant = _default_contact()
    technical = _default_contact()
    administrative = _default_contact()
    registrar_name = "N/A"
    registrar_iana = "N/A"

    for entity in _iter_entities(data.get("entities", [])):
        roles = [str(role).lower() for role in (entity.get("roles") or [])]
        contact = _parse_rdap_vcard(entity.get("vcardArray"))

        if "registrant" in roles:
            registrant = _merge_contact(registrant, contact)
        if "technical" in roles:
            technical = _merge_contact(technical, contact)
        if "administrative" in roles:
            administrative = _merge_contact(administrative, contact)
        if "registrar" in roles:
            registrar_name = contact.get("organization") if not _is_empty(contact.get("organization")) else contact.get("name", "N/A")
            registrar_iana = _extract_iana_id(entity)

    status = data.get("status", "N/A")
    secure_dns = data.get("secureDNS") if isinstance(data.get("secureDNS"), dict) else {}
    dnssec = "N/A"
    if secure_dns:
        delegation_signed = secure_dns.get("delegationSigned")
        if delegation_signed is True:
            dnssec = "signed"
        elif delegation_signed is False:
            dnssec = "unsigned"

    mapped = {
        "domainName": data.get("ldhName", domain),
        "domainNameExt": _domain_extension(domain),
        "createdDate": created_date or "N/A",
        "updatedDate": updated_date or "N/A",
        "expiresDate": expires_date or "N/A",
        "registrarName": registrar_name,
        "registrarIANAID": registrar_iana,
        "registrarURL": "N/A",
        "whoisServer": data.get("port43", "N/A"),
        "status": status,
        "dnssec": dnssec,
        "nameServers": nameservers,
        "registrant": registrant,
        "technicalContact": technical,
        "administrativeContact": administrative,
        "ips": _resolve_host_ips(domain),
        "domainAvailability": "N/A",
        "contactEmail": registrant.get("email", "N/A"),
        "audit": {
            "createdDate": _to_iso_string(created_date),
            "updatedDate": _to_iso_string(updated_date),
        },
    }

    result = _normalize_result(domain, mapped, "rdap")
    return result, None


def _query_whois_server(server, query):
    if _is_empty(server):
        return None

    try:
        with socket.create_connection((str(server), 43), timeout=12) as sock:
            sock.settimeout(12)
            sock.sendall((str(query).strip() + "\r\n").encode("utf-8", errors="ignore"))
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 800000:
                    break

        if not chunks:
            return None
        return b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        return None


def _guess_whois_server(domain):
    tld = str(domain).split(".")[-1].lower() if "." in str(domain) else ""
    return WHOIS_SERVER_BY_TLD.get(tld)


def _parse_whois_lines(raw_text):
    parsed = {}
    if _is_empty(raw_text):
        return parsed

    for line in str(raw_text).splitlines():
        text = line.strip()
        if not text:
            continue
        if text.startswith("#") or text.startswith("%") or text.startswith(";"):
            continue
        if ":" not in text:
            continue

        key, value = text.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key not in parsed:
            parsed[key] = []
        if value:
            parsed[key].append(value)

    return parsed


def _first_field(parsed, keys):
    for key in keys:
        values = parsed.get(str(key).lower(), [])
        if values:
            return values[0]
    return "N/A"


def _extract_nameservers(parsed):
    candidates = []
    for key, values in parsed.items():
        if key in ("name server", "name servers", "nserver", "nameserver"):
            candidates.extend(values)

    extracted = []
    for value in candidates:
        token = str(value).split()[0].lower().rstrip(".")
        if token and "." in token:
            extracted.append(token)

    return _normalize_name_servers(extracted)


def _extract_contact_from_parsed(parsed, prefix):
    prefix = str(prefix).lower()
    return _merge_contact(
        {
            "name": _first_field(parsed, [f"{prefix} name", f"{prefix} contact name"]),
            "organization": _first_field(parsed, [f"{prefix} organization", f"{prefix} org", f"{prefix} contact organization"]),
            "email": _first_field(parsed, [f"{prefix} email", f"{prefix} contact email"]),
            "phone": _first_field(parsed, [f"{prefix} phone", f"{prefix} contact phone"]),
            "country": _first_field(parsed, [f"{prefix} country", f"{prefix} contact country"]),
            "city": _first_field(parsed, [f"{prefix} city", f"{prefix} contact city"]),
            "state": _first_field(parsed, [f"{prefix} state/province", f"{prefix} state", f"{prefix} contact state"]),
            "postalCode": _first_field(parsed, [f"{prefix} postal code", f"{prefix} zipcode", f"{prefix} zip"]),
            "address": _first_field(parsed, [f"{prefix} street", f"{prefix} address", f"{prefix} contact street"]),
        },
        {},
    )


def _extract_referral_server(parsed):
    refer = _first_field(parsed, ["refer", "whois"])
    if _is_empty(refer) or str(refer).upper() == "N/A":
        return None
    return str(refer).strip()


def _raw_whois_lookup(domain):
    iana_text = _query_whois_server("whois.iana.org", domain)
    iana_parsed = _parse_whois_lines(iana_text)

    whois_server = _extract_referral_server(iana_parsed) or _guess_whois_server(domain)
    if _is_empty(whois_server):
        return None, "Raw WHOIS fallback could not determine WHOIS server"

    query = f"={domain}" if "verisign-grs.com" in str(whois_server).lower() else domain
    raw_text = _query_whois_server(whois_server, query)
    parsed = _parse_whois_lines(raw_text)

    if not parsed:
        return None, "Raw WHOIS fallback returned no parsable data"

    registrant = _extract_contact_from_parsed(parsed, "registrant")
    technical = _extract_contact_from_parsed(parsed, "tech")
    administrative = _extract_contact_from_parsed(parsed, "admin")

    all_status = []
    all_status.extend(parsed.get("domain status", []))
    all_status.extend(parsed.get("status", []))
    status = _merge_status(all_status, None)

    contact_email = _first_field(
        parsed,
        [
            "registrant email",
            "admin email",
            "tech email",
            "registrar abuse contact email",
            "email",
        ],
    )

    mapped = {
        "domainName": _first_field(parsed, ["domain name", "domain"]),
        "domainNameExt": _domain_extension(domain),
        "createdDate": _first_field(parsed, ["creation date", "created on", "domain registration date", "registered on", "created"]),
        "updatedDate": _first_field(parsed, ["updated date", "last updated on", "modified", "last modified"]),
        "expiresDate": _first_field(parsed, ["registry expiry date", "expiration date", "expiry date", "expires on", "paid-till"]),
        "registrarName": _first_field(parsed, ["registrar", "sponsoring registrar", "registrar name"]),
        "registrarIANAID": _first_field(parsed, ["registrar iana id", "iana id"]),
        "registrarURL": _first_field(parsed, ["registrar url", "referral url"]),
        "whoisServer": whois_server,
        "status": status,
        "dnssec": _first_field(parsed, ["dnssec", "dnssec signed"]),
        "nameServers": _extract_nameservers(parsed),
        "registrant": registrant,
        "technicalContact": technical,
        "administrativeContact": administrative,
        "ips": _resolve_host_ips(domain),
        "domainAvailability": "N/A",
        "contactEmail": contact_email,
        "audit": {"createdDate": "N/A", "updatedDate": "N/A"},
    }

    result = _normalize_result(domain, mapped, "raw_whois")
    return result, None


def _optional_api_enrichment(domain, existing):
    if not WHOISXML_API_KEY:
        return existing

    if not isinstance(existing, dict):
        return existing

    missing_core = any(
        _is_empty(existing.get(field)) for field in ("createdDate", "expiresDate", "registrarName")
    )
    sparse_contacts = not _contact_has_meaningful_data(existing.get("registrant", {}))
    sparse_nameservers = _is_empty(existing.get("nameServers", []))

    if not (missing_core or sparse_contacts or sparse_nameservers):
        return existing

    try:
        api_data = get_domain_info(domain)
    except Exception:
        return existing

    if not isinstance(api_data, dict):
        return existing
    if str(api_data.get("registrar", "")).lower() == "error":
        return existing

    api_result = _normalize_result(
        domain,
        {
            "domainName": domain,
            "domainNameExt": _domain_extension(domain),
            "createdDate": api_data.get("creation_date", "N/A"),
            "updatedDate": api_data.get("last_updated", "N/A"),
            "expiresDate": api_data.get("expiration_date", "N/A"),
            "registrarName": api_data.get("registrar", "N/A"),
            "registrarIANAID": "N/A",
            "whoisServer": "N/A",
            "status": api_data.get("domain_status", "N/A"),
            "nameServers": api_data.get("name_servers", []),
            "registrant": {
                "organization": api_data.get("registrant_organization", "N/A"),
                "country": api_data.get("registrant_country", "N/A"),
            },
            "technicalContact": {},
            "administrativeContact": {},
            "ips": _resolve_host_ips(domain),
            "domainAvailability": "N/A",
            "contactEmail": "N/A",
            "audit": {"createdDate": "N/A", "updatedDate": "N/A"},
        },
        "whoisxml_api",
    )

    return _merge_whois_results(existing, api_result)


def _finalize_result(domain, result):
    finalized = dict(result)

    finalized["domainName"] = finalized.get("domainName") if not _is_empty(finalized.get("domainName")) else domain
    finalized["domainNameExt"] = finalized.get("domainNameExt") if not _is_empty(finalized.get("domainNameExt")) else _domain_extension(domain)

    finalized["createdDate"] = _to_iso_string(finalized.get("createdDate", "N/A"))
    finalized["updatedDate"] = _to_iso_string(finalized.get("updatedDate", "N/A"))
    finalized["expiresDate"] = _to_iso_string(finalized.get("expiresDate", "N/A"))
    finalized["estimatedDomainAge"] = _compute_domain_age(finalized.get("createdDate", "N/A"))

    finalized["nameServers"] = _normalize_name_servers(finalized.get("nameServers", []))
    ns_ips = finalized.get("nameServerIPs", {}) if isinstance(finalized.get("nameServerIPs", {}), dict) else {}
    if not ns_ips:
        ns_ips = _resolve_nameserver_ips(finalized.get("nameServers", []))
    finalized["nameServerIPs"] = {key: _unique_strings(value) for key, value in ns_ips.items()}

    if _is_empty(finalized.get("ips", [])):
        finalized["ips"] = _resolve_host_ips(domain)
    else:
        finalized["ips"] = _unique_strings(finalized.get("ips", []))

    finalized["registrant"] = _merge_contact(finalized.get("registrant", {}), {})
    finalized["technicalContact"] = _merge_contact(finalized.get("technicalContact", {}), {})
    finalized["administrativeContact"] = _merge_contact(finalized.get("administrativeContact", {}), {})

    contact_email = finalized.get("contactEmail")
    if _is_empty(contact_email):
        contact_email = _safe_pick([
            finalized["registrant"].get("email"),
            finalized["technicalContact"].get("email"),
            finalized["administrativeContact"].get("email"),
        ])
    finalized["contactEmail"] = str(contact_email) if not _is_empty(contact_email) else "N/A"

    finalized["status"] = _merge_status(finalized.get("status", "N/A"), None)
    finalized["privacyProtection"] = _detect_privacy_protection(
        finalized.get("registrant", {}),
        finalized.get("technicalContact", {}),
        finalized.get("administrativeContact", {}),
        finalized.get("contactEmail", "N/A"),
        finalized.get("status", "N/A"),
    )

    finalized["lookupSources"] = _unique_strings(finalized.get("lookupSources", []))
    finalized["audit"] = {
        "createdDate": finalized.get("createdDate", "N/A"),
        "updatedDate": finalized.get("updatedDate", "N/A"),
    }

    for key in (
        "registrarName",
        "registrarIANAID",
        "registrarURL",
        "whoisServer",
        "dnssec",
        "domainAvailability",
    ):
        if _is_empty(finalized.get(key)):
            finalized[key] = "N/A"

    return finalized


def get_whois_info(domain):
    """Get WHOIS information from multiple free sources, then optional API enrichment."""
    try:
        normalized_domain = normalize_domain_input(domain)
        if not normalized_domain:
            return {"error": "Invalid domain format. Enter a valid domain like youtube.com."}

        source_results = []
        source_errors = []

        for lookup_fn in (_python_whois_lookup, _rdap_lookup, _raw_whois_lookup):
            try:
                result, err = lookup_fn(normalized_domain)
            except Exception as exc:
                result, err = None, str(exc)

            if result:
                source_results.append(result)
            if err:
                source_errors.append(err)

        if not source_results:
            message = source_errors[0] if source_errors else "WHOIS lookup returned no data"
            return {"error": f"WHOIS lookup failed: {message}"}

        merged = source_results[0]
        for candidate in source_results[1:]:
            merged = _merge_whois_results(merged, candidate)

        merged = _optional_api_enrichment(normalized_domain, merged)
        finalized = _finalize_result(normalized_domain, merged)

        if source_errors:
            finalized["lookupNotes"] = source_errors[:3]

        return finalized
    except Exception as exc:
        return {"error": f"WHOIS lookup failed: {str(exc)}"}
