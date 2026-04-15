from datetime import datetime

import requests

from .domain_services import normalize_domain_input

try:
    import whois as python_whois
except Exception:
    python_whois = None


def _safe_pick(value, default="N/A"):
    if value in (None, "", [], {}):
        return default
    if isinstance(value, list):
        return value[0] if value else default
    return value


def _to_iso_string(value):
    if value in (None, "", "N/A"):
        return "N/A"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, list):
        if not value:
            return "N/A"
        return _to_iso_string(value[0])
    return str(value)


def _build_whois_result(domain, source_data):
    created_date = _to_iso_string(source_data.get("createdDate", "N/A"))
    updated_date = _to_iso_string(source_data.get("updatedDate", "N/A"))
    expires_date = _to_iso_string(source_data.get("expiresDate", "N/A"))
    status = source_data.get("status", "N/A")
    if isinstance(status, list):
        status = " ".join(status)

    domain_age = source_data.get("estimatedDomainAge", "N/A")
    if domain_age == "N/A" and created_date != "N/A":
        try:
            created = datetime.strptime(created_date, "%Y-%m-%dT%H:%M:%SZ")
            domain_age = (datetime.now() - created).days
        except Exception:
            domain_age = "N/A"

    return {
        "domainName": source_data.get("domainName", domain),
        "domainNameExt": source_data.get("domainNameExt", "." + domain.split(".")[-1] if "." in domain else ""),
        "createdDate": created_date,
        "updatedDate": updated_date,
        "expiresDate": expires_date,
        "registrarName": source_data.get("registrarName", "N/A"),
        "registrarIANAID": source_data.get("registrarIANAID", "N/A"),
        "whoisServer": source_data.get("whoisServer", "N/A"),
        "status": status,
        "nameServers": source_data.get("nameServers", []),
        "registrant": source_data.get("registrant", {}),
        "technicalContact": source_data.get("technicalContact", {}),
        "administrativeContact": source_data.get("administrativeContact", {}),
        "estimatedDomainAge": domain_age,
        "ips": source_data.get("ips", []),
        "domainAvailability": source_data.get("domainAvailability", "N/A"),
        "contactEmail": source_data.get("contactEmail", "N/A"),
        "audit": source_data.get("audit", {"createdDate": "N/A", "updatedDate": "N/A"}),
    }


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
    }


def _python_whois_lookup(domain):
    if python_whois is None:
        return None, "python-whois library not installed"

    try:
        data = python_whois.whois(domain)
    except Exception as e:
        return None, f"WHOIS query failed: {str(e)}"

    if not data:
        return None, "No WHOIS data found for this domain"

    domain_name = getattr(data, "domain_name", None)
    if not domain_name:
        has_registrar = getattr(data, "registrar", None)
        has_creation = getattr(data, "creation_date", None)
        if not has_registrar and not has_creation:
            return None, "No WHOIS data found for this domain"

    registrar = _safe_pick(getattr(data, "registrar", None))
    name_servers = getattr(data, "name_servers", []) or []
    if isinstance(name_servers, str):
        name_servers = [name_servers]
    name_servers = sorted({str(ns).lower() for ns in name_servers if ns})

    emails = getattr(data, "emails", None)
    if isinstance(emails, list):
        registrant_email = emails[0] if emails else "N/A"
    else:
        registrant_email = emails if emails else "N/A"

    status = getattr(data, "status", "N/A")
    if isinstance(status, list):
        status = " | ".join([str(x) for x in status if x]) or "N/A"

    registrant_contact = {
        "name": _safe_pick(getattr(data, "name", None)),
        "organization": _safe_pick(getattr(data, "org", None)),
        "email": registrant_email,
        "phone": "N/A",
        "country": _safe_pick(getattr(data, "country", None)),
        "city": _safe_pick(getattr(data, "city", None)),
        "state": _safe_pick(getattr(data, "state", None)),
        "postalCode": _safe_pick(getattr(data, "zipcode", None)),
        "address": _safe_pick(getattr(data, "address", None)),
    }

    mapped = {
        "domainName": domain,
        "domainNameExt": "." + domain.split(".")[-1] if "." in domain else "",
        "createdDate": _to_iso_string(getattr(data, "creation_date", "N/A")),
        "updatedDate": _to_iso_string(getattr(data, "updated_date", "N/A")),
        "expiresDate": _to_iso_string(getattr(data, "expiration_date", "N/A")),
        "registrarName": registrar,
        "registrarIANAID": "N/A",
        "registrarURL": _safe_pick(getattr(data, "registrar_url", None)),
        "whoisServer": _safe_pick(getattr(data, "whois_server", "N/A")),
        "status": status,
        "dnssec": _safe_pick(getattr(data, "dnssec", None)),
        "nameServers": name_servers,
        "registrant": registrant_contact,
        "technicalContact": _default_contact(),
        "administrativeContact": _default_contact(),
        "estimatedDomainAge": "N/A",
        "ips": [],
        "domainAvailability": "N/A",
        "contactEmail": registrant_email,
        "audit": {"createdDate": "N/A", "updatedDate": "N/A"},
    }
    return _build_whois_result(domain, mapped), None


def _rdap_lookup(domain):
    rdap_url = f"https://rdap.org/domain/{domain}"
    response = requests.get(rdap_url, timeout=15)
    if response.status_code != 200:
        return None, f"RDAP lookup failed ({response.status_code})"

    data = response.json()
    events = data.get("events", []) or []
    event_map = {}
    for ev in events:
        action = ev.get("eventAction")
        date = ev.get("eventDate")
        if action and date and action not in event_map:
            event_map[action] = date

    nameservers = [ns.get("ldhName") for ns in (data.get("nameservers", []) or []) if ns.get("ldhName")]
    registrant = _default_contact()
    technical = _default_contact()
    admin = _default_contact()
    registrar_name = "N/A"

    for ent in data.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        vcard = ent.get("vcardArray")
        contact = _default_contact()
        if isinstance(vcard, list) and len(vcard) >= 2:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4:
                    key, value = item[0], item[3]
                    if key == "fn" and value:
                        contact["name"] = str(value)
                    elif key == "org" and value:
                        contact["organization"] = value[0] if isinstance(value, list) else str(value)
                    elif key == "email" and value:
                        contact["email"] = str(value)
                    elif key == "tel" and value:
                        contact["phone"] = str(value)
                    elif key == "adr" and isinstance(value, list):
                        if len(value) > 3 and value[3]:
                            contact["city"] = str(value[3])
                        if len(value) > 4 and value[4]:
                            contact["state"] = str(value[4])
                        if len(value) > 5 and value[5]:
                            contact["postalCode"] = str(value[5])
                        if len(value) > 6 and value[6]:
                            contact["country"] = str(value[6])

        if "registrant" in roles:
            registrant = contact
        if "technical" in roles:
            technical = contact
        if "administrative" in roles:
            admin = contact
        if "registrar" in roles:
            registrar_name = contact.get("organization") or contact.get("name") or "N/A"

    status = data.get("status", [])
    if isinstance(status, list):
        status = " | ".join([str(s) for s in status]) if status else "N/A"

    mapped = {
        "domainName": data.get("ldhName", domain),
        "domainNameExt": "." + domain.split(".")[-1] if "." in domain else "",
        "createdDate": event_map.get("registration", "N/A"),
        "updatedDate": event_map.get("last changed", event_map.get("last update of RDAP database", "N/A")),
        "expiresDate": event_map.get("expiration", "N/A"),
        "registrarName": registrar_name,
        "registrarIANAID": "N/A",
        "whoisServer": data.get("port43", "N/A"),
        "status": status,
        "nameServers": nameservers,
        "registrant": registrant,
        "technicalContact": technical,
        "administrativeContact": admin,
        "estimatedDomainAge": "N/A",
        "ips": [],
        "domainAvailability": "N/A",
        "contactEmail": registrant.get("email", "N/A"),
        "audit": {"createdDate": "N/A", "updatedDate": "N/A"},
    }
    return _build_whois_result(domain, mapped), None


def get_whois_info(domain):
    """Get WHOIS information using python-whois with RDAP fallback."""
    try:
        normalized_domain = normalize_domain_input(domain)
        if not normalized_domain:
            return {"error": "Invalid domain format. Enter a valid domain like youtube.com."}

        result, err = _python_whois_lookup(normalized_domain)
        if result:
            return result

        try:
            result, _ = _rdap_lookup(normalized_domain)
            if result:
                return result
        except Exception:
            pass

        return {"error": f"WHOIS lookup failed: {err}" if err else "WHOIS lookup returned no data"}
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}
