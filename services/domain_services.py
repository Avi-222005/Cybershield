import os
import re
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY")


def normalize_domain_input(domain_input):
    """Normalize user-provided domain/URL into a clean hostname."""
    if not domain_input:
        return ""

    value = str(domain_input).strip()
    if not value:
        return ""

    candidate = value if "://" in value else f"http://{value}"
    parsed = urlparse(candidate)

    host = parsed.netloc or parsed.path
    host = host.split("@")[-1]
    host = host.split(":")[0]
    host = host.strip().strip(".").lower()

    if host.startswith("www."):
        host = host[4:]

    if not host or "." not in host:
        return ""

    if not re.match(r"^[a-z0-9.-]+$", host):
        return ""

    return host


def get_domain_info(domain):
    """Get domain information using WhoisXML API."""
    try:
        url = (
            "https://www.whoisxmlapi.com/whoisserver/WhoisService"
            f"?apiKey={WHOISXML_API_KEY}&domainName={domain}&outputFormat=JSON"
        )
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            whois_record = data.get("WhoisRecord", {})

            registrar_data = whois_record.get("registrarName", "N/A")
            if not registrar_data or registrar_data == "N/A":
                registrar_data = whois_record.get("registrar", {}).get("name", "N/A")

            dates = whois_record.get("registryData", whois_record)
            creation_date = dates.get("createdDate", dates.get("created", "N/A"))
            expiration_date = dates.get("expiresDate", dates.get("expires", "N/A"))
            updated_date = dates.get("updatedDate", dates.get("changed", "N/A"))

            name_servers = []
            raw_nameservers = whois_record.get("nameServers", {}).get("hostNames", [])
            if isinstance(raw_nameservers, list):
                name_servers = raw_nameservers

            return {
                "registrar": registrar_data,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "last_updated": updated_date,
                "name_servers": name_servers,
                "domain_status": whois_record.get("status", "N/A"),
                "registrant_country": whois_record.get("registrant", {}).get("country", "N/A"),
                "registrant_organization": whois_record.get("registrant", {}).get("organization", "N/A"),
            }

        return {
            "registrar": "Error",
            "creation_date": "Error",
            "expiration_date": "Error",
            "last_updated": "Error",
            "name_servers": [],
            "domain_status": "Error",
            "registrant_country": "Error",
            "registrant_organization": "Error",
        }
    except Exception:
        return {
            "registrar": "Error",
            "creation_date": "Error",
            "expiration_date": "Error",
            "last_updated": "Error",
            "name_servers": [],
            "domain_status": "Error",
            "registrant_country": "Error",
            "registrant_organization": "Error",
        }


def get_ip_geolocation(ip):
    """Get IP geolocation using WhoisXML API with fallback to ip-api.com."""
    if WHOISXML_API_KEY:
        try:
            url = f"https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey={WHOISXML_API_KEY}&ipAddress={ip}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return {
                    "country": data.get("location", {}).get("country", "N/A"),
                    "region": data.get("location", {}).get("region", "N/A"),
                    "city": data.get("location", {}).get("city", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "asn": str(data.get("as", {}).get("asn", "N/A")),
                    "connection_type": data.get("connectionType", "N/A"),
                    "latitude": data.get("location", {}).get("lat"),
                    "longitude": data.get("location", {}).get("lng"),
                    "timezone": data.get("location", {}).get("timezone", "N/A"),
                    "postal_code": data.get("location", {}).get("postalCode", "N/A"),
                }
        except Exception:
            pass

    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "N/A"),
                    "region": data.get("regionName", "N/A"),
                    "city": data.get("city", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "asn": data.get("as", "N/A"),
                    "connection_type": "N/A",
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone", "N/A"),
                    "postal_code": data.get("zip", "N/A"),
                }
    except Exception:
        pass

    return {
        "country": "Unavailable",
        "region": "Unavailable",
        "city": "Unavailable",
        "isp": "Unavailable",
        "asn": "Unavailable",
        "connection_type": "Unavailable",
        "latitude": None,
        "longitude": None,
        "timezone": "Unavailable",
        "postal_code": "Unavailable",
    }
