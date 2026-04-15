import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")


def check_url_virustotal(url):
    """Check URL using VirusTotal API."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        submit_url = "https://www.virustotal.com/api/v3/urls"
        data = {"url": url}
        response = requests.post(submit_url, headers=headers, data=data)

        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]

            max_attempts = 20
            attempt = 0
            while attempt < max_attempts:
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                analysis_response = requests.get(analysis_url, headers=headers)

                if analysis_response.status_code == 200:
                    result = analysis_response.json()
                    status = result["data"]["attributes"]["status"]

                    if status == "completed":
                        stats = result["data"]["attributes"]["stats"]
                        last_analysis = result["data"]["attributes"]["results"]

                        malicious_vendors = []
                        suspicious_vendors = []
                        clean_vendors = []

                        for vendor, details in last_analysis.items():
                            if details["category"] == "malicious":
                                malicious_vendors.append(
                                    {"name": vendor, "result": details.get("result", "Malicious")}
                                )
                            elif details["category"] == "suspicious":
                                suspicious_vendors.append(
                                    {"name": vendor, "result": details.get("result", "Suspicious")}
                                )
                            elif details["category"] == "harmless":
                                clean_vendors.append(vendor)

                        details = []
                        if malicious_vendors:
                            details.append(f"<b>Malicious ({len(malicious_vendors)}):</b>")
                            for vendor in malicious_vendors:
                                details.append(f"  • <span>{vendor['name']}</span>: {vendor['result']}")

                        if suspicious_vendors:
                            details.append(f"\n<b>Suspicious ({len(suspicious_vendors)}):</b>")
                            for vendor in suspicious_vendors:
                                details.append(f"  • <span>{vendor['name']}</span>: {vendor['result']}")

                        if clean_vendors:
                            details.append(f"\nClean ({len(clean_vendors)}):")
                            details.append(f"  • {', '.join(clean_vendors)}")

                        if stats["malicious"] > 0:
                            status = "Malicious"
                        elif stats["suspicious"] > 0:
                            status = "Suspicious"
                        else:
                            status = "Safe"

                        vendor_data = {
                            "malicious": malicious_vendors,
                            "suspicious": suspicious_vendors,
                            "clean": clean_vendors,
                            "stats": stats,
                        }
                        return status, "\n".join(details), vendor_data

                time.sleep(1.5)
                attempt += 1

            return "Error", "Analysis timed out - please try again", {}

        return "Error", "Failed to analyze URL", {}
    except Exception as e:
        return "Error", f"API Error: {str(e)}", {}


def check_ip_reputation(ip):
    """Check IP reputation using VirusTotal API and return structured vendor data."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            last_analysis = data["data"]["attributes"]["last_analysis_results"]
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious_vendors = []
            suspicious_vendors = []
            clean_vendors = []

            for vendor, result in last_analysis.items():
                if result["category"] == "malicious":
                    malicious_vendors.append({"name": vendor, "result": result["result"]})
                elif result["category"] == "suspicious":
                    suspicious_vendors.append({"name": vendor, "result": result["result"]})
                elif result["category"] in ("undetected", "harmless"):
                    clean_vendors.append(vendor)

            details = []
            if malicious_vendors:
                details.append(f"Malicious ({len(malicious_vendors)}):")
                for vendor in malicious_vendors:
                    details.append(f"  • {vendor['name']}: {vendor['result']}")

            if suspicious_vendors:
                details.append(f"\nSuspicious ({len(suspicious_vendors)}):")
                for vendor in suspicious_vendors:
                    details.append(f"  • {vendor['name']}: {vendor['result']}")

            if clean_vendors:
                details.append(f"\nClean ({len(clean_vendors)}):")
                for vendor in clean_vendors[:10]:
                    details.append(f"  • {vendor}")
                if len(clean_vendors) > 10:
                    details.append(f"  ... and {len(clean_vendors) - 10} more")

            if stats["malicious"] > 0:
                status = "Malicious"
            elif stats["suspicious"] > 0:
                status = "Suspicious"
            else:
                status = "Safe"

            vendor_data = {
                "malicious_vendors": malicious_vendors,
                "suspicious_vendors": suspicious_vendors,
                "clean_vendors": clean_vendors,
                "malicious_count": len(malicious_vendors),
                "suspicious_count": len(suspicious_vendors),
                "clean_count": len(clean_vendors),
                "total_vendors": len(last_analysis),
            }
            return status, "\n".join(details), vendor_data

        return (
            "Error",
            "Failed to analyze IP",
            {
                "malicious_vendors": [],
                "suspicious_vendors": [],
                "clean_vendors": [],
                "malicious_count": 0,
                "suspicious_count": 0,
                "clean_count": 0,
                "total_vendors": 0,
            },
        )
    except Exception as e:
        return (
            "Error",
            f"API Error: {str(e)}",
            {
                "malicious_vendors": [],
                "suspicious_vendors": [],
                "clean_vendors": [],
                "malicious_count": 0,
                "suspicious_count": 0,
                "clean_count": 0,
                "total_vendors": 0,
            },
        )


def check_url_urlhaus(url):
    """Check URL against URLhaus intelligence feed."""
    if not URLHAUS_AUTH_KEY:
        return {
            "enabled": False,
            "matched": False,
            "query_status": "disabled",
            "message": "URLhaus auth key not configured",
        }

    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            headers={"Auth-Key": URLHAUS_AUTH_KEY},
            data={"url": url},
            timeout=12,
        )

        if response.status_code != 200:
            return {
                "enabled": True,
                "matched": False,
                "query_status": "error",
                "message": f"URLhaus HTTP {response.status_code}",
            }

        payload = response.json()
        query_status = payload.get("query_status", "unknown")

        if query_status != "ok":
            return {
                "enabled": True,
                "matched": False,
                "query_status": query_status,
                "message": payload.get("message", "No URLhaus match"),
            }

        blacklists = payload.get("blacklists", {}) or {}
        tags = payload.get("tags", []) or []
        payloads = payload.get("payloads", []) or []

        return {
            "enabled": True,
            "matched": True,
            "query_status": query_status,
            "id": payload.get("id"),
            "urlhaus_reference": payload.get("urlhaus_reference"),
            "url_status": payload.get("url_status", "unknown"),
            "host": payload.get("host"),
            "date_added": payload.get("date_added"),
            "last_online": payload.get("last_online"),
            "threat": payload.get("threat"),
            "reporter": payload.get("reporter"),
            "larted": payload.get("larted"),
            "takedown_time_seconds": payload.get("takedown_time_seconds"),
            "blacklists": {
                "surbl": blacklists.get("surbl", "unknown"),
                "spamhaus_dbl": blacklists.get("spamhaus_dbl", "unknown"),
            },
            "tags": tags,
            "payload_count": len(payloads),
            "payloads": payloads[:5],  # keep response compact for UI
        }
    except Exception as e:
        return {
            "enabled": True,
            "matched": False,
            "query_status": "error",
            "message": f"URLhaus API error: {str(e)}",
        }
