import socket
import ssl
from datetime import datetime


def check_ssl_certificate(domain):
    """Check SSL certificate information for a domain."""
    try:
        with socket.create_connection((domain, 443)) as sock:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                issuer = dict(x[0] for x in cert["issuer"])
                subject = dict(x[0] for x in cert["subject"])

                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (not_after - datetime.now()).days

                return {
                    "status": "Valid",
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "subject": subject.get("commonName", "Unknown"),
                    "valid_from": not_before.strftime("%Y-%m-%d"),
                    "valid_until": not_after.strftime("%Y-%m-%d"),
                    "days_until_expiry": days_until_expiry,
                    "is_valid": True,
                }
    except socket.gaierror:
        return {"status": "Error", "message": "Could not Resolve Domain Name", "is_valid": False}
    except ssl.SSLError as e:
        return {"status": "Error", "message": str(e), "is_valid": False}
    except Exception as e:
        return {"status": "Error", "message": str(e), "is_valid": False}
