def format_ip_reputation_details_for_pdf(malicious_vendors, suspicious_vendors, undetected_vendors):
    details = []
    if malicious_vendors:
        details.append(f"<strong>Malicious ({len(malicious_vendors)}):</strong>")
        for vendor in malicious_vendors:
            details.append(f"  • {vendor['name']}: {vendor['result']}")
    if suspicious_vendors:
        details.append(f"<strong>Suspicious ({len(suspicious_vendors)}):</strong>")
        for vendor in suspicious_vendors:
            details.append(f"  • {vendor['name']}: {vendor['result']}")
    if undetected_vendors:
        details.append(f"<strong>Clean ({len(undetected_vendors)}):</strong>")
        for vendor in undetected_vendors:
            details.append(f"  • {vendor}")
    return "<br>".join(details)
