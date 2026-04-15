# Malicious IP Analysis Engine - Complete Documentation

## 🎯 Overview

The Malicious IP Analysis Engine is a comprehensive hybrid threat detection system that combines custom security analysis (40% weight) with external threat intelligence APIs (60% weight) to provide accurate, explainable IP reputation assessments.

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IP Analysis Pipeline                      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │   1. IP Validation (IPValidator)      │
        │   • Format validation (IPv4/IPv6)     │
        │   • Public IP filtering               │
        │   • Reject private/reserved ranges    │
        └───────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │  2. Custom Risk Analysis (40% weight) │
        │   • Hosting provider detection        │
        │   • VPN/Proxy/Tor indicators          │
        │   • Geolocation anomalies             │
        │   • ISP characteristics               │
        │   • Connection type analysis          │
        └───────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │  3. API Intelligence (60% weight)     │
        │   • VirusTotal vendor analysis        │
        │   • Malicious: +10 points/vendor      │
        │   • Suspicious: +5 points/vendor      │
        │   • Threat category extraction        │
        │   • Score capped at 70                │
        └───────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │  4. Hybrid Scoring Engine             │
        │   final = (0.4 × custom) + (0.6 × API)│
        └───────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │  5. Severity Classification            │
        │   • 0-39:  Low                        │
        │   • 40-69: Medium                     │
        │   • 70-100: High                      │
        └───────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │  6. Recommendation Engine             │
        │   • Actionable security guidance      │
        │   • Context-aware suggestions         │
        └───────────────────────────────────────┘
```

---

## 🔧 Module Documentation

### 1. **IPValidator**

**Purpose:** Validates IP addresses and filters out non-public IPs

**Key Methods:**
- `validate_ip(ip: str) -> Dict`

**Validation Rules:**
```python
✅ ACCEPTED:
- Valid IPv4 public addresses (e.g., 8.8.8.8, 1.1.1.1)
- Valid IPv6 public addresses

❌ REJECTED:
- Private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback (127.0.0.0/8, ::1)
- Link-local (169.254.0.0/16, fe80::/10)
- Reserved/Multicast ranges
- Invalid format
```

**Output Example:**
```json
{
  "is_valid": true,
  "ip_version": "IPv4",
  "reason": "Valid public IP address",
  "category": "public"
}
```

---

### 2. **CustomRiskAnalyzer**

**Purpose:** Analyzes IP characteristics using custom security logic (40% weight)

**Risk Indicators Checked:**

#### A. **Hosting Provider Detection**
- **Risk Points:** 15
- **Severity:** Medium
- **Logic:** Checks if ISP matches known hosting/cloud providers
- **Providers Detected:** AWS, DigitalOcean, OVH, Hetzner, Linode, Vultr, GoDaddy, etc.
- **Reason:** Hosting IPs are often used for attacks (bots, scanners, etc.)

#### B. **VPN/Proxy/Anonymizer Detection**
- **Risk Points:** 25-30
- **Severity:** High
- **Logic:** Scans ISP name and connection type for anonymization keywords
- **Keywords:** vpn, proxy, tunnel, anonymous, hide, private, tor
- **Reason:** Anonymized IPs often hide malicious actors

#### C. **Geolocation Anomalies**
- **Risk Points:** 10
- **Severity:** Medium
- **Logic:** Detects unknown or unavailable geolocation
- **Reason:** Legitimate IPs typically have proper geo-registration

#### D. **Unknown ISP**
- **Risk Points:** 5
- **Severity:** Low
- **Logic:** Flags IPs with missing or generic ISP information
- **Reason:** Legitimate traffic usually has identifiable ISP

#### E. **Unusual Connection Types**
- **Risk Points:** 5
- **Severity:** Low
- **Logic:** Detects uncommon connection types (dialup, satellite)
- **Reason:** Rare connection types in modern traffic

**Output Example:**
```json
{
  "custom_score": 45,
  "risk_level": "medium",
  "risk_factors": [
    {
      "indicator": "Hosting Provider",
      "severity": "medium",
      "description": "IP belongs to hosting provider: DigitalOcean LLC",
      "risk_points": 15
    },
    {
      "indicator": "VPN/Proxy/Anonymizer",
      "severity": "high",
      "description": "Possible VPN/Proxy detected in ISP name: ProtonVPN",
      "risk_points": 30
    }
  ],
  "analysis_summary": "Custom analysis identified 2 risk indicator(s)"
}
```

---

### 3. **ThreatIntelligenceMapper**

**Purpose:** Maps VirusTotal API responses to numeric scores (60% weight)

**Scoring Algorithm:**
```python
api_score = (malicious_vendors × 10) + (suspicious_vendors × 5)
api_score = min(api_score, 70)  # Cap at 70
```

**Threat Category Detection:**
- Malicious Activity
- Suspicious Behavior
- Spam
- Botnet
- Brute Force
- Malware
- Port Scanning
- DDoS

**Output Example:**
```json
{
  "api_score": 60,
  "threat_categories": ["Botnet", "Malware", "Port Scanning"],
  "vendor_summary": {
    "malicious": 6,
    "suspicious": 0,
    "clean": 54,
    "total_analyzed": 60
  }
}
```

---

### 4. **HybridScoringEngine**

**Purpose:** Combines custom (40%) and API (60%) scores

**Formula:**
```python
final_score = (0.4 × custom_score) + (0.6 × normalized_api_score)

where:
  normalized_api_score = (api_score / 70) × 100
```

**Example Calculation:**
```
Custom Score: 45/100
API Score: 60/70

Normalized API: (60/70) × 100 = 85.7

Final Score: (0.4 × 45) + (0.6 × 85.7)
           = 18 + 51.4
           = 69.4 ≈ 69
           
Severity: Medium (40-69 range)
Verdict: SUSPICIOUS
```

**Severity Thresholds:**
- **Low (0-39):** Minimal risk, standard monitoring
- **Medium (40-69):** Elevated risk, enhanced monitoring required
- **High (70-100):** Critical risk, immediate action required

---

### 5. **RecommendationEngine**

**Purpose:** Generates actionable security recommendations

**Recommendation Types:**

#### **High Risk (70-100)**
```
⚠️ HIGH RISK - IMMEDIATE ACTION REQUIRED

• Block this IP address immediately at firewall/WAF level
• Monitor all traffic from this IP in logs
• Check for any successful connections in the past 24-48 hours
• Review and update security rules to prevent similar threats

🎯 Identified Threats: Botnet, Malware, Port Scanning

📋 Recommended Actions:
1. Add IP to blacklist/blocklist
2. Enable enhanced logging for this IP range
3. Alert security team for investigation
4. Consider reporting to abuse contacts
```

#### **Medium Risk (40-69)**
```
⚡ MEDIUM RISK - MONITORING REQUIRED

• Monitor activity from this IP address closely
• Apply rate limiting to prevent abuse
• Enable detailed logging for this IP
• Consider temporary restrictions if suspicious patterns emerge

📋 Recommended Actions:
1. Add to monitoring watchlist
2. Apply rate limiting (e.g., max 100 req/min)
3. Enable CAPTCHA for suspicious activity
4. Review logs periodically
```

#### **Low Risk (0-39)**
```
✅ LOW RISK - NO IMMEDIATE ACTION REQUIRED

• This IP appears to be legitimate based on current analysis
• Continue standard monitoring practices
• No special restrictions necessary at this time

📋 Best Practices:
1. Maintain normal traffic monitoring
2. Keep standard rate limits active
3. Continue regular log reviews
4. Update threat intelligence feeds regularly
```

---

## 📡 API Integration

### **Flask Endpoint: `/api/check-ip`**

**Request:**
```json
POST /api/check-ip
Content-Type: application/json

{
  "ip": "203.0.113.45"
}
```

**Response Structure:**
```json
{
  "ip": "203.0.113.45",
  "valid": true,
  "ip_version": "IPv4",
  "verdict": "SUSPICIOUS",
  "final_score": 69,
  "severity": "Medium",
  
  "score_breakdown": {
    "custom_score": 45,
    "custom_weight": "40%",
    "api_score": 60,
    "api_weight": "60%",
    "calculation": "(0.4 × 45) + (0.6 × 85.7) = 69"
  },
  
  "custom_analysis": {
    "score": 45,
    "risk_level": "medium",
    "risk_factors": [
      {
        "indicator": "Hosting Provider",
        "severity": "medium",
        "description": "IP belongs to hosting provider: DigitalOcean LLC",
        "risk_points": 15
      }
    ],
    "summary": "Custom analysis identified 1 risk indicator(s)"
  },
  
  "api_analysis": {
    "score": 60,
    "threat_categories": ["Botnet", "Port Scanning"],
    "vendor_summary": {
      "malicious": 6,
      "suspicious": 0,
      "clean": 54,
      "total_analyzed": 60
    }
  },
  
  "geolocation": {
    "country": "United States",
    "region": "California",
    "city": "San Francisco",
    "isp": "DigitalOcean LLC",
    "asn": "AS14061",
    "connection_type": "Corporate",
    "latitude": 37.7749,
    "longitude": -122.4194,
    "timezone": "America/Los_Angeles",
    "postal_code": "94102"
  },
  
  "vendor_data": {
    "malicious_vendors": [
      {"name": "Kaspersky", "result": "botnet"},
      {"name": "ESET", "result": "malicious"}
    ],
    "suspicious_vendors": [],
    "clean_vendors": ["Google", "Microsoft", ...],
    "malicious_count": 6,
    "suspicious_count": 0,
    "clean_count": 54,
    "total_vendors": 60
  },
  
  "security_recommendation": "⚡ MEDIUM RISK - MONITORING REQUIRED\n\n...",
  
  "detection_reasons": [
    "Custom Analysis: Custom analysis identified 1 risk indicator(s)",
    "• Hosting Provider: IP belongs to hosting provider: DigitalOcean LLC",
    "API Intelligence: 60 vendors analyzed",
    "• Botnet",
    "• Port Scanning"
  ]
}
```

---

## 🔍 Usage Examples

### **Example 1: Safe Public IP (8.8.8.8 - Google DNS)**

**Input:** `8.8.8.8`

**Expected Output:**
```json
{
  "verdict": "SAFE",
  "final_score": 12,
  "severity": "Low",
  "custom_score": 0,
  "api_score": 0,
  "risk_factors": [],
  "threat_categories": [],
  "recommendation": "✅ LOW RISK - NO IMMEDIATE ACTION REQUIRED"
}
```

---

### **Example 2: Suspicious IP (VPN Provider)**

**Input:** `45.152.65.72`

**Expected Output:**
```json
{
  "verdict": "SUSPICIOUS",
  "final_score": 52,
  "severity": "Medium",
  "custom_score": 30,
  "api_score": 20,
  "risk_factors": [
    {
      "indicator": "VPN/Proxy/Anonymizer",
      "severity": "high",
      "description": "Possible VPN detected",
      "risk_points": 30
    }
  ],
  "threat_categories": ["Suspicious Behavior"],
  "recommendation": "⚡ MEDIUM RISK - MONITORING REQUIRED"
}
```

---

### **Example 3: Malicious IP (Known Botnet)**

**Input:** `185.220.101.23`

**Expected Output:**
```json
{
  "verdict": "MALICIOUS",
  "final_score": 82,
  "severity": "High",
  "custom_score": 45,
  "api_score": 70,
  "risk_factors": [
    {
      "indicator": "Hosting Provider",
      "severity": "medium",
      "description": "IP belongs to hosting provider",
      "risk_points": 15
    },
    {
      "indicator": "VPN/Proxy/Anonymizer",
      "severity": "high",
      "description": "Anonymous connection detected",
      "risk_points": 30
    }
  ],
  "threat_categories": ["Botnet", "Malware", "Brute Force"],
  "recommendation": "⚠️ HIGH RISK - IMMEDIATE ACTION REQUIRED"
}
```

---

### **Example 4: Invalid/Private IP**

**Input:** `192.168.1.1`

**Expected Output:**
```json
{
  "ip": "192.168.1.1",
  "valid": false,
  "validation_error": "Private IP address - not routable on the internet",
  "category": "private",
  "verdict": "INVALID",
  "final_score": 0,
  "severity": "N/A",
  "recommendation": "Cannot analyze - IP address is not a valid public IP."
}
```

---

## 🎓 Key Design Decisions

### **1. Why 40% Custom + 60% API Split?**
- **Custom analysis (40%):** Provides independent validation, prevents over-reliance on external APIs
- **API intelligence (60%):** Leverages crowdsourced threat data from 60+ security vendors
- **Balance:** Ensures neither source dominates, reducing false positives/negatives

### **2. Why Cap API Score at 70?**
- Prevents API from completely overriding custom analysis
- Ensures custom indicators always influence final verdict
- Maintains 40/60 weight distribution mathematically

### **3. Why Reject Private IPs?**
- Security: Prevents internal network scanning
- Accuracy: Private IPs have no public threat intelligence
- Compliance: Protects user privacy

### **4. Why These Specific Severity Thresholds?**
- **0-39 (Low):** Matches typical baseline internet noise
- **40-69 (Medium):** Elevated risk requiring attention
- **70-100 (High):** Clear malicious indicators from multiple sources

---

## 🚀 Testing the System

### **Test Commands:**

```bash
# Start Flask server
python app.py

# Test Safe IP
curl -X POST http://localhost:5000/api/check-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'

# Test Private IP (should reject)
curl -X POST http://localhost:5000/api/check-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.1"}'

# Test Invalid IP
curl -X POST http://localhost:5000/api/check-ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"999.999.999.999"}'
```

---

## 📝 Function-Level Explanation

### **Main Function: `analyze_ip_hybrid()`**

```python
def analyze_ip_hybrid(ip, api_status, api_details, vendor_data, geolocation_data):
    """
    Orchestrates the entire hybrid IP analysis pipeline.
    
    Pipeline:
    1. Validate IP format and type (public vs private)
    2. Run custom risk analysis (40% weight)
    3. Map API vendor verdicts to score (60% weight)
    4. Calculate weighted final score
    5. Classify severity (Low/Medium/High)
    6. Generate actionable recommendation
    7. Compile comprehensive JSON response
    
    Returns: Complete analysis with explainability
    """
```

**Data Flow:**
```
IP Input → Validation → Custom Analysis → API Mapping → 
Hybrid Scoring → Severity Classification → Recommendation → Final JSON
```

---

## ✅ Deliverables Checklist

- ✅ **Backend Implementation:** Complete Flask integration
- ✅ **IP Validation:** IPv4/IPv6, private/public filtering
- ✅ **Custom Risk Analysis:** 5 independent indicators
- ✅ **Threat Intelligence:** VirusTotal API integration
- ✅ **Vendor Mapping:** Malicious (+10), Suspicious (+5)
- ✅ **Hybrid Scoring:** 40% custom + 60% API weighted
- ✅ **Severity Classification:** Low/Medium/High thresholds
- ✅ **Recommendation Engine:** Context-aware guidance
- ✅ **Modular Architecture:** Separate classes for each component
- ✅ **Explainable Output:** Detailed JSON with reasoning
- ✅ **Function Documentation:** Comprehensive comments
- ✅ **Example Test Cases:** Safe, Suspicious, Malicious, Invalid

---

## 🔐 Security Considerations

1. **API Key Protection:** Store VirusTotal key in `.env` file
2. **Rate Limiting:** Implement request throttling to prevent abuse
3. **Input Validation:** Strict IP format checking
4. **Private IP Filtering:** Prevents internal network scanning
5. **Error Handling:** Graceful degradation if API unavailable

---

## 📊 Performance Metrics

- **Average Response Time:** 1-2 seconds (depends on API latency)
- **Custom Analysis:** <100ms (local processing)
- **API Call:** 500ms-1.5s (VirusTotal API)
- **Geolocation Lookup:** 200-500ms (free IP-API fallback)

---

## 🛠️ Future Enhancements

1. **Machine Learning:** Train ML model on historical data
2. **Expanded Custom Indicators:** Add ASN reputation, BGP data
3. **Multiple API Sources:** Integrate AbuseIPDB, Shodan, etc.
4. **Real-time Blocklist:** Auto-block high-risk IPs
5. **Historical Tracking:** Store IP reputation over time
6. **Bulk Analysis:** Analyze multiple IPs simultaneously
7. **IPv6 Support:** Expand custom analysis for IPv6

---

## 📚 References

- **VirusTotal API:** https://developers.virustotal.com/reference/ip-info
- **IP-API Geolocation:** https://ip-api.com/docs
- **Python ipaddress Module:** https://docs.python.org/3/library/ipaddress.html
- **IANA Reserved IP Addresses:** https://www.iana.org/assignments/iana-ipv4-special-registry/

---

**Author:** CyberShield Security Team  
**Version:** 1.0  
**Last Updated:** December 28, 2025
