# CyberShield - Advanced Cybersecurity Analysis Platform

🛡️ A comprehensive cybersecurity analysis platform with **Hybrid Phishing Detection** system that combines custom URL analysis with threat intelligence APIs.

## 🌟 Key Features

### 🎯 **NEW: Hybrid Phishing Detection System**
- ✅ **Custom URL Analysis** (65% weight) - 12+ security feature detection
- ✅ **Threat Intelligence Integration** (35% weight) - VirusTotal API
- ✅ **Explainable AI** - Clear detection reasons for every verdict
- ✅ **Risk Scoring** - 0-100 score with severity classification
- ✅ **Zero-Day Detection** - Works even without API data

### 🔧 Additional Security Tools
- 🔍 URL Phishing Detection
- 🌍 IP Reputation Analysis
- 📍 IP Geolocation Tracking
- 🔒 SSL Certificate Checker
- 📊 WHOIS Lookup
- 📱 Mobile-Friendly Interface

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- API keys (optional for full functionality):
  - VirusTotal API key
  - WhoisXML API key

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/cybershield.git
cd cybershield
```

2. **Create virtual environment**:
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Configure API keys** (create `.env` file):
```
VIRUSTOTAL_API_KEY=your_virustotal_api_key
WHOISXML_API_KEY=your_whoisxml_api_key
FLASK_SECRET_KEY=your_secret_key_here
```

### Running the Application

1. **Start the server**:
```bash
python app.py
```

2. **Access the application**:
   - Open browser: http://127.0.0.1:5000
   - The app runs in debug mode by default

3. **Run tests**:
```bash
python test_phishing_detector.py
```

## 📊 Hybrid Phishing Detection

### How It Works

```
User URL → Custom Analysis (65%) + API Check (35%) → Weighted Score → Verdict
```

**Custom Analysis** extracts 12+ features:
- IP address usage
- Brand spoofing detection
- Suspicious keywords
- Subdomain analysis
- HTTPS misuse
- High-risk TLDs
- URL shorteners
- And more...

**Weighted Decision**:
```
Final Score = (0.65 × Custom Score) + (0.35 × API Score)

Classification:
- 0-29   → SAFE
- 30-59  → SUSPICIOUS  
- 60-100 → MALICIOUS
```

### API Usage Example

```bash
curl -X POST http://127.0.0.1:5000/api/check-url \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```

**Response**:
```json
{
  "verdict": "SAFE",
  "final_score": 0,
  "severity": "LOW",
  "custom_score": 0,
  "api_score": 0,
  "detection_reasons": [...],
  "security_recommendation": "...",
  "score_breakdown": {...}
}
```

## 📁 Project Structure

```
CyberShield/
├── phishing_detector.py          # 🔴 Hybrid detection system
├── app.py                         # Flask application
├── utils.py                       # Helper functions
├── test_phishing_detector.py     # Test suite
├── example_usage.py               # Usage examples
├── HYBRID_DETECTION_DOCS.md      # Complete documentation
├── VIVA_QUICK_REFERENCE.py       # Academic guide
├── PROJECT_SUMMARY.md            # Project overview
├── templates/                     # HTML templates
├── static/                        # CSS, JS, images
└── requirements.txt               # Dependencies
```

## 🎓 Academic Project

This project includes:
- ✅ Original algorithm implementation (not just API wrapper)
- ✅ Comprehensive documentation (100+ pages)
- ✅ Test suite with multiple scenarios
- ✅ Modular, clean code architecture
- ✅ Viva preparation materials
- ✅ Mathematical explanations

### Documentation Files
- **HYBRID_DETECTION_DOCS.md** - Complete system documentation
- **VIVA_QUICK_REFERENCE.py** - Viva Q&A preparation
- **PROJECT_SUMMARY.md** - Executive summary
- **test_phishing_detector.py** - Comprehensive test suite
- **example_usage.py** - Simple usage examples

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## API Documentation

### URL Check Endpoint
```
POST /api/check-url
Content-Type: application/json

{
    "url": "https://example.com"
}
```

### IP Check Endpoint
```
POST /api/check-ip
Content-Type: application/json

{
    "ip": "8.8.8.8"
}
```

## Project Structure

```
cybershield/
├── app.py              # Main Flask application
├── utils.py            # API integration utilities
├── requirements.txt    # Python dependencies
├── .env               # Environment variables
├── templates/         # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── phishing_checker.html
│   ├── ip_checker.html
│   └── about.html
└── README.md
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- VirusTotal API
- WhoisXML API
- OpenStreetMap
- Bootstrap
- Flask 