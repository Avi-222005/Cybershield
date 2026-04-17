# CyberShield - Cybersecurity Analysis Platform

CyberShield is a full-stack cybersecurity toolkit with a Flask API backend and a React + Vite frontend. It combines hybrid threat scoring with practical recon and forensics utilities for URLs, IPs, domains, HTTP headers, email headers, and web stack fingerprinting.

## Current Features

### Hybrid Threat Detection
- Hybrid URL phishing detection with weighted scoring:
  - Custom URL risk analysis (65%)
  - Threat intelligence checks (35%)
  - URLhaus hit escalation for known malicious infrastructure
- Hybrid IP reputation analysis with weighted scoring:
  - Custom IP risk indicators (40%)
  - Threat intelligence score (60%)
- Explainable output:
  - Final verdict (SAFE, SUSPICIOUS, MALICIOUS)
  - Risk score (0-100)
  - Severity and security recommendations
  - Detection reasons and score breakdown

### Recon and Domain Security Tools
- SSL certificate checker
- WHOIS lookup
- DNS lookup (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, DMARC, SPF)
- Subdomain finder (common wordlist scan)
- Port scanner (common ports)
- Service detection with basic banner grab
- HTTP security header analyzer
- Technology stack analyzer (headers, assets, script fingerprints)

### Email Forensics
- Basic email header analyzer
- Advanced email header analyzer with:
  - SPF, DKIM, DMARC parsing
  - spoofing checks
  - received-route IP extraction
  - per-hop reputation checks
  - risk scoring and phishing indicators
  - time-delay anomaly signals

### Reporting
- IP report PDF endpoint (WeasyPrint based, optional)
- WHOIS report PDF endpoint (WeasyPrint based, optional)
- Email threat analysis PDF endpoint (ReportLab based)

### Frontend Experience
- React + TypeScript single-page application
- Dedicated pages for each analyzer tool
- Animated UI with route transitions
- API integration layer with typed result models

## Tech Stack

### Backend
- Python
- Flask
- Flask-CORS
- Flask-SQLAlchemy
- requests
- python-dotenv
- python-whois
- dnspython

### Frontend
- React 18 + TypeScript
- Vite
- Tailwind CSS
- Framer Motion
- React Router

## Project Structure

```text
CyberShield/
|- app.py                     # Flask app and API routes
|- phishing_detector.py       # Hybrid URL phishing logic
|- ip_analyzer.py             # Hybrid IP analysis logic
|- services/                  # Domain, recon, intel, email, tech stack services
|- frontend/                  # React + Vite frontend
|- templates/                 # Server-side templates (legacy/PDF)
|- static/                    # Static assets
|- config/                    # Config files
|- requirements.txt           # Python dependencies
|- vercel.json                # Deployment config
```

## API Endpoints

### Core Threat Endpoints
- POST /api/check-url
- POST /api/check-ip

### Domain and Recon Endpoints
- POST /api/check-ssl
- POST /api/whois-lookup
- POST /api/dns-lookup
- POST /api/subdomain-scan
- POST /api/port-scan
- POST /api/service-detect
- POST /api/header-analysis
- POST /api/tech-stack

### Email Forensics Endpoints
- POST /api/email-analyzer
- POST /api/email-analyzer-advanced

### PDF Export Endpoints
- POST /api/download-ip-pdf
- POST /api/download-whois-pdf
- POST /api/download-email-analysis-pdf

## Setup

### 1. Clone Repository

```bash
git clone <your-repo-url>
cd CyberShield
```

### 2. Backend Setup

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

Create a root .env file:

```env
FLASK_SECRET_KEY=your_secret_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
WHOISXML_API_KEY=your_whoisxml_api_key
URLHAUS_AUTH_KEY=your_urlhaus_auth_key
```

Optional/extra PDF packages:

```bash
pip install reportlab weasyprint
```

### 3. Frontend Setup

```bash
cd frontend
npm install
```

Create frontend/.env from frontend/.env.example:

```env
VITE_SUPABASE_URL=your_supabase_project_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
```

### 4. Run the Project

Backend:

```bash
python app.py
```

Frontend (new terminal):

```bash
cd frontend
npm run dev
```

Default local URLs:
- Backend: http://127.0.0.1:5000
- Frontend: http://127.0.0.1:5173

## Notes
- Some external intel features depend on API keys and third-party service availability.
- PDF generation routes using WeasyPrint are disabled automatically if WeasyPrint is not installed.
- SQLite scan history is created automatically by Flask-SQLAlchemy on startup.

## Render Deployment Checklist

Before pushing to GitHub for auto-deploy:

1. Backend dependencies
- Ensure [requirements.txt](requirements.txt) is committed.
- Install command on Render: pip install -r requirements.txt

2. Backend start command
- Use: gunicorn app:app

3. Required environment variables (Render)
- FLASK_SECRET_KEY
- VIRUSTOTAL_API_KEY
- WHOISXML_API_KEY
- URLHAUS_AUTH_KEY

4. CORS configuration
- Set either CORS_ALLOWED_ORIGINS (comma-separated) or FRONTEND_URL.
- The backend also auto-detects RENDER_EXTERNAL_URL and VERCEL_URL when available.

5. Frontend build artifacts
- Ensure [frontend/package.json](frontend/package.json) and [frontend/package-lock.json](frontend/package-lock.json) are committed so new tool dependencies install correctly.

6. Frontend API base URL
- In frontend env, set VITE_API_BASE_URL to your Render backend URL when frontend is hosted separately.
