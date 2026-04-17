from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from jinja2 import TemplateNotFound
import os
from dotenv import load_dotenv
import requests
from datetime import datetime
from urllib.parse import urlparse
import re
import tempfile
import html
from io import BytesIO
import threading
import time

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Try to import weasyprint, but make it optional
try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False
    print("Warning: WeasyPrint not available. PDF generation will be disabled.")

from services import (
    check_url_virustotal,
    check_url_urlhaus,
    get_domain_info,
    check_ip_reputation,
    get_ip_geolocation,
    check_ssl_certificate,
    get_whois_info,
    normalize_domain_input,
    dns_lookup,
    dns_lookup_pro,
    subdomain_scan,
    subdomain_finder_pro,
    port_scan,
    service_detection,
    advanced_network_scan,
    header_analysis,
    http_header_audit,
    analyze_tech_stack,
    analyze_email_header,
    analyze_email_header_advanced,
    unified_recon_scan,
)
from phishing_detector import analyze_url_for_phishing
from ip_analyzer import analyze_ip_hybrid

# Load environment variables
load_dotenv()

app = Flask(__name__)

def _build_cors_origins():
    raw = os.getenv('CORS_ALLOWED_ORIGINS', '').strip()
    if raw == '*':
        return '*'

    origins = []
    if raw:
        origins.extend([origin.strip().rstrip('/') for origin in raw.split(',') if origin.strip()])

    # Common deployment env vars to reduce manual config mistakes.
    frontend_url = os.getenv('FRONTEND_URL', '').strip()
    if frontend_url:
        origins.append(frontend_url.rstrip('/'))

    render_external_url = os.getenv('RENDER_EXTERNAL_URL', '').strip()
    if render_external_url:
        origins.append(render_external_url.rstrip('/'))

    vercel_url = os.getenv('VERCEL_URL', '').strip()
    if vercel_url:
        if not vercel_url.startswith('http://') and not vercel_url.startswith('https://'):
            vercel_url = f'https://{vercel_url}'
        origins.append(vercel_url.rstrip('/'))

    if not origins:
        origins = ['http://localhost:5173', 'http://127.0.0.1:5173']

    return list(dict.fromkeys(origins))


CORS(app, origins=_build_cors_origins())
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybershield.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    result = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()


_ADVANCED_SCAN_LOCK = threading.Lock()
_ADVANCED_SCAN_LAST_REQUEST = {}
_ADVANCED_SCAN_MIN_INTERVAL_SECONDS = 3

# Routes
@app.route('/')
def home():
    return jsonify({
        'service': 'CyberShield API',
        'status': 'ok',
        'message': 'Backend is running. Use /api/* endpoints for analysis.'
    }), 200


def _safe_render_template(template_name: str, fallback_route: str):
    try:
        return render_template(template_name)
    except TemplateNotFound:
        return jsonify({
            'error': f'Template not found: {template_name}',
            'message': 'This deployment is configured as API-only. Use frontend app for UI pages.',
            'frontend_route': fallback_route
        }), 404


@app.route('/healthz')
def healthz():
    return jsonify({'status': 'ok'}), 200

@app.route('/phishing-checker')
def phishing_checker():
    return _safe_render_template('phishing_checker.html', '/phishing-checker')

@app.route('/ip-checker')
def ip_checker():
    return _safe_render_template('ip_checker.html', '/ip-checker')

@app.route('/about')
def about():
    return _safe_render_template('about.html', '/about')

@app.route('/ssl-checker')
def ssl_checker():
    return _safe_render_template('ssl_checker.html', '/ssl-checker')

@app.route('/whois-lookup')
def whois_lookup():
    return _safe_render_template('whois_lookup.html', '/whois-lookup')

@app.route('/api/check-url', methods=['POST'])
def check_url():
    """
    Hybrid Phishing Detection Endpoint
    Combines custom URL analysis with threat intelligence API
    """
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Validate URL format
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Step 1: Check URL with VirusTotal (Threat Intelligence API)
        api_status, api_details, vendor_data = check_url_virustotal(url)
        urlhaus_result = check_url_urlhaus(url)
        
        # Step 2: Perform hybrid phishing analysis
        # This combines custom URL analysis (65%) with API results (35%)
        phishing_analysis = analyze_url_for_phishing(url, api_status, api_details)
        
        # Step 3: Get additional domain information
        domain_info = get_domain_info(parsed_url.netloc)
        
        # Step 4: Prepare response with hybrid detection results
        detection_reasons = list(phishing_analysis['detection_reasons'])
        if urlhaus_result.get('matched'):
            url_status = urlhaus_result.get('url_status', 'unknown')
            threat = urlhaus_result.get('threat', 'unknown threat')
            detection_reasons.append(
                f"URLhaus flagged this URL as {threat} (status: {url_status})"
            )

            # Escalate verdict to at least suspicious if URLhaus has a hit.
            if phishing_analysis['final_score'] < 60:
                phishing_analysis['final_score'] = max(phishing_analysis['final_score'], 60)
                phishing_analysis['verdict'] = 'MALICIOUS' if url_status == 'online' else 'SUSPICIOUS'
                phishing_analysis['severity'] = 'HIGH' if url_status == 'online' else 'MEDIUM'
                phishing_analysis['security_recommendation'] = (
                    'URLhaus reported this URL as malicious infrastructure. '
                    'Block access and investigate related traffic immediately.'
                )

        result = {
            # Hybrid Detection Results
            'verdict': phishing_analysis['verdict'],
            'final_score': phishing_analysis['final_score'],
            'severity': phishing_analysis['severity'],
            'security_recommendation': phishing_analysis['security_recommendation'],
            
            # Detailed Scoring Breakdown
            'score_breakdown': phishing_analysis['score_breakdown'],
            'custom_score': phishing_analysis['custom_score'],
            'api_score': phishing_analysis['api_score'],
            
            # Detection Reasons (combined from custom + API)
            'detection_reasons': detection_reasons,
            
            # Analysis Features Summary
            'analysis_features': phishing_analysis['analysis_features'],
            
            # Legacy fields for backward compatibility
            'status': phishing_analysis['verdict'],  # Maps to SAFE/SUSPICIOUS/MALICIOUS
            'details': '\n'.join(detection_reasons),
            
            # Additional Context
            'domain_info': domain_info,
            'analyzed_url': url,
            'domain': phishing_analysis['domain'],
            'urlhaus': urlhaus_result,
            
            # Vendor Details
            'vendor_data': vendor_data
        }
        
        # Step 5: Save to database
        scan_result = ScanResult(
            scan_type='url_phishing_hybrid',
            target=url,
            result=str({
                'verdict': result['verdict'],
                'score': result['final_score'],
                'severity': result['severity']
            })
        )
        db.session.add(scan_result)
        db.session.commit()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-ip', methods=['POST'])
def check_ip():
    """
    Hybrid IP Analysis Endpoint
    
    Performs comprehensive IP threat analysis using:
    - Custom risk indicators (40% weight)
    - Threat intelligence API (60% weight)
    - Geolocation analysis
    - Vendor verdict aggregation
    """
    ip = request.json.get('ip')
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400
    
    try:
        # Step 1: Get threat intelligence from API
        status, details, vendor_data = check_ip_reputation(ip)
        
        # Step 2: Get geolocation information
        geolocation = get_ip_geolocation(ip)
        
        # Step 3: Perform hybrid analysis (custom 40% + API 60%)
        analysis_result = analyze_ip_hybrid(
            ip=ip,
            api_status=status,
            api_details=details,
            vendor_data=vendor_data,
            geolocation_data=geolocation
        )
        
        # Step 4: Prepare response with all data for frontend
        result = {
            # Core analysis results
            'status': analysis_result['verdict'],
            'verdict': analysis_result['verdict'],
            'final_score': analysis_result['final_score'],
            'severity': analysis_result['severity'],
            
            # Score breakdown
            'score_breakdown': analysis_result['score_breakdown'],
            'custom_score': analysis_result['custom_analysis']['score'],
            'api_score': analysis_result['api_analysis']['score'],
            
            # Detection details
            'details': details,
            'detection_reasons': analysis_result['detection_reasons'],
            'risk_factors': analysis_result['custom_analysis']['risk_factors'],
            'threat_categories': analysis_result['api_analysis']['threat_categories'],
            
            # Geolocation (flattened for frontend compatibility)
            **geolocation,
            
            # Vendor data
            'vendor_data': vendor_data,
            'vendor_summary': analysis_result['api_analysis']['vendor_summary'],
            
            # Recommendation
            'security_recommendation': analysis_result['security_recommendation'],
            
            # Validation
            'valid': analysis_result['valid'],
            'ip_version': analysis_result.get('ip_version', 'IPv4')
        }
        
        # Step 5: Save to database
        scan_result = ScanResult(
            scan_type='ip',
            target=ip,
            result=str({
                'verdict': analysis_result['verdict'],
                'final_score': analysis_result['final_score'],
                'severity': analysis_result['severity']
            })
        )
        db.session.add(scan_result)
        db.session.commit()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download-ip-pdf', methods=['POST'])
def download_ip_pdf():
    if not WEASYPRINT_AVAILABLE:
        return jsonify({'error': 'PDF generation is not available. WeasyPrint library is not properly configured.'}), 503
    
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'error': 'IP address is required'}), 400
            
        # Get IP information
        status, details, _vendor_data = check_ip_reputation(ip)
        geo = get_ip_geolocation(ip)
        
        # Create HTML content for PDF
        html_content = render_template('ip_pdf_template.html',
            ip=ip,
            status=status,
            details=details,
            geo=geo
        )
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
            try:
                # Generate PDF using WeasyPrint
                HTML(string=html_content).write_pdf(tmp.name)
                
                # Send the file
                return send_file(
                    tmp.name,
                    as_attachment=True,
                    download_name=f'ip-report-{ip}.pdf',
                    mimetype='application/pdf'
                )
                
            except Exception as pdf_error:
                error_msg = str(pdf_error)
                print(f"PDF Generation Error: {error_msg}")
                return jsonify({'error': f'PDF Generation Error: {error_msg}'}), 500
            
    except Exception as e:
        error_msg = str(e)
        print(f"General Error: {error_msg}")
        return jsonify({'error': f'Error: {error_msg}'}), 500

@app.route('/api/check-ssl', methods=['POST'])
def check_ssl():
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
            
        # Normalize URL/domain input into plain host
        domain = normalize_domain_input(domain)
        if not domain:
            return jsonify({'error': 'Invalid domain format. Enter a valid domain like example.com.'}), 400
        
        # Call the SSL certificate checking function
        result = check_ssl_certificate(domain)
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 400
            
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/whois-lookup', methods=['POST'])
def api_whois_lookup():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request body'}), 400
            
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
            
        # Normalize URL/domain input into plain host
        domain = normalize_domain_input(domain)
        if not domain:
            return jsonify({'error': 'Invalid domain format. Enter a valid domain like youtube.com.'}), 400
        
        # Call the WHOIS lookup function
        result = get_whois_info(domain)
        
        if not result:
            return jsonify({'error': 'WHOIS lookup returned no data'}), 500
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 400
            
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/download-whois-pdf', methods=['POST'])
def download_whois_pdf():
    if not WEASYPRINT_AVAILABLE:
        return jsonify({'error': 'PDF generation is not available. WeasyPrint library is not properly configured.'}), 503
    
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400

        domain = normalize_domain_input(domain)
        if not domain:
            return jsonify({'error': 'Invalid domain format. Enter a valid domain like youtube.com.'}), 400
            
        # Get WHOIS information
        whois_data = get_whois_info(domain)
        
        if 'error' in whois_data:
            return jsonify({'error': whois_data['error']}), 400
            
        # Create HTML content for PDF
        html_content = f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                @page {{
                    margin: 2.5cm;
                    @top-right {{
                        content: "WHOIS Report";
                        font-size: 9pt;
                        color: #666;
                    }}
                    @bottom-center {{
                        content: "Page " counter(page) " of " counter(pages);
                        font-size: 9pt;
                        color: #666;
                    }}
                }}
                body {{ 
                    font-family: Arial, sans-serif;
                    color: #333;
                    line-height: 1.6;
                }}
                h1 {{ 
                    color: #1a237e; 
                    font-size: 24px; 
                    margin-bottom: 30px;
                    text-align: center;
                    border-bottom: 2px solid #1a237e;
                    padding-bottom: 10px;
                }}
                h2 {{ 
                    color: #1a237e; 
                    font-size: 18px; 
                    margin-top: 20px; 
                    margin-bottom: 15px; 
                    border-bottom: 2px solid #e3f2fd; 
                    padding-bottom: 5px;
                }}
                .section {{ 
                    margin-bottom: 20px;
                    page-break-inside: avoid;
                }}
                .field {{ 
                    margin-bottom: 10px;
                    padding: 5px;
                }}
                .field-name {{ 
                    font-weight: bold; 
                    color: #2c3e50;
                    display: inline-block;
                    width: 200px;
                }}
                .status-badge {{ 
                    display: inline-block; 
                    padding: 5px 10px; 
                    border-radius: 4px; 
                    font-weight: bold;
                }}
                .status-active {{ 
                    background: #d4edda; 
                    color: #155724;
                }}
                .status-inactive {{ 
                    background: #f8d7da; 
                    color: #721c24;
                }}
                .date-info {{ 
                    color: #495057;
                }}
                .contact-section {{ 
                    background: #f8f9fa; 
                    padding: 15px; 
                    border-radius: 8px; 
                    margin-top: 20px;
                }}
                .nameserver-list {{ 
                    list-style: none; 
                    padding-left: 0;
                }}
                .nameserver-item {{ 
                    background: #f8f9fa; 
                    padding: 8px; 
                    margin-bottom: 5px; 
                    border-radius: 4px; 
                    border-left: 3px solid #3498db;
                }}
            </style>
        </head>
        <body>
            <h1>WHOIS Report for {domain}</h1>
            
            <div class="section">
                <h2>Domain Information</h2>
                <div class="field">
                    <span class="field-name">Domain Name:</span> {whois_data['domainName']}{whois_data['domainNameExt']}
                </div>
                <div class="field">
                    <span class="field-name">Status:</span>
                    <span class="status-badge {'status-active' if 'active' in whois_data['status'].lower() else 'status-inactive'}">
                        {whois_data['status']}
                    </span>
                </div>
                <div class="field">
                    <span class="field-name">Domain Age:</span> {whois_data['estimatedDomainAge']}
                </div>
                <div class="field">
                    <span class="field-name">Contact Email:</span> {whois_data.get('contactEmail', 'N/A')}
                </div>
            </div>
            
            <div class="section">
                <h2>Important Dates</h2>
                <div class="field">
                    <span class="field-name">Created Date:</span> <span class="date-info">{whois_data['createdDate']}</span>
                </div>
                <div class="field">
                    <span class="field-name">Updated Date:</span> <span class="date-info">{whois_data['updatedDate']}</span>
                </div>
                <div class="field">
                    <span class="field-name">Expires Date:</span> <span class="date-info">{whois_data['expiresDate']}</span>
                </div>
            </div>
            
            <div class="section">
                <h2>Registrar Information</h2>
                <div class="field">
                    <span class="field-name">Registrar Name:</span> {whois_data['registrarName']}
                </div>
                <div class="field">
                    <span class="field-name">Registrar IANA ID:</span> {whois_data['registrarIANAID']}
                </div>
                <div class="field">
                    <span class="field-name">WHOIS Server:</span> {whois_data['whoisServer']}
                </div>
            </div>
        """
        
        # Add Name Servers section
        html_content += """
            <div class="section">
                <h2>Name Servers</h2>
        """
        if whois_data.get('nameServers'):
            html_content += "<ul class='nameserver-list'>"
            for ns in whois_data['nameServers']:
                html_content += f"""
                <li class="nameserver-item">{ns}</li>
                """
            html_content += "</ul>"
        else:
            html_content += "<div class='field'>No name servers found</div>"
        html_content += "</div>"
            
        # Add Registrant Information
        html_content += """
            <div class="section contact-section">
                <h2>Registrant Information</h2>
        """
        if whois_data.get('registrant'):
            for key, value in whois_data['registrant'].items():
                html_content += f"""
                <div class="field">
                    <span class="field-name">{key.replace('_', ' ').title()}:</span> {value}
                </div>
                """
        else:
            html_content += "<div class='field'>No registrant information available</div>"
        html_content += "</div>"
            
        # Add Administrative Contact
        html_content += """
            <div class="section contact-section">
                <h2>Administrative Contact</h2>
        """
        if whois_data.get('administrativeContact'):
            for key, value in whois_data['administrativeContact'].items():
                html_content += f"""
                <div class="field">
                    <span class="field-name">{key.replace('_', ' ').title()}:</span> {value}
                </div>
                """
        else:
            html_content += "<div class='field'>No administrative contact information available</div>"
        html_content += "</div>"
            
        # Add Technical Contact
        html_content += """
            <div class="section contact-section">
                <h2>Technical Contact</h2>
        """
        if whois_data.get('technicalContact'):
            for key, value in whois_data['technicalContact'].items():
                html_content += f"""
                <div class="field">
                    <span class="field-name">{key.replace('_', ' ').title()}:</span> {value}
                </div>
                """
        else:
            html_content += "<div class='field'>No technical contact information available</div>"
        html_content += "</div>"
            
        # Close HTML
        html_content += """
        </body>
        </html>
        """
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
            try:
                # Generate PDF using WeasyPrint
                HTML(string=html_content).write_pdf(tmp.name)
                
                # Send the file
                return send_file(
                    tmp.name,
                    as_attachment=True,
                    download_name=f'whois-report-{domain}.pdf',
                    mimetype='application/pdf'
                )
                
            except Exception as pdf_error:
                error_msg = str(pdf_error)
                print(f"PDF Generation Error: {error_msg}")
                return jsonify({'error': f'PDF Generation Error: {error_msg}'}), 500
            
    except Exception as e:
        error_msg = str(e)
        print(f"General Error: {error_msg}")
        return jsonify({'error': f'Error: {error_msg}'}), 500


@app.route('/api/dns-lookup', methods=['POST'])
def api_dns_lookup():
    try:
        data = request.get_json() or {}
        domain = data.get('domain')
        result = dns_lookup(domain)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/dns-lookup-pro', methods=['POST'])
@app.route('/api/dns-lookup-pro', methods=['POST'])
def api_dns_lookup_pro():
    try:
        data = request.get_json() or {}
        target = data.get('target') or data.get('domain')
        result = dns_lookup_pro(target)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/subdomain-scan', methods=['POST'])
def api_subdomain_scan():
    try:
        data = request.get_json() or {}
        domain = data.get('domain')
        result = subdomain_scan(domain)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/subdomain-finder-pro', methods=['POST'])
@app.route('/api/subdomain-finder-pro', methods=['POST'])
def api_subdomain_finder_pro():
    try:
        data = request.get_json() or {}
        target = data.get('target') or data.get('domain')
        scan_mode = data.get('scan_mode', 'standard')
        result = subdomain_finder_pro(target, scan_mode)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/port-scan', methods=['POST'])
def api_port_scan():
    try:
        data = request.get_json() or {}
        target = data.get('target')
        result = port_scan(target)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/service-detect', methods=['POST'])
def api_service_detect():
    try:
        data = request.get_json() or {}
        target = data.get('target')
        result = service_detection(target)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/advanced-scan', methods=['POST'])
@app.route('/api/advanced-scan', methods=['POST'])
def api_advanced_scan():
    try:
        data = request.get_json() or {}
        target = str(data.get('target', '')).strip()
        scan_type = str(data.get('scan_type', 'quick')).strip().lower()
        custom_range = str(data.get('custom_range', '')).strip()

        if not target:
            return jsonify({'error': 'Target is required.'}), 400

        # Lightweight anti-spam throttle per client (best effort)
        client = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')
        client = client.split(',')[0].strip()
        now = time.time()
        with _ADVANCED_SCAN_LOCK:
            last_seen = _ADVANCED_SCAN_LAST_REQUEST.get(client, 0)
            if now - last_seen < _ADVANCED_SCAN_MIN_INTERVAL_SECONDS:
                wait_for = int(_ADVANCED_SCAN_MIN_INTERVAL_SECONDS - (now - last_seen)) + 1
                return jsonify({
                    'error': f'Rate limit exceeded. Please wait {wait_for}s before scanning again.'
                }), 429
            _ADVANCED_SCAN_LAST_REQUEST[client] = now

        result = advanced_network_scan(target, scan_type, custom_range)
        if 'error' in result:
            return jsonify(result), 400

        # Save summary for history/debugging (best effort)
        try:
            scan_result = ScanResult(
                scan_type='advanced_network_scan',
                target=target,
                result=str({
                    'risk_level': result.get('risk_level'),
                    'open_ports': result.get('open_ports'),
                    'os_guess': result.get('os_guess'),
                })
            )
            db.session.add(scan_result)
            db.session.commit()
        except Exception:
            db.session.rollback()

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/header-analysis', methods=['POST'])
def api_header_analysis():
    try:
        data = request.get_json() or {}
        target = data.get('url') or data.get('target')
        result = http_header_audit(target)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/http-header-audit', methods=['POST'])
@app.route('/api/http-header-audit', methods=['POST'])
def api_http_header_audit():
    try:
        data = request.get_json() or {}
        target = data.get('target') or data.get('url')
        result = http_header_audit(target)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/tech-stack', methods=['POST'])
def api_tech_stack():
    try:
        data = request.get_json() or {}
        url = data.get('url')
        result = analyze_tech_stack(url)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/unified-recon', methods=['POST'])
@app.route('/api/unified-recon', methods=['POST'])
def api_unified_recon():
    try:
        data = request.get_json() or {}
        target = data.get('target') or data.get('domain') or data.get('url')
        scan_mode = data.get('scan_mode', 'standard')

        result = unified_recon_scan(target, scan_mode)
        if 'error' in result:
            return jsonify(result), 400

        # Save summary for traceability (best effort)
        try:
            scan_result = ScanResult(
                scan_type='unified_recon',
                target=str(result.get('target', target or '')),
                result=str({
                    'overall_score': result.get('overall_score'),
                    'grade': result.get('grade'),
                    'risk_level': result.get('risk_level'),
                    'scan_mode': result.get('scan_mode'),
                })
            )
            db.session.add(scan_result)
            db.session.commit()
        except Exception:
            db.session.rollback()

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/download-unified-recon-pdf', methods=['POST'])
def download_unified_recon_pdf():
    if not REPORTLAB_AVAILABLE:
        return jsonify({'error': 'PDF generation is not available. ReportLab library is not installed.'}), 503

    try:
        data = request.get_json() or {}
        result = data.get('result') if isinstance(data.get('result'), dict) else None

        if not result:
            target = data.get('target') or data.get('domain') or data.get('url')
            scan_mode = data.get('scan_mode', 'standard')
            result = unified_recon_scan(target, scan_mode)

        if not isinstance(result, dict):
            return jsonify({'error': 'Invalid scan result payload.'}), 400

        if 'error' in result:
            return jsonify(result), 400

        target = str(result.get('target', 'Unknown target'))
        scan_mode = str(result.get('scan_mode', 'standard')).upper()
        score = result.get('overall_score', 'N/A')
        grade = result.get('grade', 'N/A')
        risk_level = result.get('risk_level', 'N/A')
        summary = str(result.get('summary', ''))
        generated_at = str(result.get('generated_at', datetime.utcnow().isoformat()))

        highlights = result.get('highlights', {}) if isinstance(result.get('highlights'), dict) else {}
        issues = result.get('issues', []) if isinstance(result.get('issues'), list) else []
        findings = result.get('findings', []) if isinstance(result.get('findings'), list) else []
        recommendations = result.get('recommendations', []) if isinstance(result.get('recommendations'), list) else []
        modules = result.get('modules', {}) if isinstance(result.get('modules'), dict) else {}
        module_views = result.get('module_views', {}) if isinstance(result.get('module_views'), dict) else {}

        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = styles['Title']
        heading_style = styles['Heading2']
        body_style = styles['BodyText']

        story = []
        story.append(Paragraph('Unified Recon Scanner Report', title_style))
        story.append(Spacer(1, 0.2 * inch))

        summary_table = Table([
            ['Target', html.escape(target)],
            ['Scan Mode', html.escape(scan_mode)],
            ['Overall Score', html.escape(str(score))],
            ['Grade', html.escape(str(grade))],
            ['Risk Level', html.escape(str(risk_level))],
            ['Generated At', html.escape(generated_at)],
        ], colWidths=[130, 380])
        summary_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f7fb')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.15 * inch))

        story.append(Paragraph('Executive Summary', heading_style))
        story.append(Paragraph(html.escape(summary), body_style))
        story.append(Spacer(1, 0.12 * inch))

        story.append(Paragraph('Highlights', heading_style))
        highlights_rows = [
            ['Subdomains Found', html.escape(str(highlights.get('subdomains_found', 'N/A')))],
            ['Open Ports', html.escape(', '.join(str(p) for p in highlights.get('open_ports', [])[:20]) or 'None')],
            ['DNS Grade', html.escape(str(highlights.get('dns_grade', 'N/A')))],
            ['Header Grade', html.escape(str(highlights.get('header_grade', 'N/A')))],
            ['SSL Status', html.escape(str(highlights.get('ssl_status', 'N/A')))],
            ['Technologies', html.escape(', '.join(highlights.get('tech', [])[:10]) or 'N/A')],
        ]
        highlights_table = Table(highlights_rows, colWidths=[130, 380])
        highlights_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f7fb')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(highlights_table)
        story.append(Spacer(1, 0.12 * inch))

        story.append(Paragraph('Top Findings', heading_style))
        if findings:
            for finding in findings[:5]:
                if not isinstance(finding, dict):
                    continue
                sev = html.escape(str(finding.get('severity', 'Low')))
                title = html.escape(str(finding.get('title', 'Unnamed finding')))
                detail = html.escape(str(finding.get('detail', '')))
                points = html.escape(str(finding.get('points', '')))
                line = f'• [{sev}] {title}'
                if points:
                    line += f' (impact {points})'
                story.append(Paragraph(line, body_style))
                if detail:
                    story.append(Paragraph(f'  {detail}', body_style))
        elif issues:
            for issue in issues[:5]:
                story.append(Paragraph(f'• {html.escape(str(issue))}', body_style))
        else:
            story.append(Paragraph('• No significant findings.', body_style))
        story.append(Spacer(1, 0.1 * inch))

        story.append(Paragraph('Priority Recommendations', heading_style))
        if recommendations:
            for rec in recommendations[:8]:
                story.append(Paragraph(f'• {html.escape(str(rec))}', body_style))
        else:
            story.append(Paragraph('• No immediate action required.', body_style))
        story.append(Spacer(1, 0.12 * inch))

        story.append(Paragraph('Module Intelligence Summary', heading_style))
        module_summary_rows = [['Module', 'Key Summary']]

        dns_view = module_views.get('dns', {}) if isinstance(module_views.get('dns'), dict) else {}
        if dns_view:
            dns_line = (
                f"Grade {dns_view.get('dns_grade', 'N/A')}, "
                f"DNSSEC {'Enabled' if dns_view.get('dnssec_enabled') else 'Disabled'}, "
                f"SPF {dns_view.get('spf_status', 'N/A')}, DMARC {dns_view.get('dmarc_policy', 'N/A')}"
            )
            module_summary_rows.append(['DNS Intelligence', html.escape(dns_line)])

        sub_view = module_views.get('subdomains', {}) if isinstance(module_views.get('subdomains'), dict) else {}
        if sub_view:
            sub_line = (
                f"Total {sub_view.get('total_found', 0)}, "
                f"Live {sub_view.get('live_hosts', 0)}, "
                f"High-Risk {sub_view.get('high_risk_hosts', 0)}"
            )
            module_summary_rows.append(['Subdomain Discovery', html.escape(sub_line)])

        header_view = module_views.get('headers', {}) if isinstance(module_views.get('headers'), dict) else {}
        if header_view:
            header_line = (
                f"Grade {header_view.get('header_grade', 'N/A')}, "
                f"Missing headers {len(header_view.get('missing_security_headers', []) or [])}, "
                f"HSTS {header_view.get('hsts_status', 'N/A')}"
            )
            module_summary_rows.append(['HTTP Header Audit', html.escape(header_line)])

        ssl_view = module_views.get('ssl', {}) if isinstance(module_views.get('ssl'), dict) else {}
        if ssl_view:
            ssl_line = (
                f"{'Valid' if ssl_view.get('valid') else 'Invalid'}, "
                f"Issuer {ssl_view.get('issuer', 'N/A')}, "
                f"Expires in {ssl_view.get('expires_in_days', 'N/A')} days"
            )
            module_summary_rows.append(['SSL Certificate', html.escape(ssl_line)])

        ports_view = module_views.get('ports', {}) if isinstance(module_views.get('ports'), dict) else {}
        if ports_view:
            ports_line = (
                f"Open ports {ports_view.get('open_ports_count', 0)}, "
                f"Risky ports {ports_view.get('risky_ports_count', 0)}"
            )
            module_summary_rows.append(['Port Exposure', html.escape(ports_line)])

        tech_view = module_views.get('tech', {}) if isinstance(module_views.get('tech'), dict) else {}
        if tech_view:
            tech_line = (
                f"Frameworks {len(tech_view.get('frameworks', []) or [])}, "
                f"CMS {len(tech_view.get('cms', []) or [])}, "
                f"CDN {len(tech_view.get('cdn', []) or [])}"
            )
            module_summary_rows.append(['Technology Fingerprint', html.escape(tech_line)])

        whois_view = module_views.get('whois', {}) if isinstance(module_views.get('whois'), dict) else {}
        if whois_view:
            whois_line = (
                f"Registrar {whois_view.get('registrar', 'N/A')}, "
                f"Age {whois_view.get('domain_age_days', 'N/A')} days, "
                f"Expiry {whois_view.get('expiry_date', 'N/A')}"
            )
            module_summary_rows.append(['WHOIS Intelligence', html.escape(whois_line)])

        if len(module_summary_rows) > 1:
            module_summary_table = Table(module_summary_rows, colWidths=[130, 380])
            module_summary_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e3ecfb')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(module_summary_table)
            story.append(Spacer(1, 0.12 * inch))

        story.append(Paragraph('Module Status', heading_style))
        module_rows = [['Module', 'Status', 'Duration (ms)', 'Error']]
        for module_name, module_info in modules.items():
            if not isinstance(module_info, dict):
                continue
            module_rows.append([
                html.escape(str(module_name)),
                'OK' if module_info.get('ok') else 'FAILED',
                html.escape(str(module_info.get('duration_ms', 0))),
                html.escape(str(module_info.get('error', '') or '-')),
            ])

        module_table = Table(module_rows, colWidths=[95, 60, 80, 275])
        module_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e3ecfb')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(module_table)

        doc.build(story)
        pdf_buffer.seek(0)
        safe_name = re.sub(r'[^a-zA-Z0-9._-]+', '-', target)
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f'unified-recon-{safe_name}.pdf',
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/email-analyzer', methods=['POST'])
def api_email_analyzer():
    try:
        data = request.get_json() or {}
        raw_header = data.get('raw_header')
        result = analyze_email_header(raw_header)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/email-analyzer-advanced', methods=['POST'])
def api_email_analyzer_advanced():
    try:
        data = request.get_json() or {}
        raw_header = data.get('raw_header')
        result = analyze_email_header_advanced(raw_header)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/download-email-analysis-pdf', methods=['POST'])
def download_email_analysis_pdf():
    if not REPORTLAB_AVAILABLE:
        return jsonify({'error': 'PDF generation is not available. ReportLab library is not installed.'}), 503

    try:
        data = request.get_json() or {}
        raw_header = data.get('raw_header')
        result = analyze_email_header_advanced(raw_header)
        if 'error' in result:
            return jsonify(result), 400

        basic = result.get('basic_info', {})
        auth = result.get('authentication', {})
        spoofing_checks = result.get('spoofing_checks', [])
        ip_route = result.get('ip_route', [])
        ip_analysis = result.get('ip_analysis', [])
        phishing_indicators = result.get('phishing_indicators', [])
        issues = result.get('issues', [])
        risk_level = result.get('risk_level', 'LOW')
        risk_score = result.get('risk_score', 0)
        delay = result.get('time_delay_analysis', {})
        domain_analysis = result.get('domain_analysis', '')

        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = styles["Title"]
        heading_style = styles["Heading2"]
        body_style = styles["BodyText"]
        mono_style = ParagraphStyle(
            "Mono",
            parent=body_style,
            fontName="Courier",
            fontSize=9,
            leading=12,
        )

        story = []
        story.append(Paragraph("Email Forensics & Threat Analysis Report", title_style))
        story.append(Spacer(1, 0.2 * inch))

        def add_heading(text):
            story.append(Paragraph(text, heading_style))
            story.append(Spacer(1, 0.08 * inch))

        def add_kv_rows(rows):
            table = Table([[Paragraph(f"<b>{k}</b>", body_style), Paragraph(html.escape(str(v)), body_style)] for k, v in rows], colWidths=[150, 360])
            table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f7fb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(table)
            story.append(Spacer(1, 0.12 * inch))

        def add_bullets(items):
            if not items:
                story.append(Paragraph("• None", body_style))
            else:
                for item in items:
                    story.append(Paragraph(f"• {html.escape(str(item))}", body_style))
            story.append(Spacer(1, 0.10 * inch))

        add_heading("Basic Information")
        add_kv_rows([
            ("From", basic.get("from", "")),
            ("To", basic.get("to", "")),
            ("Subject", basic.get("subject", "")),
            ("Date", basic.get("date", "")),
            ("Return-Path", basic.get("return_path", "")),
            ("Reply-To", basic.get("reply_to", "")),
            ("Message-ID", basic.get("message_id", "")),
        ])

        add_heading("Authentication")
        add_kv_rows([
            ("SPF", auth.get("spf", "missing")),
            ("DKIM", auth.get("dkim", "missing")),
            ("DMARC", auth.get("dmarc", "missing")),
            ("SPF Domain", auth.get("spf_domain", "")),
            ("DKIM d=", auth.get("dkim_domain", "")),
        ])

        add_heading("Spoofing Checks")
        add_bullets(spoofing_checks)

        add_heading("Email Route")
        route_text = " -> ".join(ip_route) if ip_route else "No route IPs found"
        story.append(Paragraph(html.escape(route_text), mono_style))
        story.append(Spacer(1, 0.12 * inch))

        add_heading("IP Reputation Analysis")
        ip_rows = [["IP", "Status", "Malicious Vendors", "Suspicious Vendors"]]
        if ip_analysis:
            for row in ip_analysis:
                ip_rows.append([
                    html.escape(str(row.get("ip", "-"))),
                    html.escape(str(row.get("status", "-"))),
                    str(row.get("malicious_count", "-")),
                    str(row.get("suspicious_count", "-")),
                ])
        else:
            ip_rows.append(["-", "No IP analysis available", "-", "-"])
        ip_table = Table(ip_rows, colWidths=[120, 170, 120, 120])
        ip_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf0fb")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ip_table)
        story.append(Spacer(1, 0.12 * inch))

        add_heading("Phishing Indicators")
        add_bullets(phishing_indicators)
        story.append(Paragraph(html.escape(str(domain_analysis)), body_style))
        story.append(Spacer(1, 0.12 * inch))

        add_heading("Time Delay Analysis")
        add_kv_rows([
            ("Hop Delays (s)", delay.get("hop_delays_seconds", [])),
            ("Max Delay (s)", delay.get("max_delay_seconds", 0)),
            ("Notes", delay.get("notes", "")),
        ])

        add_heading("Issues")
        add_bullets(issues)

        add_heading("Overall Risk")
        risk_color = colors.HexColor("#155724")
        risk_bg = colors.HexColor("#d4edda")
        if risk_level == "MEDIUM":
            risk_color = colors.HexColor("#856404")
            risk_bg = colors.HexColor("#fff3cd")
        elif risk_level == "HIGH":
            risk_color = colors.HexColor("#721c24")
            risk_bg = colors.HexColor("#f8d7da")
        risk_table = Table(
            [[f"{risk_level} (Score: {risk_score}/100)"]],
            colWidths=[510],
        )
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), risk_bg),
            ("TEXTCOLOR", (0, 0), (0, 0), risk_color),
            ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (0, 0), 12),
            ("LEFTPADDING", (0, 0), (0, 0), 8),
            ("RIGHTPADDING", (0, 0), (0, 0), 8),
            ("TOPPADDING", (0, 0), (0, 0), 8),
            ("BOTTOMPADDING", (0, 0), (0, 0), 8),
        ]))
        story.append(risk_table)

        doc.build(story)
        pdf_buffer.seek(0)
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name='email-threat-analysis-report.pdf',
            mimetype='application/pdf',
        )
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 
