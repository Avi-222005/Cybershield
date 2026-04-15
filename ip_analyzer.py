"""
Hybrid IP Analysis Engine
==========================
A comprehensive IP reputation and threat intelligence system combining custom analysis 
with threat intelligence APIs.

Architecture:
1. IPValidator - Validates IP format and rejects private/reserved addresses
2. CustomRiskAnalyzer - Analyzes IP characteristics and assigns custom risk score
3. ThreatIntelligenceMapper - Maps API vendor verdicts to numeric scores
4. HybridScoringEngine - Combines custom (40%) and API (60%) scores for final verdict

Author: CyberShield Security Team
"""

import ipaddress
import json
import os
import re
from typing import Dict, Tuple, List, Optional


# Load configuration
def load_config():
    """Load risk analysis configuration from JSON file."""
    config_path = os.path.join(os.path.dirname(__file__), 'config', 'risk_analysis_config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Fallback to default config if file doesn't exist
        return {
            "hosting_providers": ["aws", "amazon", "google cloud", "azure", "digitalocean", "ovh", "linode", "vultr", "hetzner"],
            "vpn_keywords": ["vpn", "proxy", "tunnel", "anonymous", "hide", "private"],
            "high_risk_countries": ["Unknown", "N/A"],
            "suspicious_isp_patterns": ["unknown", "none", "n/a", "unavailable"],
            "unusual_connection_types": ["dialup", "satellite"],
            "risk_points": {
                "hosting_provider": 15,
                "vpn_proxy_isp": 30,
                "vpn_proxy_connection": 25,
                "unknown_location": 10,
                "unknown_isp": 5,
                "unusual_connection": 5
            },
            "weighting": {
                "custom_score_weight": 0.4,
                "api_score_weight": 0.6
            },
            "severity_thresholds": {
                "low_max": 39,
                "medium_max": 69,
                "high_min": 70
            },
            "api_score_cap": 70
        }

# Load config at module level for performance
CONFIG = load_config()


class IPValidator:
    """
    Validates IP addresses and filters out private, loopback, and reserved ranges.
    
    This class ensures only legitimate public IPs are analyzed, preventing
    abuse of the system for internal network scanning.
    """
    
    @staticmethod
    def validate_ip(ip: str) -> Dict:
        """
        Validate IP address format and check if it's a public IP.
        
        Args:
            ip (str): IP address string to validate
            
        Returns:
            Dict: Validation result with status, is_valid, ip_version, and reason
        """
        try:
            # Parse IP address
            ip_obj = ipaddress.ip_address(ip)
            
            # Determine IP version
            ip_version = f"IPv{ip_obj.version}"
            
            # Check if IP is private, loopback, reserved, or multicast
            if ip_obj.is_private:
                return {
                    'is_valid': False,
                    'ip_version': ip_version,
                    'reason': 'Private IP address - not routable on the internet',
                    'category': 'private'
                }
            
            if ip_obj.is_loopback:
                return {
                    'is_valid': False,
                    'ip_version': ip_version,
                    'reason': 'Loopback address - refers to local machine',
                    'category': 'loopback'
                }
            
            if ip_obj.is_reserved:
                return {
                    'is_valid': False,
                    'ip_version': ip_version,
                    'reason': 'Reserved IP address - not available for public use',
                    'category': 'reserved'
                }
            
            if ip_obj.is_multicast:
                return {
                    'is_valid': False,
                    'ip_version': ip_version,
                    'reason': 'Multicast address - used for group communication',
                    'category': 'multicast'
                }
            
            if ip_obj.is_link_local:
                return {
                    'is_valid': False,
                    'ip_version': ip_version,
                    'reason': 'Link-local address - only valid on local network segment',
                    'category': 'link_local'
                }
            
            # Valid public IP
            return {
                'is_valid': True,
                'ip_version': ip_version,
                'reason': 'Valid public IP address',
                'category': 'public'
            }
            
        except ValueError:
            return {
                'is_valid': False,
                'ip_version': 'unknown',
                'reason': 'Invalid IP address format',
                'category': 'invalid'
            }


class CustomRiskAnalyzer:
    """
    Analyzes IP characteristics using custom logic to identify risk indicators.
    
    This analyzer looks for patterns that suggest malicious activity, anonymization,
    or suspicious hosting characteristics without relying on external APIs.
    """
    
    def __init__(self, ip: str, geolocation_data: Dict):
        """
        Initialize analyzer with IP and geolocation data.
        
        Args:
            ip (str): IP address to analyze
            geolocation_data (Dict): Geolocation information from API
        """
        self.ip = ip
        self.geo = geolocation_data
        self.risk_factors = []
        self.risk_score = 0
        
    def analyze(self) -> Dict:
        """
        Perform comprehensive custom risk analysis.
        
        Returns:
            Dict: Analysis results with risk_score, risk_factors, and risk_level
        """
        # Check various risk indicators
        self._check_hosting_provider()
        self._check_vpn_proxy_indicators()
        self._check_geolocation_anomalies()
        self._check_isp_characteristics()
        self._check_connection_type()
        
        # Calculate final custom risk score (0-100)
        self._calculate_risk_score()
        
        # Determine risk level
        risk_level = self._determine_risk_level()
        
        return {
            'custom_score': self.risk_score,
            'risk_factors': self.risk_factors,
            'risk_level': risk_level,
            'analysis_summary': f'Custom analysis identified {len(self.risk_factors)} risk indicator(s)'
        }
    
    def _check_hosting_provider(self):
        """Check if IP belongs to hosting/cloud provider."""
        isp = str(self.geo.get('isp', '')).lower()
        
        for provider in CONFIG['hosting_providers']:
            if provider in isp:
                self.risk_factors.append({
                    'indicator': 'Hosting Provider',
                    'severity': 'medium',
                    'description': f'IP belongs to hosting provider: {self.geo.get("isp")}',
                    'risk_points': CONFIG['risk_points']['hosting_provider']
                })
                return
    
    def _check_vpn_proxy_indicators(self):
        """Check for VPN/Proxy/Tor indicators in ISP name."""
        isp = str(self.geo.get('isp', '')).lower()
        
        for keyword in CONFIG['vpn_keywords']:
            if keyword in isp:
                self.risk_factors.append({
                    'indicator': 'VPN/Proxy/Anonymizer',
                    'severity': 'high',
                    'description': f'Possible VPN/Proxy detected in ISP name: {self.geo.get("isp")}',
                    'risk_points': CONFIG['risk_points']['vpn_proxy_isp']
                })
                return
        
        # Check connection type
        conn_type = str(self.geo.get('connection_type', '')).lower()
        if 'proxy' in conn_type or 'vpn' in conn_type:
            self.risk_factors.append({
                'indicator': 'Anonymous Connection',
                'severity': 'high',
                'description': f'Anonymous connection type detected: {conn_type}',
                'risk_points': CONFIG['risk_points']['vpn_proxy_connection']
            })
    
    def _check_geolocation_anomalies(self):
        """Check for suspicious geolocation patterns."""
        country = self.geo.get('country', '')
        
        if country in CONFIG['high_risk_countries'] or not country:
            self.risk_factors.append({
                'indicator': 'Unknown Location',
                'severity': 'medium',
                'description': 'IP geolocation could not be determined',
                'risk_points': CONFIG['risk_points']['unknown_location']
            })
    
    def _check_isp_characteristics(self):
        """Analyze ISP characteristics for suspicious patterns."""
        isp = str(self.geo.get('isp', '')).lower()
        
        for pattern in CONFIG['suspicious_isp_patterns']:
            if pattern in isp:
                self.risk_factors.append({
                    'indicator': 'Unknown ISP',
                    'severity': 'low',
                    'description': 'ISP information unavailable or unknown',
                    'risk_points': CONFIG['risk_points']['unknown_isp']
                })
                return
    
    def _check_connection_type(self):
        """Check connection type for suspicious characteristics."""
        conn_type = str(self.geo.get('connection_type', '')).lower()
        
        for conn in CONFIG['unusual_connection_types']:
            if conn in conn_type:
                self.risk_factors.append({
                    'indicator': 'Unusual Connection',
                    'severity': 'low',
                    'description': f'Uncommon connection type: {conn.capitalize()}',
                    'risk_points': CONFIG['risk_points']['unusual_connection']
                })
                break
    
    def _calculate_risk_score(self):
        """Calculate total custom risk score from all factors."""
        total_points = sum(factor['risk_points'] for factor in self.risk_factors)
        
        # Cap at 100
        self.risk_score = min(total_points, 100)
    
    def _determine_risk_level(self) -> str:
        """Determine risk level based on score."""
        if self.risk_score >= 50:
            return 'high'
        elif self.risk_score >= 25:
            return 'medium'
        else:
            return 'low'


class ThreatIntelligenceMapper:
    """
    Maps threat intelligence API responses to numeric scores.
    
    Processes vendor verdicts from VirusTotal or similar APIs and converts
    them into a standardized numeric risk score.
    """
    
    @staticmethod
    def map_api_response(api_status: str, api_details: str, vendor_data: Dict) -> Dict:
        """
        Map API vendor verdicts to risk score.
        
        Scoring logic:
        - Each malicious verdict: +10 points
        - Each suspicious verdict: +5 points
        - Cap at 70 points (60% of total possible score)
        
        Args:
            api_status (str): Overall API status (SAFE/SUSPICIOUS/MALICIOUS)
            api_details (str): Detailed API response text
            vendor_data (Dict): Vendor analysis data
            
        Returns:
            Dict: API score, threat categories, and vendor summary
        """
        api_score = 0
        threat_categories = []
        
        # Extract vendor counts
        malicious_count = vendor_data.get('malicious_count', 0)
        suspicious_count = vendor_data.get('suspicious_count', 0)
        clean_count = vendor_data.get('clean_count', 0)
        
        # Calculate score based on vendor verdicts
        api_score = (malicious_count * 10) + (suspicious_count * 5)
        
        # Cap at configured maximum
        api_score = min(api_score, CONFIG['api_score_cap'])
        
        # Extract threat categories from vendor data
        if vendor_data.get('malicious_vendors'):
            threat_categories.append('Malicious Activity')
        if vendor_data.get('suspicious_vendors'):
            threat_categories.append('Suspicious Behavior')
        
        # Parse details for specific threat types
        details_lower = api_details.lower()
        if 'spam' in details_lower:
            threat_categories.append('Spam')
        if 'botnet' in details_lower or 'bot' in details_lower:
            threat_categories.append('Botnet')
        if 'brute' in details_lower or 'bruteforce' in details_lower:
            threat_categories.append('Brute Force')
        if 'malware' in details_lower:
            threat_categories.append('Malware')
        if 'scan' in details_lower or 'scanner' in details_lower:
            threat_categories.append('Port Scanning')
        if 'ddos' in details_lower:
            threat_categories.append('DDoS')
        
        return {
            'api_score': api_score,
            'threat_categories': list(set(threat_categories)),  # Remove duplicates
            'vendor_summary': {
                'malicious': malicious_count,
                'suspicious': suspicious_count,
                'clean': clean_count,
                'total_analyzed': malicious_count + suspicious_count + clean_count
            }
        }


class HybridScoringEngine:
    """
    Combines custom analysis (40%) with API intelligence (60%) for final verdict.
    
    This engine implements weighted scoring to balance internal custom analysis
    with external threat intelligence, ensuring neither source dominates the decision.
    """
    
    @staticmethod
    def calculate_final_score(custom_score: int, api_score: int) -> Dict:
        """
        Calculate weighted final risk score.
        
        Formula: final_score = (custom_weight × custom_score) + (api_weight × api_score)
        
        Args:
            custom_score (int): Custom analysis score (0-100)
            api_score (int): API intelligence score (0-70, mapped to 0-100)
            
        Returns:
            Dict: Final score, severity, and score breakdown
        """
        # Get weights from config
        custom_weight = CONFIG['weighting']['custom_score_weight']
        api_weight = CONFIG['weighting']['api_score_weight']
        
        # Normalize API score to 0-100 scale for weighting
        normalized_api_score = (api_score / CONFIG['api_score_cap']) * 100 if api_score > 0 else 0
        
        # Calculate weighted final score
        final_score = (
            (custom_weight * custom_score) +
            (api_weight * normalized_api_score)
        )
        
        # Round to integer
        final_score = round(final_score)
        
        # Determine severity
        severity = HybridScoringEngine._classify_severity(final_score)
        
        # Determine verdict
        verdict = HybridScoringEngine._determine_verdict(final_score)
        
        return {
            'final_score': final_score,
            'severity': severity,
            'verdict': verdict,
            'score_breakdown': {
                'custom_score': custom_score,
                'custom_weight': f'{int(custom_weight * 100)}%',
                'api_score': api_score,
                'api_weight': f'{int(api_weight * 100)}%',
                'calculation': f'({custom_weight} × {custom_score}) + ({api_weight} × {normalized_api_score:.0f}) = {final_score}'
            }
        }
    
    @staticmethod
    def _classify_severity(score: int) -> str:
        """
        Classify severity based on final score.
        
        Uses thresholds from config:
        - Low: 0 to low_max
        - Medium: low_max+1 to medium_max
        - High: medium_max+1 to 100
        """
        thresholds = CONFIG['severity_thresholds']
        if score >= thresholds['high_min']:
            return 'High'
        elif score > thresholds['low_max']:
            return 'Medium'
        else:
            return 'Low'
    
    @staticmethod
    def _determine_verdict(score: int) -> str:
        """Determine overall verdict based on score."""
        if score >= 70:
            return 'MALICIOUS'
        elif score >= 40:
            return 'SUSPICIOUS'
        else:
            return 'SAFE'


class RecommendationEngine:
    """
    Generates security recommendations based on risk analysis results.
    
    Provides actionable guidance for security teams on how to handle
    the analyzed IP address.
    """
    
    @staticmethod
    def generate_recommendation(severity: str, verdict: str, threat_categories: List[str]) -> str:
        """
        Generate security recommendation based on analysis results.
        
        Args:
            severity (str): Risk severity level (Low/Medium/High)
            verdict (str): Overall verdict (SAFE/SUSPICIOUS/MALICIOUS)
            threat_categories (List[str]): Identified threat types
            
        Returns:
            str: Detailed security recommendation
        """
        if severity == 'High':
            recommendation = "⚠️ HIGH RISK - IMMEDIATE ACTION REQUIRED\n\n"
            recommendation += "• Block this IP address immediately at firewall/WAF level\n"
            recommendation += "• Monitor all traffic from this IP in logs\n"
            recommendation += "• Check for any successful connections in the past 24-48 hours\n"
            recommendation += "• Review and update security rules to prevent similar threats\n"
            
            if threat_categories:
                recommendation += f"\n🎯 Identified Threats: {', '.join(threat_categories)}\n"
            
            recommendation += "\n📋 Recommended Actions:\n"
            recommendation += "1. Add IP to blacklist/blocklist\n"
            recommendation += "2. Enable enhanced logging for this IP range\n"
            recommendation += "3. Alert security team for investigation\n"
            recommendation += "4. Consider reporting to abuse contacts"
            
        elif severity == 'Medium':
            recommendation = "⚡ MEDIUM RISK - MONITORING REQUIRED\n\n"
            recommendation += "• Monitor activity from this IP address closely\n"
            recommendation += "• Apply rate limiting to prevent abuse\n"
            recommendation += "• Enable detailed logging for this IP\n"
            recommendation += "• Consider temporary restrictions if suspicious patterns emerge\n"
            
            if threat_categories:
                recommendation += f"\n🎯 Potential Threats: {', '.join(threat_categories)}\n"
            
            recommendation += "\n📋 Recommended Actions:\n"
            recommendation += "1. Add to monitoring watchlist\n"
            recommendation += "2. Apply rate limiting (e.g., max 100 req/min)\n"
            recommendation += "3. Enable CAPTCHA for suspicious activity\n"
            recommendation += "4. Review logs periodically"
            
        else:
            recommendation = "✅ LOW RISK - NO IMMEDIATE ACTION REQUIRED\n\n"
            recommendation += "• This IP appears to be legitimate based on current analysis\n"
            recommendation += "• Continue standard monitoring practices\n"
            recommendation += "• No special restrictions necessary at this time\n"
            recommendation += "• Keep standard security measures in place\n"
            
            recommendation += "\n📋 Best Practices:\n"
            recommendation += "1. Maintain normal traffic monitoring\n"
            recommendation += "2. Keep standard rate limits active\n"
            recommendation += "3. Continue regular log reviews\n"
            recommendation += "4. Update threat intelligence feeds regularly"
        
        return recommendation


def analyze_ip_hybrid(ip: str, api_status: str, api_details: str, 
                      vendor_data: Dict, geolocation_data: Dict) -> Dict:
    """
    Main function: Perform hybrid IP analysis combining custom logic with API intelligence.
    
    This function orchestrates the entire analysis pipeline:
    1. Validate IP address
    2. Run custom risk analysis
    3. Map API response to score
    4. Calculate weighted final score
    5. Generate recommendation
    
    Args:
        ip (str): IP address to analyze
        api_status (str): API verdict (SAFE/SUSPICIOUS/MALICIOUS)
        api_details (str): Detailed API response
        vendor_data (Dict): Vendor analysis from API
        geolocation_data (Dict): Geolocation information
        
    Returns:
        Dict: Comprehensive analysis results
    """
    # Step 1: Validate IP
    validation = IPValidator.validate_ip(ip)
    
    if not validation['is_valid']:
        return {
            'ip': ip,
            'valid': False,
            'validation_error': validation['reason'],
            'category': validation['category'],
            'verdict': 'INVALID',
            'final_score': 0,
            'severity': 'N/A',
            'recommendation': 'Cannot analyze - IP address is not a valid public IP.'
        }
    
    # Step 2: Custom Risk Analysis (40% weight)
    custom_analyzer = CustomRiskAnalyzer(ip, geolocation_data)
    custom_analysis = custom_analyzer.analyze()
    
    # Step 3: Map API Response (60% weight)
    api_analysis = ThreatIntelligenceMapper.map_api_response(
        api_status, api_details, vendor_data
    )
    
    # Step 4: Calculate Final Weighted Score
    scoring_result = HybridScoringEngine.calculate_final_score(
        custom_analysis['custom_score'],
        api_analysis['api_score']
    )
    
    # Step 5: Generate Recommendation
    recommendation = RecommendationEngine.generate_recommendation(
        scoring_result['severity'],
        scoring_result['verdict'],
        api_analysis['threat_categories']
    )
    
    # Step 6: Compile comprehensive result
    final_result = {
        # IP Information
        'ip': ip,
        'valid': True,
        'ip_version': validation['ip_version'],
        
        # Scoring Results
        'verdict': scoring_result['verdict'],
        'final_score': scoring_result['final_score'],
        'severity': scoring_result['severity'],
        
        # Score Breakdown
        'score_breakdown': scoring_result['score_breakdown'],
        'custom_analysis': {
            'score': custom_analysis['custom_score'],
            'risk_level': custom_analysis['risk_level'],
            'risk_factors': custom_analysis['risk_factors'],
            'summary': custom_analysis['analysis_summary']
        },
        'api_analysis': {
            'score': api_analysis['api_score'],
            'threat_categories': api_analysis['threat_categories'],
            'vendor_summary': api_analysis['vendor_summary']
        },
        
        # Geolocation
        'geolocation': geolocation_data,
        
        # Vendor Data
        'vendor_data': vendor_data,
        
        # Recommendation
        'security_recommendation': recommendation,
        
        # Detection Reasons (combined from custom + API)
        'detection_reasons': [
            f"Custom Analysis: {custom_analysis['analysis_summary']}",
            *[f"• {factor['indicator']}: {factor['description']}" for factor in custom_analysis['risk_factors']],
            f"API Intelligence: {api_analysis['vendor_summary']['total_analyzed']} vendors analyzed",
            *[f"• {category}" for category in api_analysis['threat_categories']]
        ]
    }
    
    return final_result
