"""
Hybrid Phishing Detection System
==================================
A modular phishing detection system combining custom URL analysis with threat intelligence API.

Architecture:
1. URLFeatureExtractor - Extracts phishing indicators from URLs
2. PhishingScorer - Calculates risk scores based on features
3. ThreatIntelligenceMapper - Maps API responses to numeric scores
4. HybridDecisionEngine - Combines custom and API scores for final verdict

Author: CyberShield Security Team
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional


class URLFeatureExtractor:
    """
    Extracts security-relevant features from URLs for phishing detection.
    
    This class analyzes various URL characteristics that are commonly
    associated with phishing attempts, including structural anomalies,
    suspicious keywords, and security indicator misuse.
    """
    
    # Suspicious keywords commonly used in phishing attacks
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'update', 'confirm', 'secure', 'account',
        'bank', 'payment', 'billing', 'credential', 'suspend', 'locked',
        'validate', 'authenticate', 'security', 'alert', 'urgent', 'action',
        'required', 'expire', 'click', 'here', 'now', 'immediately'
    ]
    
    # High-risk TLDs often used in phishing
    HIGH_RISK_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
        '.click', '.link', '.download', '.loan', '.win', '.bid'
    ]
    
    # Trusted brand names often spoofed in phishing
    BRAND_KEYWORDS = [
        'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
        'facebook', 'instagram', 'twitter', 'linkedin', 'ebay', 'walmart',
        'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'dhl', 'fedex',
        'usps', 'irs', 'uscis', 'dropbox', 'adobe'
    ]
    
    def __init__(self, url: str):
        """
        Initialize the feature extractor with a URL.
        
        Args:
            url (str): The URL to analyze
        """
        self.url = url.lower()
        self.parsed_url = urlparse(url)
        self.features = {}
        
    def extract_all_features(self) -> Dict:
        """
        Extract all security features from the URL.
        
        Returns:
            Dict: Dictionary containing all extracted features
        """
        self.features = {
            'url_length': self._check_url_length(),
            'has_ip_address': self._check_ip_address(),
            'subdomain_count': self._count_subdomains(),
            'special_char_count': self._count_special_characters(),
            'suspicious_keywords': self._find_suspicious_keywords(),
            'https_misuse': self._check_https_misuse(),
            'url_shortener': self._check_url_shortener(),
            'high_risk_tld': self._check_high_risk_tld(),
            'excessive_dots': self._check_excessive_dots(),
            'brand_spoofing': self._check_brand_spoofing(),
            'punycode_domain': self._check_punycode(),
            'path_depth': self._check_path_depth(),
            'raw_url': self.url,
            'domain': self.parsed_url.netloc
        }
        return self.features
    
    def _check_url_length(self) -> Dict:
        """
        Check if URL length is suspicious.
        Long URLs are often used to hide malicious intent.
        
        Returns:
            Dict: Length analysis with risk flag
        """
        length = len(self.url)
        is_suspicious = length > 75
        risk_level = 'high' if length > 100 else 'medium' if length > 75 else 'low'
        
        return {
            'length': length,
            'is_suspicious': is_suspicious,
            'risk_level': risk_level,
            'reason': f'URL length is {length} characters' + (' (suspiciously long)' if is_suspicious else '')
        }
    
    def _check_ip_address(self) -> Dict:
        """
        Check if domain uses IP address instead of domain name.
        Using IP addresses directly is a common phishing tactic.
        
        Returns:
            Dict: IP address detection result
        """
        # IPv4 pattern
        ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^\[?[0-9a-f:]+\]?$'
        
        domain = self.parsed_url.netloc.split(':')[0]  # Remove port if present
        
        is_ip = bool(re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain))
        
        return {
            'is_ip_address': is_ip,
            'risk_level': 'high' if is_ip else 'low',
            'reason': 'Domain uses IP address instead of domain name' if is_ip else 'Domain uses proper domain name'
        }
    
    def _count_subdomains(self) -> Dict:
        """
        Count the number of subdomains in the URL.
        Excessive subdomains can indicate phishing attempts.
        
        Returns:
            Dict: Subdomain analysis
        """
        domain = self.parsed_url.netloc.split(':')[0]
        parts = domain.split('.')
        
        # Subtract 2 for typical domain.tld structure
        subdomain_count = max(0, len(parts) - 2)
        
        is_suspicious = subdomain_count > 2
        risk_level = 'high' if subdomain_count > 3 else 'medium' if subdomain_count > 2 else 'low'
        
        return {
            'count': subdomain_count,
            'is_suspicious': is_suspicious,
            'risk_level': risk_level,
            'reason': f'{subdomain_count} subdomain(s) detected' + (' (excessive)' if is_suspicious else '')
        }
    
    def _count_special_characters(self) -> Dict:
        """
        Count suspicious special characters in the URL.
        Characters like @, -, _ in unusual quantities can indicate phishing.
        
        Returns:
            Dict: Special character analysis
        """
        at_count = self.url.count('@')
        hyphen_count = self.url.count('-')
        underscore_count = self.url.count('_')
        
        total = at_count + hyphen_count + underscore_count
        
        # @ symbol in URL is especially suspicious
        has_at_symbol = at_count > 0
        excessive_hyphens = hyphen_count > 4
        excessive_underscores = underscore_count > 3
        
        is_suspicious = has_at_symbol or excessive_hyphens or excessive_underscores
        
        risk_level = 'high' if has_at_symbol else 'medium' if (excessive_hyphens or excessive_underscores) else 'low'
        
        reasons = []
        if has_at_symbol:
            reasons.append(f"Contains @ symbol ({at_count})")
        if excessive_hyphens:
            reasons.append(f"Excessive hyphens ({hyphen_count})")
        if excessive_underscores:
            reasons.append(f"Excessive underscores ({underscore_count})")
        
        return {
            'at_symbol': at_count,
            'hyphens': hyphen_count,
            'underscores': underscore_count,
            'total': total,
            'is_suspicious': is_suspicious,
            'risk_level': risk_level,
            'reason': '; '.join(reasons) if reasons else f'Normal special character usage (total: {total})'
        }
    
    def _find_suspicious_keywords(self) -> Dict:
        """
        Identify suspicious keywords commonly used in phishing attacks.
        
        Returns:
            Dict: Keyword analysis
        """
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in self.url]
        
        count = len(found_keywords)
        is_suspicious = count > 0
        risk_level = 'high' if count > 2 else 'medium' if count > 0 else 'low'
        
        return {
            'found_keywords': found_keywords,
            'count': count,
            'is_suspicious': is_suspicious,
            'risk_level': risk_level,
            'reason': f'Found {count} suspicious keyword(s): {", ".join(found_keywords[:3])}' if found_keywords else 'No suspicious keywords detected'
        }
    
    def _check_https_misuse(self) -> Dict:
        """
        Check for HTTPS-related phishing indicators.
        Phishers may use 'https' in the domain name to appear secure.
        
        Returns:
            Dict: HTTPS misuse analysis
        """
        scheme = self.parsed_url.scheme
        domain = self.parsed_url.netloc
        
        has_https_in_domain = 'https' in domain or 'ssl' in domain or 'secure' in domain
        is_http_only = scheme == 'http'
        
        is_suspicious = has_https_in_domain
        risk_level = 'high' if has_https_in_domain else 'medium' if is_http_only else 'low'
        
        reasons = []
        if has_https_in_domain:
            reasons.append("Domain contains 'https', 'ssl', or 'secure' (deceptive)")
        if is_http_only:
            reasons.append("Uses HTTP instead of HTTPS")
        
        return {
            'has_https_in_domain': has_https_in_domain,
            'is_http_only': is_http_only,
            'is_suspicious': is_suspicious,
            'risk_level': risk_level,
            'reason': '; '.join(reasons) if reasons else 'Proper HTTPS usage'
        }
    
    def _check_url_shortener(self) -> Dict:
        """
        Check if URL uses a URL shortening service.
        Shortened URLs hide the actual destination.
        
        Returns:
            Dict: URL shortener detection
        """
        shortener_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 
            'is.gd', 'buff.ly', 'adf.ly', 'short.link', 'rebrand.ly',
            'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy'
        ]
        
        domain = self.parsed_url.netloc.lower()
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check for exact domain match (not substring)
        # This prevents false positives like "niet.co.in" matching "t.co"
        is_shortener = domain in shortener_domains or any(
            domain == short or domain.endswith('.' + short) 
            for short in shortener_domains
        )
        
        return {
            'is_url_shortener': is_shortener,
            'risk_level': 'medium' if is_shortener else 'low',
            'reason': 'URL shortener detected (hides true destination)' if is_shortener else 'Not a URL shortener'
        }
    
    def _check_high_risk_tld(self) -> Dict:
        """
        Check if domain uses high-risk top-level domain.
        Some TLDs are frequently abused for phishing.
        
        Returns:
            Dict: TLD risk analysis
        """
        domain = self.parsed_url.netloc
        is_high_risk = any(domain.endswith(tld) for tld in self.HIGH_RISK_TLDS)
        
        found_tld = next((tld for tld in self.HIGH_RISK_TLDS if domain.endswith(tld)), None)
        
        return {
            'is_high_risk_tld': is_high_risk,
            'tld': found_tld,
            'risk_level': 'high' if is_high_risk else 'low',
            'reason': f'Uses high-risk TLD: {found_tld}' if is_high_risk else 'Uses standard TLD'
        }
    
    def _check_excessive_dots(self) -> Dict:
        """
        Check for excessive dots in domain which can indicate subdomain abuse.
        
        Returns:
            Dict: Dot count analysis
        """
        domain = self.parsed_url.netloc
        dot_count = domain.count('.')
        
        is_suspicious = dot_count > 3
        risk_level = 'medium' if is_suspicious else 'low'
        
        return {
            'dot_count': dot_count,
            'is_suspicious': is_suspicious,
            'risk_level': risk_level,
            'reason': f'{dot_count} dots in domain' + (' (excessive)' if is_suspicious else '')
        }
    
    def _check_brand_spoofing(self) -> Dict:
        """
        Check if URL attempts to spoof a well-known brand.
        
        Returns:
            Dict: Brand spoofing analysis
        """
        domain = self.parsed_url.netloc.lower()
        full_url = self.url
        
        found_brands = []
        for brand in self.BRAND_KEYWORDS:
            if brand in full_url:
                # Check if it's the legitimate brand domain
                # Valid: brand.com, www.brand.com, subdomain.brand.com
                # Invalid: brand-something.com, secure-brand.com, brand.fake.com
                
                # Remove port if present
                domain_without_port = domain.split(':')[0]
                
                # Split domain into parts
                domain_parts = domain_without_port.split('.')
                
                # Check if brand is the actual domain name (not just part of it)
                is_legitimate = False
                
                # For .com domains: brand must be second-to-last part
                # For other TLDs: similar logic
                if len(domain_parts) >= 2:
                    # Get the domain name (excluding subdomains and TLD)
                    # e.g., for "www.amazon.com" -> "amazon"
                    # e.g., for "secure-login-amazon.com" -> "secure-login-amazon"
                    domain_name = domain_parts[-2]
                    
                    # The domain name must exactly match the brand (not contain it)
                    if domain_name == brand:
                        is_legitimate = True
                
                # If brand appears in URL but domain is not legitimate, it's spoofing
                if not is_legitimate:
                    found_brands.append(brand)
        
        is_suspicious = len(found_brands) > 0
        risk_level = 'high' if is_suspicious else 'low'
        
        return {
            'potential_spoofing': is_suspicious,
            'brands_found': found_brands,
            'risk_level': risk_level,
            'reason': f'Possible brand spoofing: {", ".join(found_brands)}' if found_brands else 'No brand spoofing detected'
        }
    
    def _check_punycode(self) -> Dict:
        """
        Check for punycode (internationalized domain names) which can be used for homograph attacks.
        
        Returns:
            Dict: Punycode detection
        """
        domain = self.parsed_url.netloc
        has_punycode = 'xn--' in domain
        
        return {
            'has_punycode': has_punycode,
            'risk_level': 'medium' if has_punycode else 'low',
            'reason': 'Punycode detected (possible homograph attack)' if has_punycode else 'No punycode detected'
        }
    
    def _check_path_depth(self) -> Dict:
        """
        Check URL path depth (number of directories).
        Excessive depth can be used to hide malicious intent.
        
        Returns:
            Dict: Path depth analysis
        """
        path = self.parsed_url.path
        depth = len([p for p in path.split('/') if p])
        
        is_suspicious = depth > 4
        risk_level = 'medium' if is_suspicious else 'low'
        
        return {
            'depth': depth,
            'is_suspicious': is_suspicious,
            'risk_level': risk_level,
            'reason': f'Path depth: {depth}' + (' (deeply nested)' if is_suspicious else '')
        }


class PhishingScorer:
    """
    Calculates phishing risk scores based on extracted URL features.
    
    Uses a weighted scoring system where different features contribute
    different amounts to the final risk score (0-100).
    """
    
    # Weight assignments for different risk factors (total = 100)
    WEIGHTS = {
        'url_length': 8,
        'ip_address': 20,
        'subdomain_count': 12,
        'special_characters': 10,
        'suspicious_keywords': 15,
        'https_misuse': 12,
        'url_shortener': 5,
        'high_risk_tld': 10,
        'excessive_dots': 3,
        'brand_spoofing': 15,
        'punycode': 5,
        'path_depth': 5
    }
    
    def __init__(self, features: Dict):
        """
        Initialize scorer with extracted features.
        
        Args:
            features (Dict): Features extracted by URLFeatureExtractor
        """
        self.features = features
        self.risk_score = 0
        self.detection_reasons = []
        
    def calculate_custom_score(self) -> Tuple[int, List[str]]:
        """
        Calculate custom phishing risk score based on URL features.
        
        Returns:
            Tuple[int, List[str]]: Risk score (0-100) and list of detection reasons
        """
        score = 0
        reasons = []
        
        # 1. URL Length Analysis (Weight: 8)
        url_len = self.features['url_length']
        if url_len['is_suspicious']:
            points = self.WEIGHTS['url_length']
            if url_len['risk_level'] == 'high':
                points = int(points * 1.25)  # Boost for high risk
            score += points
            reasons.append(f"⚠️ {url_len['reason']} (+{points} points)")
        
        # 2. IP Address Check (Weight: 20)
        ip_check = self.features['has_ip_address']
        if ip_check['is_ip_address']:
            points = self.WEIGHTS['ip_address']
            score += points
            reasons.append(f"🚨 {ip_check['reason']} (+{points} points)")
        
        # 3. Subdomain Count (Weight: 12)
        subdomain = self.features['subdomain_count']
        if subdomain['is_suspicious']:
            points = self.WEIGHTS['subdomain_count']
            if subdomain['risk_level'] == 'high':
                points = int(points * 1.3)
            score += points
            reasons.append(f"⚠️ {subdomain['reason']} (+{points} points)")
        
        # 4. Special Characters (Weight: 10)
        special_chars = self.features['special_char_count']
        if special_chars['is_suspicious']:
            points = self.WEIGHTS['special_characters']
            if special_chars['risk_level'] == 'high':
                points = int(points * 1.4)
            score += points
            reasons.append(f"⚠️ {special_chars['reason']} (+{points} points)")
        
        # 5. Suspicious Keywords (Weight: 15)
        keywords = self.features['suspicious_keywords']
        if keywords['is_suspicious']:
            points = self.WEIGHTS['suspicious_keywords']
            if keywords['risk_level'] == 'high':
                points = int(points * 1.2)
            score += points
            reasons.append(f"⚠️ {keywords['reason']} (+{points} points)")
        
        # 6. HTTPS Misuse (Weight: 12)
        https_check = self.features['https_misuse']
        if https_check['is_suspicious']:
            points = self.WEIGHTS['https_misuse']
            if https_check['risk_level'] == 'high':
                points = int(points * 1.3)
            score += points
            reasons.append(f"🚨 {https_check['reason']} (+{points} points)")
        
        # 7. URL Shortener (Weight: 5)
        shortener = self.features['url_shortener']
        if shortener['is_url_shortener']:
            points = self.WEIGHTS['url_shortener']
            score += points
            reasons.append(f"⚠️ {shortener['reason']} (+{points} points)")
        
        # 8. High Risk TLD (Weight: 10)
        tld_check = self.features['high_risk_tld']
        if tld_check['is_high_risk_tld']:
            points = self.WEIGHTS['high_risk_tld']
            score += points
            reasons.append(f"⚠️ {tld_check['reason']} (+{points} points)")
        
        # 9. Excessive Dots (Weight: 3)
        dots = self.features['excessive_dots']
        if dots['is_suspicious']:
            points = self.WEIGHTS['excessive_dots']
            score += points
            reasons.append(f"⚠️ {dots['reason']} (+{points} points)")
        
        # 10. Brand Spoofing (Weight: 15)
        spoofing = self.features['brand_spoofing']
        if spoofing['potential_spoofing']:
            points = self.WEIGHTS['brand_spoofing']
            score += points
            reasons.append(f"🚨 {spoofing['reason']} (+{points} points)")
        
        # 11. Punycode (Weight: 5)
        punycode = self.features['punycode_domain']
        if punycode['has_punycode']:
            points = self.WEIGHTS['punycode']
            score += points
            reasons.append(f"⚠️ {punycode['reason']} (+{points} points)")
        
        # 12. Path Depth (Weight: 5)
        path = self.features['path_depth']
        if path['is_suspicious']:
            points = self.WEIGHTS['path_depth']
            score += points
            reasons.append(f"⚠️ {path['reason']} (+{points} points)")
        
        # Normalize score to 0-100 range
        self.risk_score = min(100, score)
        self.detection_reasons = reasons
        
        # Add safe indicator if no issues found
        if not reasons:
            reasons.append("✅ No suspicious patterns detected in URL structure")
        
        return self.risk_score, self.detection_reasons


class ThreatIntelligenceMapper:
    """
    Maps threat intelligence API responses to numeric risk scores.
    
    Standardizes different API response formats into a consistent
    scoring system for the hybrid decision engine.
    """
    
    # API response mapping to scores
    API_SCORE_MAP = {
        'safe': 0,
        'clean': 0,
        'harmless': 0,
        'suspicious': 30,
        'warning': 30,
        'unknown': 20,
        'malicious': 70,
        'malware': 80,
        'phishing': 85,
        'error': 0  # Don't penalize on API errors
    }
    
    @staticmethod
    def map_virustotal_response(status: str, details: str = '') -> Tuple[int, str]:
        """
        Map VirusTotal API response to numeric score.
        
        Args:
            status (str): Status from VirusTotal ('Safe', 'Suspicious', 'Malicious', 'Error')
            details (str): Additional details from the API
            
        Returns:
            Tuple[int, str]: API risk score and explanation
        """
        status_lower = status.lower()
        
        # Map status to score
        api_score = ThreatIntelligenceMapper.API_SCORE_MAP.get(status_lower, 20)
        
        # Generate explanation
        if status_lower == 'safe' or status_lower == 'clean':
            explanation = "✅ Threat intelligence: URL marked as SAFE by security vendors"
        elif status_lower == 'suspicious':
            explanation = "⚠️ Threat intelligence: URL flagged as SUSPICIOUS by some vendors"
        elif status_lower == 'malicious':
            explanation = "🚨 Threat intelligence: URL flagged as MALICIOUS by multiple vendors"
        elif status_lower == 'error':
            explanation = "ℹ️ Threat intelligence: API check unavailable (relying on custom analysis)"
            api_score = 0  # Neutral score on error
        else:
            explanation = f"ℹ️ Threat intelligence: Status '{status}' (moderate risk assumed)"
        
        return api_score, explanation
    
    @staticmethod
    def map_generic_api_response(response_data: Dict) -> Tuple[int, str]:
        """
        Map generic threat intelligence API response to score.
        Can be extended for other API providers.
        
        Args:
            response_data (Dict): Generic API response
            
        Returns:
            Tuple[int, str]: API risk score and explanation
        """
        # Extract status from various possible field names
        status = (response_data.get('status') or 
                 response_data.get('verdict') or 
                 response_data.get('classification') or 
                 'unknown').lower()
        
        return ThreatIntelligenceMapper.map_virustotal_response(status)


class HybridDecisionEngine:
    """
    Combines custom URL analysis with threat intelligence API results
    to produce a final phishing verdict using weighted scoring.
    
    Scoring Model:
    - Custom Analysis Weight: 65%
    - API Intelligence Weight: 35%
    - Final Score = (0.65 × custom_score) + (0.35 × api_score)
    
    Classification:
    - 0-29: SAFE
    - 30-59: SUSPICIOUS
    - 60-100: MALICIOUS
    """
    
    # Weight distribution
    CUSTOM_WEIGHT = 0.65
    API_WEIGHT = 0.35
    
    # Classification thresholds
    SAFE_THRESHOLD = 29
    SUSPICIOUS_THRESHOLD = 59
    
    def __init__(self, custom_score: int, api_score: int, 
                 custom_reasons: List[str], api_explanation: str):
        """
        Initialize the decision engine with scores and reasons.
        
        Args:
            custom_score (int): Score from custom URL analysis (0-100)
            api_score (int): Score from threat intelligence API (0-100)
            custom_reasons (List[str]): Detection reasons from custom analysis
            api_explanation (str): Explanation from API
        """
        self.custom_score = custom_score
        self.api_score = api_score
        self.custom_reasons = custom_reasons
        self.api_explanation = api_explanation
        self.final_score = 0
        self.verdict = ""
        self.severity = ""
        
    def calculate_final_verdict(self) -> Dict:
        """
        Calculate weighted final score and determine verdict.
        
        Returns:
            Dict: Complete analysis result with verdict, scores, and recommendations
        """
        # Calculate weighted final score
        self.final_score = round(
            (self.CUSTOM_WEIGHT * self.custom_score) + 
            (self.API_WEIGHT * self.api_score)
        )
        
        # Determine verdict based on thresholds
        if self.final_score <= self.SAFE_THRESHOLD:
            self.verdict = "SAFE"
            self.severity = "LOW"
            security_recommendation = (
                "✅ This URL appears to be safe based on our analysis. "
                "However, always verify the legitimacy of websites before entering sensitive information."
            )
        elif self.final_score <= self.SUSPICIOUS_THRESHOLD:
            self.verdict = "SUSPICIOUS"
            self.severity = "MEDIUM"
            security_recommendation = (
                "⚠️ This URL shows suspicious characteristics. Exercise caution. "
                "Verify the sender/source, avoid entering personal information, and consider using alternative methods to access the service."
            )
        else:
            self.verdict = "MALICIOUS"
            self.severity = "HIGH"
            security_recommendation = (
                "🚨 DANGER: This URL is likely a phishing attempt. DO NOT visit this site or enter any information. "
                "Report this URL to your security team and delete any messages containing it."
            )
        
        # Compile all detection reasons
        all_reasons = []
        
        # Add scoring breakdown
        all_reasons.append(f"📊 Custom Analysis Score: {self.custom_score}/100 (Weight: {int(self.CUSTOM_WEIGHT*100)}%)")
        all_reasons.append(f"📊 API Intelligence Score: {self.api_score}/100 (Weight: {int(self.API_WEIGHT*100)}%)")
        all_reasons.append(f"📊 Final Weighted Score: {self.final_score}/100")
        all_reasons.append("")  # Blank line for separation
        
        # Add custom analysis reasons
        if self.custom_reasons:
            all_reasons.append("🔍 CUSTOM ANALYSIS FINDINGS:")
            all_reasons.extend(self.custom_reasons)
            all_reasons.append("")  # Blank line
        
        # Add API intelligence
        all_reasons.append("🌐 THREAT INTELLIGENCE:")
        all_reasons.append(self.api_explanation)
        
        # Build final response
        result = {
            'verdict': self.verdict,
            'final_score': self.final_score,
            'severity': self.severity,
            'custom_score': self.custom_score,
            'api_score': self.api_score,
            'detection_reasons': all_reasons,
            'security_recommendation': security_recommendation,
            'score_breakdown': {
                'custom_analysis': {
                    'score': self.custom_score,
                    'weight': f"{int(self.CUSTOM_WEIGHT*100)}%",
                    'contribution': round(self.CUSTOM_WEIGHT * self.custom_score, 1)
                },
                'api_intelligence': {
                    'score': self.api_score,
                    'weight': f"{int(self.API_WEIGHT*100)}%",
                    'contribution': round(self.API_WEIGHT * self.api_score, 1)
                }
            }
        }
        
        return result


def analyze_url_for_phishing(url: str, api_status: str = 'Unknown', 
                             api_details: str = '') -> Dict:
    """
    Main function to perform hybrid phishing detection on a URL.
    
    This function orchestrates the entire phishing detection pipeline:
    1. Extract URL features
    2. Calculate custom risk score
    3. Map API response to score
    4. Combine scores using weighted model
    5. Generate final verdict with explanations
    
    Args:
        url (str): The URL to analyze
        api_status (str): Status from threat intelligence API
        api_details (str): Additional details from API
        
    Returns:
        Dict: Complete phishing analysis result
    """
    # Step 1: Extract URL features
    extractor = URLFeatureExtractor(url)
    features = extractor.extract_all_features()
    
    # Step 2: Calculate custom risk score
    scorer = PhishingScorer(features)
    custom_score, custom_reasons = scorer.calculate_custom_score()
    
    # Step 3: Map API response to score
    api_score, api_explanation = ThreatIntelligenceMapper.map_virustotal_response(
        api_status, api_details
    )
    
    # Step 4: Calculate final verdict using hybrid model
    decision_engine = HybridDecisionEngine(
        custom_score, api_score, custom_reasons, api_explanation
    )
    final_result = decision_engine.calculate_final_verdict()
    
    # Step 5: Add additional metadata
    final_result['analyzed_url'] = url
    final_result['domain'] = features['domain']
    final_result['analysis_features'] = {
        'url_length': features['url_length']['length'],
        'url_length_risk': features['url_length']['risk_level'],
        'uses_ip': features['has_ip_address']['is_ip_address'],
        'subdomain_count': features['subdomain_count']['count'],
        'subdomain_risk': features['subdomain_count']['risk_level'],
        'suspicious_keywords_found': features['suspicious_keywords']['count'],
        'suspicious_keywords_list': features['suspicious_keywords']['found_keywords'],
        'uses_https': url.startswith('https'),
        'https_in_domain': features['https_misuse']['has_https_in_domain'],
        'is_http_only': features['https_misuse']['is_http_only'],
        'special_chars': features['special_char_count'],
        'is_url_shortener': features['url_shortener']['is_url_shortener'],
        'high_risk_tld': features['high_risk_tld']['is_high_risk_tld'],
        'tld_name': features['high_risk_tld'].get('tld', ''),
        'excessive_dots': features['excessive_dots']['is_suspicious'],
        'dot_count': features['excessive_dots']['dot_count'],
        'brand_spoofing': features['brand_spoofing']['potential_spoofing'],
        'brands_found': features['brand_spoofing']['brands_found'],
        'has_punycode': features['punycode_domain']['has_punycode'],
        'path_depth': features['path_depth']['depth'],
        'path_depth_suspicious': features['path_depth']['is_suspicious']
    }
    
    return final_result
