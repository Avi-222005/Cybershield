import re
from collections import defaultdict
from typing import Dict, List
from urllib.parse import urlparse

import requests


def extract_scripts(html: str) -> List[str]:
    """Extract script src URLs from HTML."""
    if not html:
        return []
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)


def extract_links(html: str) -> List[str]:
    """Extract link href URLs from HTML."""
    if not html:
        return []
    return re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)


def extract_inline_scripts(html: str) -> str:
    """Extract inline script content for signal matching."""
    if not html:
        return ""
    blocks = re.findall(r"<script(?![^>]+src=)[^>]*>(.*?)</script>", html, flags=re.IGNORECASE | re.DOTALL)
    return " ".join(blocks)


def extract_asset_signals(base_url: str, asset_paths: List[str], limit: int = 3, max_chars: int = 1_500_000) -> str:
    """Fetch a few JS/CSS assets and aggregate text for deeper fingerprint detection."""
    if not base_url or not asset_paths:
        return ""

    seen = set()
    collected = []
    origin_match = re.match(r"^https?://[^/]+", base_url)
    if not origin_match:
        return ""
    origin = origin_match.group(0)

    for path in asset_paths:
        if len(seen) >= limit:
            break
        raw = (path or "").strip()
        if not raw or raw.startswith("data:"):
            continue

        if raw.startswith("//"):
            asset_url = f"https:{raw}"
        elif raw.startswith("http://") or raw.startswith("https://"):
            asset_url = raw
        else:
            asset_url = f"{origin}{raw if raw.startswith('/') else '/' + raw}"

        if asset_url in seen:
            continue
        seen.add(asset_url)

        try:
            res = requests.get(
                asset_url,
                timeout=8,
                headers={"User-Agent": "CyberShield-TechStack/1.0"},
            )
            if res.status_code >= 400:
                continue
            collected.append((res.text or "")[:max_chars].lower())
        except requests.RequestException:
            continue

    return " ".join(collected)


PATTERNS: Dict[str, Dict] = {
    # Servers
    "Nginx": {"category": "Server", "headers": ["nginx"]},
    "Apache": {"category": "Server", "headers": ["apache"]},
    "IIS": {"category": "Server", "headers": ["microsoft-iis"]},
    "LiteSpeed": {"category": "Server", "headers": ["litespeed"]},
    "Caddy": {"category": "Server", "headers": ["caddy"]},
    "OpenResty": {"category": "Server", "headers": ["openresty"]},
    "Tomcat": {"category": "Server", "headers": ["tomcat"]},
    "Jetty": {"category": "Server", "headers": ["jetty"]},
    # Backend
    "PHP": {"category": "Backend", "headers": ["php"], "cookies": ["phpsessid"]},
    "Node.js": {"category": "Backend", "headers": ["node", "express"]},
    "Python": {"category": "Backend", "headers": ["gunicorn", "uwsgi", "werkzeug"]},
    "ASP.NET": {"category": "Backend", "headers": ["asp.net"], "cookies": ["asp.net"]},
    "Ruby": {"category": "Backend", "headers": ["ruby"]},
    "Perl": {"category": "Backend", "headers": ["perl"]},
    "Go": {"category": "Backend", "headers": ["golang", "go-http"]},
    "Java": {"category": "Backend", "headers": ["java", "jsp"]},
    "Elixir": {"category": "Backend", "headers": ["phoenix"]},
    # Frameworks
    "Express": {"category": "Framework", "headers": ["express"]},
    "Django": {"category": "Framework", "headers": ["django"], "cookies": ["csrftoken"]},
    "Flask": {"category": "Framework", "headers": ["werkzeug"]},
    "Laravel": {"category": "Framework", "cookies": ["laravel_session"], "html": ["laravel"]},
    "CodeIgniter": {"category": "Framework", "html": ["codeigniter"], "cookies": ["ci_session"]},
    "Spring": {"category": "Framework", "headers": ["spring"]},
    "Ruby on Rails": {"category": "Framework", "html": ["rails"], "cookies": ["_rails_session"]},
    "Next.js": {"category": "Framework", "html": ["_next"]},
    "Nuxt.js": {"category": "Framework", "html": ["nuxt"]},
    "Phoenix": {"category": "Framework", "html": ["phoenix"]},
    "FastAPI": {"category": "Framework", "headers": ["fastapi"]},
    # Frontend
    "React": {"category": "Frontend", "scripts": ["react"], "html": ["data-reactroot"], "asset_content": ["react"]},
    "React Router": {"category": "Frontend", "asset_content": ["react-router-dom", "react router", "reactrouter"]},
    "Angular": {"category": "Frontend", "html": ["ng-app", "angular"]},
    "Vue.js": {"category": "Frontend", "scripts": ["vue"], "html": ["vue"]},
    "Svelte": {"category": "Frontend", "scripts": ["svelte"]},
    "jQuery": {"category": "Frontend", "scripts": ["jquery"]},
    "Backbone.js": {"category": "Frontend", "scripts": ["backbone"]},
    "Alpine.js": {"category": "Frontend", "scripts": ["alpinejs"]},
    "Ember.js": {"category": "Frontend", "scripts": ["ember"]},
    "Preact": {"category": "Frontend", "scripts": ["preact"]},
    # CMS
    "WordPress": {"category": "CMS", "html": ["wp-content"], "cookies": ["wordpress"], "meta": ["wordpress"]},
    "Drupal": {"category": "CMS", "html": ["drupal"]},
    "Joomla": {"category": "CMS", "html": ["joomla"]},
    "Shopify": {"category": "CMS", "html": ["shopify"], "headers": ["shopify"]},
    "Wix": {"category": "CMS", "html": ["wix.com"]},
    "Squarespace": {"category": "CMS", "html": ["squarespace"]},
    "Ghost": {"category": "CMS", "html": ["ghost"]},
    "Blogger": {"category": "CMS", "html": ["blogger"]},
    "Webflow": {"category": "CMS", "html": ["webflow"]},
    "Umbraco": {"category": "CMS", "html": ["umbraco"]},
    # E-commerce
    "Magento": {"category": "E-commerce", "html": ["mage"]},
    "BigCommerce": {"category": "E-commerce", "html": ["bigcommerce"]},
    "PrestaShop": {"category": "E-commerce", "html": ["prestashop"]},
    "OpenCart": {"category": "E-commerce", "html": ["opencart"]},
    "WooCommerce": {"category": "E-commerce", "html": ["woocommerce"]},
    "Shopware": {"category": "E-commerce", "html": ["shopware"]},
    # Analytics
    "Google Analytics": {"category": "Analytics", "scripts": ["google-analytics", "gtag"]},
    "Google Tag Manager": {"category": "Analytics", "scripts": ["googletagmanager"]},
    "Facebook Pixel": {"category": "Analytics", "scripts": ["connect.facebook.net"]},
    "Hotjar": {"category": "Analytics", "scripts": ["hotjar"]},
    "Mixpanel": {"category": "Analytics", "scripts": ["mixpanel"]},
    "Amplitude": {"category": "Analytics", "scripts": ["amplitude"]},
    "Segment": {"category": "Analytics", "scripts": ["segment.com", "segment.io"]},
    "Matomo": {"category": "Analytics", "scripts": ["matomo"]},
    # CDN / Security
    "Cloudflare": {"category": "CDN/Security", "headers": ["cloudflare"], "cookies": ["cf_clearance"]},
    "CDNJS": {"category": "CDN/Security", "assets": ["cdnjs.cloudflare.com"]},
    "Akamai": {"category": "CDN/Security", "headers": ["akamai"]},
    "Fastly": {"category": "CDN/Security", "headers": ["fastly"]},
    "Cloudfront": {"category": "CDN/Security", "headers": ["cloudfront"]},
    "Imperva": {"category": "CDN/Security", "headers": ["imperva"]},
    "Sucuri": {"category": "CDN/Security", "headers": ["sucuri"]},
    "BunnyCDN": {"category": "CDN/Security", "headers": ["bunnycdn"]},
    "KeyCDN": {"category": "CDN/Security", "headers": ["keycdn"]},
    # Auth / Services
    "Firebase": {"category": "Service", "scripts": ["firebase"]},
    "Auth0": {"category": "Service", "html": ["auth0"]},
    "Okta": {"category": "Service", "html": ["okta"]},
    "Clerk": {"category": "Service", "scripts": ["clerk"]},
    # UI / CSS
    "Bootstrap": {"category": "Frontend", "scripts": ["bootstrap"], "html": ["bootstrap"]},
    "Tailwind CSS": {"category": "Frontend", "html": ["tailwind"], "asset_content": ["--tw-"]},
    "Material UI": {"category": "Frontend", "scripts": ["mui"]},
    "Foundation": {"category": "Frontend", "html": ["foundation"]},
    "Bulma": {"category": "Frontend", "html": ["bulma"]},
    "Semantic UI": {"category": "Frontend", "html": ["semantic-ui"]},
    # Payments
    "Stripe": {"category": "Payment", "scripts": ["stripe"]},
    "PayPal": {"category": "Payment", "scripts": ["paypal"]},
    "Razorpay": {"category": "Payment", "scripts": ["razorpay"]},
    "Braintree": {"category": "Payment", "scripts": ["braintree"]},
    "Paddle": {"category": "Payment", "scripts": ["paddle"]},
    # Hosting
    "Heroku": {"category": "Hosting", "headers": ["heroku"]},
    "Vercel": {"category": "Hosting", "headers": ["vercel"]},
    "Netlify": {"category": "Hosting", "headers": ["netlify"]},
    "DigitalOcean": {"category": "Hosting", "headers": ["digitalocean"]},
    "Render": {"category": "Hosting", "headers": ["render"]},
    "Fly.io": {"category": "Hosting", "headers": ["fly.io"]},
    # Database
    "MySQL": {"category": "Database", "html": ["mysql"]},
    "PostgreSQL": {"category": "Database", "html": ["postgres"]},
    "MongoDB": {"category": "Database", "html": ["mongodb"]},
    "Redis": {"category": "Database", "html": ["redis"]},
    "Elasticsearch": {"category": "Database", "html": ["elasticsearch"]},
    # SEO
    "Yoast SEO": {"category": "SEO", "html": ["yoast"]},
    "RankMath": {"category": "SEO", "html": ["rankmath"]},
    # Email
    "SendGrid": {"category": "Email", "headers": ["sendgrid"]},
    "Mailchimp": {"category": "Email", "html": ["mailchimp"]},
    "Amazon SES": {"category": "Email", "headers": ["amazonses"]},
    "Postmark": {"category": "Email", "headers": ["postmark"]},
    # Monitoring
    "Sentry": {"category": "Monitoring", "scripts": ["sentry"]},
    "New Relic": {"category": "Monitoring", "scripts": ["newrelic"]},
    "Datadog": {"category": "Monitoring", "scripts": ["datadog"]},
    "LogRocket": {"category": "Monitoring", "scripts": ["logrocket"]},
    # A/B testing
    "Optimizely": {"category": "A/B Testing", "scripts": ["optimizely"]},
    "VWO": {"category": "A/B Testing", "scripts": ["vwo"]},
    # DevOps / CI
    "Jenkins": {"category": "DevOps", "html": ["jenkins"]},
    "GitHub Pages": {"category": "Hosting", "headers": ["github"]},
    "GitLab": {"category": "DevOps", "headers": ["gitlab"]},
    "CircleCI": {"category": "DevOps", "headers": ["circleci"]},
    "Cloud Build": {"category": "DevOps", "headers": ["cloud build"]},
    "Bazel": {"category": "DevOps", "html": ["bazel"]},
    # Chat / support
    "Zendesk": {"category": "Service", "scripts": ["zendesk"]},
    "Intercom": {"category": "Service", "scripts": ["intercom"]},
    "Drift": {"category": "Service", "scripts": ["drift"]},
    "Crisp": {"category": "Service", "scripts": ["crisp.chat"]},
    "Tawk.to": {"category": "Service", "scripts": ["tawk.to"]},
    "LeadSquared": {"category": "Service", "scripts": ["lsqbot.converse.leadsquared.com", "leadsquared"]},
    # Maps / media / forms / captcha
    "Google Maps": {"category": "Service", "scripts": ["maps.googleapis"]},
    "YouTube Embed": {"category": "Media", "html": ["youtube.com/embed"]},
    "Vimeo": {"category": "Media", "html": ["vimeo"]},
    "Formspree": {"category": "Service", "html": ["formspree"]},
    "Typeform": {"category": "Service", "html": ["typeform"]},
    "reCAPTCHA": {"category": "Security", "scripts": ["recaptcha"]},
    "hCaptcha": {"category": "Security", "scripts": ["hcaptcha"]},
    # Headless CMS / API / tooling
    "Contentful": {"category": "CMS", "html": ["contentful"]},
    "Strapi": {"category": "CMS", "html": ["strapi"]},
    "Sanity": {"category": "CMS", "html": ["sanity"]},
    "GraphQL": {"category": "API", "html": ["graphql"]},
    "DocuSign": {"category": "Service", "html": ["docusign"]},
    "Webpack": {"category": "Frontend", "scripts": ["webpack"]},
    "Parcel": {"category": "Frontend", "scripts": ["parcel"]},
    "Vite": {"category": "Frontend", "scripts": ["vite"]},
    "Algolia": {"category": "Service", "scripts": ["algolia"]},
    "CrazyEgg": {"category": "Analytics", "scripts": ["crazyegg"]},
    # Tag managers / advertising / fonts / JS libs / programming libs
    "Adobe Launch": {"category": "Tag Manager", "scripts": ["assets.adobedtm.com", "launch-"]},
    "Tealium": {"category": "Tag Manager", "scripts": ["tags.tiqcdn.com", "tealium"]},
    "DoubleClick": {"category": "Advertising", "scripts": ["doubleclick.net"]},
    "Google Ads": {"category": "Advertising", "scripts": ["googleadservices.com", "googlesyndication.com"]},
    "AdSense": {"category": "Advertising", "scripts": ["adsbygoogle", "pagead2.googlesyndication.com"]},
    "Taboola": {"category": "Advertising", "scripts": ["taboola"]},
    "Outbrain": {"category": "Advertising", "scripts": ["outbrain"]},
    "Google Fonts": {"category": "Font Script", "assets": ["fonts.googleapis.com", "fonts.gstatic.com"]},
    "Font Awesome": {"category": "Font Script", "assets": ["font-awesome", "cdnjs.cloudflare.com/ajax/libs/font-awesome"]},
    "Lucide": {"category": "Font Script", "asset_content": ["lucide-react", "lucide"]},
    "Typekit": {"category": "Font Script", "assets": ["use.typekit.net", "typekit"]},
    "Moment.js": {"category": "JavaScript Library", "scripts": ["moment.js", "moment.min.js"]},
    "Lodash": {"category": "JavaScript Library", "scripts": ["lodash"]},
    "Axios": {"category": "JavaScript Library", "scripts": ["axios"]},
    "Chart.js": {"category": "JavaScript Library", "scripts": ["chart.js"]},
    "D3.js": {"category": "JavaScript Library", "scripts": ["d3.min.js", "d3.js"]},
    "Anime.js": {"category": "JavaScript Library", "scripts": ["anime.min.js"]},
    "Owl Carousel": {"category": "JavaScript Library", "scripts": ["owl.carousel"]},
    "AOS": {"category": "JavaScript Library", "scripts": ["aos.js"], "html": ["data-aos"]},
    "Fancybox": {"category": "JavaScript Library", "scripts": ["fancybox"]},
    "Framer Motion": {"category": "JavaScript Library", "asset_content": ["framer-motion", "framer motion"]},
    "Swiper": {"category": "JavaScript Library", "scripts": ["swiper"], "asset_content": ["swiper"]},
    "jQuery Validate": {"category": "JavaScript Library", "scripts": ["jquery.validate"]},
    "jQuery TouchSwipe": {"category": "JavaScript Library", "scripts": ["jquery.touchswipe"]},
    "Lightbox": {"category": "JavaScript Library", "scripts": ["lightbox"]},
    "Core-js": {"category": "Programming Library", "scripts": ["core-js"]},
    "Babel": {"category": "Programming Library", "scripts": ["babel.min.js", "babel-"]},
    "Polyfill.io": {"category": "Programming Library", "scripts": ["polyfill.io"]},
    "Radix UI": {"category": "UI Framework", "asset_content": ["@radix-ui", "radix-ui"]},
    "shadcn/ui": {"category": "UI Framework", "asset_content": ["class-variance-authority", "cva("]},
    "Cloudinary": {"category": "Digital Asset Management", "scripts": ["cloudinary"], "asset_content": ["cloudinary"]},
    "Open Graph": {"category": "Miscellaneous", "meta": ["property:og:"]},
}

WEIGHTS = {"headers": 4, "html": 2, "scripts": 2, "cookies": 3, "meta": 3, "assets": 2, "inline": 2, "asset_content": 2}
MIN_SCORE = 2


def _normalize_url(url_input: str) -> str:
    raw = str(url_input or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if not parsed.netloc:
        return ""
    return raw if "://" in raw else f"https://{raw}"


def fetch_site(url_input: str) -> Dict:
    """Fetch website content and return headers/html/cookies/meta for detection."""
    url = _normalize_url(url_input)
    if not url:
        return {"error": "Invalid URL format."}

    try:
        response = requests.get(
            url,
            timeout=12,
            allow_redirects=True,
            headers={"User-Agent": "CyberShield-TechStack/1.0"},
        )
    except requests.RequestException as exc:
        return {"error": f"Request failed: {str(exc)}"}

    html = response.text or ""
    headers = {k.lower(): str(v).lower() for k, v in response.headers.items()}
    cookie_names = [k.lower() for k in response.cookies.keys()]
    set_cookie = response.headers.get("set-cookie", "")
    if set_cookie:
        cookie_names.extend([c.split("=")[0].strip().lower() for c in set_cookie.split(",") if "=" in c])
    script_urls = extract_scripts(html)
    link_urls = extract_links(html)
    scripts = [s.lower() for s in script_urls]
    links = [l.lower() for l in link_urls]
    inline_scripts = extract_inline_scripts(html).lower()
    asset_content = extract_asset_signals(response.url, script_urls + link_urls)

    meta_generators = re.findall(
        r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        flags=re.IGNORECASE,
    )
    meta_properties = re.findall(
        r'<meta[^>]+property=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        flags=re.IGNORECASE,
    )
    meta_generators = [f"name:{name.lower()}:{content.lower()}" for name, content in meta_generators]
    meta_generators.extend([f"property:{name.lower()}:{content.lower()}" for name, content in meta_properties])

    return {
        "final_url": response.url,
        "headers": headers,
        "html": html.lower(),
        "cookies": sorted(set(cookie_names)),
        "scripts": scripts,
        "assets": scripts + links,
        "inline": inline_scripts,
        "asset_content": asset_content,
        "meta": meta_generators,
    }


def match_patterns(
    headers: Dict[str, str],
    html: str,
    scripts: List[str],
    cookies: List[str],
    meta: List[str],
    assets: List[str],
    inline: str,
    asset_content: str,
) -> Dict:
    """Match technology patterns using weighted multi-signal detection."""
    detected = set()
    categorized = defaultdict(list)

    header_blob = " ".join([f"{k} {v}" for k, v in headers.items()])
    script_blob = " ".join(scripts)
    cookie_blob = " ".join(cookies)
    meta_blob = " ".join(meta)
    assets_blob = " ".join(assets)

    for tech, cfg in PATTERNS.items():
        score = 0
        for signal in ("headers", "html", "scripts", "cookies", "meta", "assets", "inline", "asset_content"):
            terms = [t.lower() for t in cfg.get(signal, [])]
            if not terms:
                continue
            source = (
                header_blob
                if signal == "headers"
                else html
                if signal == "html"
                else script_blob
                if signal == "scripts"
                else cookie_blob
                if signal == "cookies"
                else meta_blob
                if signal == "meta"
                else assets_blob
                if signal == "assets"
                else inline
                if signal == "inline"
                else asset_content
            )
            if any(term in source for term in terms):
                score += WEIGHTS[signal]

        if score >= MIN_SCORE:
            detected.add(tech)
            category = cfg.get("category", "Other")
            categorized[category].append(tech)

    for category in categorized:
        categorized[category] = sorted(set(categorized[category]))

    return {"technologies": sorted(detected), "categorized": dict(categorized)}


def analyze_tech_stack(url_input: str) -> Dict:
    site_data = fetch_site(url_input)
    if "error" in site_data:
        return site_data

    matched = match_patterns(
        headers=site_data["headers"],
        html=site_data["html"],
        scripts=site_data["scripts"],
        cookies=site_data["cookies"],
        meta=site_data["meta"],
        assets=site_data["assets"],
        inline=site_data["inline"],
        asset_content=site_data["asset_content"],
    )

    return {
        "url": site_data["final_url"],
        "technologies": matched["technologies"],
        "categorized": matched["categorized"],
    }
