"""
Canonical URL Phishing Scoring Engine
======================================
This is the SINGLE source of truth for URL risk scoring.

All three scanners (URL, QR, Email) MUST call scan_url_service() and use
the returned `score` field directly. No re-weighting is performed elsewhere.

Scoring breakdown (max 100):
  - Google Safe Browsing flagged          : +60
  - OpenPhish feed match                  : +60
  - Domain newly registered (< 30 days)   : +15
  - Suspicious TLD (.tk/.ml/.xyz etc.)    : +15
  - Invalid / missing SSL certificate     : +15
  - SSL expires very soon (< 15 days)     : +10
  - IP address used instead of domain     : +15
  - URL shortener detected                : +10
  - URL is unusually long (> 120 chars)   : +10
  - Too many hyphens or @ in URL          : +10
  - Phishing keywords in URL              : +10
  - Lookalike / brand-abuse domain        : +20
  - Suspicious path keywords              : +10

Labels:
  score >= 60  → "phishing"
  score >= 30  → "suspicious"
  score <  30  → "safe"
"""

import re
import datetime as dt
from difflib import SequenceMatcher
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qsl, urlencode, unquote

import tldextract
import validators

from app.services.gsb_service import check_google_safe_browsing
from app.services.openphish_service import openphish
from app.services.domain_utils import get_domain_age, get_ssl_certificate


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "zip", "top", "click", "pw", "work"}

PHISHING_URL_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "signin", "confirm", "password", "auth",
]

PHISHING_PATH_KEYWORDS = [
    "verify", "login", "auth", "update", "security",
    "account", "confirm", "password",
]

KNOWN_BRANDS = [
    "paypal", "google", "facebook", "amazon", "microsoft",
    "apple", "instagram", "twitter", "linkedin", "ebay",
    "walmart", "bankofamerica", "chase", "wellsfargo",
]

URL_SHORTENERS = re.compile(
    r"bit\.ly|tinyurl\.com|goo\.gl|t\.co|short\.link|ow\.ly|buff\.ly|rb\.gy",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"https?://(\d{1,3}\.){3}\d{1,3}",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _label_from_score(score: int) -> str:
    if score >= 60:
        return "phishing"
    if score >= 30:
        return "suspicious"
    return "safe"


def normalize_url(url: str) -> str:
    """
    Centralized canonical URL normalizer shared across URL, QR, and Email scanners.
    
    Normalization steps:
    1. Strips leading/trailing whitespace and surrounding quotes.
    2. Removes trailing sentence-boundary punctuation (. , ; ! ? ) ] >) commonly appended in emails.
    3. Normalizes scheme to lowercase, defaulting missing schemes to 'http://'.
    4. Normalizes hostname to lowercase and strips default ports (:80, :443).
    5. Decodes safe percent-encoded characters and normalizes path casing and trailing slashes.
    6. Sorts and standardizes query parameters so order variations match.
    """
    if not url:
        return ""
    url = url.strip()
    
    # Strip trailing punctuation commonly attached at end of sentences/quotes
    url = re.sub(r'[\s\.,;:!?\)\(\]\[><"\'\u201c\u201d\u2018\u2019]+$', '', url)
    if not url:
        return ""

    # Ensure valid scheme format
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = 'http://' + url
        
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()
        
        # Remove default ports
        if scheme == 'http' and netloc.endswith(':80'):
            netloc = netloc[:-3]
        elif scheme == 'https' and netloc.endswith(':443'):
            netloc = netloc[:-4]
            
        # Unquote and normalize path
        path = unquote(parts.path or '').lower()
        if path.endswith('/') and len(path) > 1:
            path = path.rstrip('/')
        elif path == '/':
            path = ''
            
        # Normalize and sort query params
        query = parts.query
        if query:
            q_pairs = parse_qsl(query, keep_blank_values=True)
            q_pairs.sort(key=lambda x: x[0])
            query = urlencode(q_pairs)
            
        return urlunsplit((scheme, netloc, path, query, parts.fragment))
    except Exception:
        return url


def _is_lookalike_domain(domain: str) -> str | None:
    """
    Returns the brand name if `domain` looks like a lookalike, else None.
    Uses SequenceMatcher similarity (0.55–0.94 range to avoid exact matches).
    """
    domain_lower = domain.lower()
    for brand in KNOWN_BRANDS:
        # Skip if the domain IS exactly the brand
        if domain_lower == brand:
            return None
        ratio = SequenceMatcher(None, domain_lower, brand).ratio()
        if 0.55 < ratio < 0.95:
            return brand
    return None


# ---------------------------------------------------------------------------
# Main scoring engine  (canonical — called by URL, QR, and Email scanners)
# ---------------------------------------------------------------------------

async def scan_url_service(url: str) -> dict:
    """
    Score a URL for phishing risk.

    Returns:
        {
            "url":             str,
            "label":           "safe" | "suspicious" | "phishing",
            "score":           int  (0-100),
            "reasons":         list[str],
            "domain_age":      dict,
            "ssl_certificate": dict,
        }
    """
    reasons: list[str] = []
    score = 0

    # ── Canonical Normalization ────────────────────────────────────────────
    url = normalize_url(url)

    # ── Validate ───────────────────────────────────────────────────────────
    if not url or not validators.url(url):
        return {
            "url": url,
            "label": "invalid",
            "score": 100,
            "reasons": ["URL format is invalid"],
            "domain_age": {},
            "ssl_certificate": {},
        }

    # ── Extract domain parts ───────────────────────────────────────────────
    extracted = tldextract.extract(url)
    main_domain = f"{extracted.domain}.{extracted.suffix}"
    parsed = urlparse(url)
    path = (parsed.path or "").lower()

    # ══════════════════════════════════════════════════════════════════════
    # BLOCK 1 – External threat feeds  (high-weight, early exit not needed)
    # ══════════════════════════════════════════════════════════════════════

    # 1a. Google Safe Browsing
    gsb = await check_google_safe_browsing(url)
    if gsb["flagged"]:
        score += 60
        reasons.append("Flagged by Google Safe Browsing")

    # 1b. OpenPhish blocklist
    if openphish.is_phishing(url) or openphish.is_phishing(url + "/") or openphish.is_phishing(url.rstrip("/")):
        score += 60
        reasons.append("Found in OpenPhish phishing feed")

    # ══════════════════════════════════════════════════════════════════════
    # BLOCK 2 – Domain / infrastructure checks
    # ══════════════════════════════════════════════════════════════════════

    # 2a. Domain age
    domain_age = get_domain_age(main_domain)
    if isinstance(domain_age.get("age_days"), int) and domain_age["age_days"] < 30:
        score += 15
        reasons.append("Domain is newly registered (< 30 days)")

    # 2b. SSL certificate
    ssl_info = get_ssl_certificate(main_domain)
    if ssl_info["valid"] is False:
        score += 15
        reasons.append("Invalid or missing SSL certificate")
    else:
        try:
            if ssl_info.get("valid_to"):
                valid_to = dt.datetime.strptime(ssl_info["valid_to"], "%b %d %H:%M:%S %Y %Z")
                valid_to = valid_to.replace(tzinfo=dt.timezone.utc)
                days_left = (valid_to - dt.datetime.now(dt.timezone.utc)).days
                if days_left < 15:
                    score += 10
                    reasons.append("SSL certificate expires very soon")
        except Exception:
            pass

    # 2c. IP address used as host (no domain)
    if IP_PATTERN.match(url):
        score += 15
        reasons.append("IP address used instead of a domain name")

    # 2d. Suspicious TLD
    if extracted.suffix in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Suspicious TLD: .{extracted.suffix}")

    # 2e. Lookalike / brand-abuse domain
    matched_brand = _is_lookalike_domain(extracted.domain)
    if matched_brand:
        score += 20
        reasons.append(f"Lookalike domain detected (similar to '{matched_brand}')")

    # ══════════════════════════════════════════════════════════════════════
    # BLOCK 3 – URL structure heuristics
    # ══════════════════════════════════════════════════════════════════════

    # 3a. URL shortener
    if URL_SHORTENERS.search(url):
        score += 10
        reasons.append("URL shortener detected")

    # 3b. Unusually long URL
    if len(url) > 120:
        score += 10
        reasons.append("URL is unusually long (> 120 characters)")

    # 3c. Special characters / obfuscation
    if url.count("-") > 3 or url.count("@") > 0:
        score += 10
        reasons.append("URL contains many special characters (hyphens / @ symbol)")

    # 3d. Phishing keywords anywhere in URL
    url_lower = url.lower()
    if any(kw in url_lower for kw in PHISHING_URL_KEYWORDS):
        score += 10
        reasons.append("URL contains phishing-related keywords")

    # 3e. Suspicious path segments
    if any(p in path for p in PHISHING_PATH_KEYWORDS):
        score += 10
        reasons.append("URL path contains suspicious keywords")

    # ── Cap and label ──────────────────────────────────────────────────────
    score = max(0, min(score, 100))
    label = _label_from_score(score)

    return {
        "url": url,
        "label": label,
        "score": score,
        "reasons": reasons,
        "domain_age": domain_age,
        "ssl_certificate": ssl_info,
    }