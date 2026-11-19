"""
Email Phishing Scanner Service
================================
Scans email content (subject, body, sender, links) for phishing indicators.

URL scoring: each URL in the email is scored using the SAME canonical
`scan_url_service()` engine used by the URL Scanner and QR Scanner.
The per-URL `score` field is taken directly — no re-weighting.

The `final_email_risk_score` is a *separate* email-level aggregate that
combines the highest URL score, text analysis, and sender checks.
It is clearly labelled differently from the per-URL scores.
"""

import re
from typing import List, Dict, Any

import tldextract
import validators

from app.services.url_scanner_service import scan_url_service, normalize_url
from app.services.redirect_chain_service import get_redirect_chain
from app.services.domain_ssl_service import get_domain_age
from app.services.ai_email_analyzer import analyze_email_text


FREE_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "icloud.com",
}


def _extract_urls_from_text(text: str) -> List[str]:
    """
    Extracts URLs from plain text or HTML bodies.
    Strips trailing sentence punctuation (. , ; ! ? ) ] > quotes) and normalizes each URL.
    """
    if not text:
        return []
    pattern = r'(?:https?://|www\.)[^\s<>"\'\u201c\u201d\u2018\u2019]+'
    raw_matches = re.findall(pattern, text, flags=re.IGNORECASE)
    extracted: List[str] = []
    seen: set = set()
    for raw in raw_matches:
        norm = normalize_url(raw)
        if norm and norm not in seen and validators.url(norm):
            seen.add(norm)
            extracted.append(norm)
    return extracted


async def _analyze_urls(urls: List[str]) -> List[Dict[str, Any]]:
    """
    Score each URL using the canonical scan_url_service().
    The `score` returned here is IDENTICAL to what URL Scanner and QR Scanner show.
    """
    per_url_reports: List[Dict[str, Any]] = []

    for raw_url in urls[:10]:   # hard cap for performance
        try:
            norm_url = normalize_url(raw_url)
            scan_result = await scan_url_service(norm_url)
            redirect_chain = await get_redirect_chain(norm_url)

            report = {
                "url":           scan_result["url"],
                "label":         scan_result["label"],
                # ↓ This is the SAME score shown by the URL Scanner and QR Scanner
                "score":         scan_result["score"],
                "reasons":       scan_result.get("reasons", []),
                "domain_age":    scan_result.get("domain_age"),
                "ssl_info":      scan_result.get("ssl_certificate"),
                "redirect_chain": redirect_chain,
            }
        except Exception as exc:
            report = {
                "url":            raw_url,
                "label":          "error",
                "score":          None,
                "reasons":        [f"URL scan failed: {str(exc)}"],
                "domain_age":     None,
                "ssl_info":       None,
                "redirect_chain": {"chain": []},
            }

        per_url_reports.append(report)

    return per_url_reports


def _analyze_sender_domain(sender: str) -> Dict[str, Any]:
    """
    Basic sender authenticity checks:
    - domain age
    - free-mail provider warning
    - SPF/DMARC/DKIM placeholders
    """
    sender_report: Dict[str, Any] = {}

    if not sender:
        sender_report["present"] = False
        sender_report["notes"] = ["No sender address provided for analysis."]
        return sender_report

    sender_report["present"] = True
    sender_report["address"] = sender

    domain_part = sender.split("@")[-1].lower() if "@" in sender else ""
    sender_report["domain"] = domain_part or None

    if domain_part in FREE_PROVIDERS:
        sender_report["email_type"] = "free_provider"
        sender_report.setdefault("warnings", []).append(
            "Sender uses a free email provider. This can be legitimate but is often abused in phishing."
        )
    elif domain_part:
        sender_report["email_type"] = "business_or_custom"

    if domain_part:
        try:
            domain_age = get_domain_age(domain_part)
        except Exception as exc:
            domain_age = {"age_days": None, "error": str(exc)}
        sender_report["domain_age"] = domain_age
    else:
        sender_report["domain_age"] = None

    sender_report["spf"]  = {"status": "unknown", "details": "SPF lookup not implemented."}
    sender_report["dmarc"] = {"status": "unknown", "details": "DMARC lookup not implemented."}
    sender_report["dkim"] = {"status": "unknown", "details": "DKIM validation not implemented."}

    return sender_report


async def scan_email_service(
    subject: str = "",
    sender: str = "",
    body: str = "",
    links: List[str] | None = None,
) -> dict:
    """
    Scans email content for phishing indicators.

    The `final_email_risk_score` is an EMAIL-LEVEL aggregate (combines URL
    scores, text analysis, and sender reputation). It is intentionally
    different from any single URL's score because it reflects the overall
    email risk, not just one link.

    Per-URL `score` values are identical to what the URL Scanner produces.

    Returns:
        {
          "summary":                  str,
          "ai_text_score":            int,
          "ai_text_label":            str | None,
          "ai_text_indicators":       List[str],
          "per_url_reports":          List[dict],
          "sender_domain_report":     dict,
          "final_email_risk_score":   int,
          "final_email_risk_label":   str,
          "recommendations":          List[str],
        }
    """
    links = links or []

    # 1. Collect and canonically normalize all URLs
    all_urls: List[str] = []
    seen: set = set()

    for raw in links:
        norm = normalize_url(raw)
        if norm and norm not in seen and validators.url(norm):
            seen.add(norm)
            all_urls.append(norm)

    extracted_from_subject = _extract_urls_from_text(subject)
    for norm in extracted_from_subject:
        if norm not in seen and validators.url(norm):
            seen.add(norm)
            all_urls.append(norm)

    extracted_from_body = _extract_urls_from_text(body)
    for norm in extracted_from_body:
        if norm not in seen and validators.url(norm):
            seen.add(norm)
            all_urls.append(norm)

    # 2. AI-style text analysis on subject + body
    text_ai = analyze_email_text(subject=subject, body=body, sender=sender)

    # 3. Sender domain analysis
    sender_report = _analyze_sender_domain(sender)

    # 4. Per-URL analysis — scores are IDENTICAL to URL Scanner
    per_url_reports = await _analyze_urls(all_urls)

    # ─────────────────────────────────────────────────────────────────────
    # 5. Compute EMAIL-LEVEL risk score
    #    This is separate from per-URL scores and uses a weighted formula
    #    that considers the overall email context.
    # ─────────────────────────────────────────────────────────────────────

    # 5a. Highest URL risk score among all links in the email
    max_url_score = 0
    has_phishing_url = False
    has_suspicious_url = False
    for rep in per_url_reports:
        s = rep.get("score")
        if isinstance(s, int):
            max_url_score = max(max_url_score, s)
        lbl = rep.get("label")
        if lbl == "phishing":
            has_phishing_url = True
        elif lbl == "suspicious":
            has_suspicious_url = True

    # 5b. Sender domain age component
    sender_age = sender_report.get("domain_age") or {}
    sender_age_days = sender_age.get("age_days")
    sender_component = 0
    if isinstance(sender_age_days, int):
        if sender_age_days < 30:
            sender_component = 30
        elif sender_age_days < 180:
            sender_component = 15

    # 5c. Text analysis score
    text_component = int(text_ai.get("ai_text_score", 0))

    # 5d. Extra heuristic signals
    extra_indicators: List[str] = []
    rule_boost = 0

    combined_text = f"{subject or ''}\n{body or ''}"
    if re.search(r"\burgent\b|\bverify\b|\bwithin\s+\d+\s+hours\b", combined_text, re.IGNORECASE):
        rule_boost += 15
        extra_indicators.append("Urgency language detected (e.g., urgent / verify / within N hours).")

    if has_phishing_url or has_suspicious_url:
        extra_indicators.append("One or more links in the email are flagged as phishing or suspicious.")

    # Sender domain vs first-link domain mismatch
    sender_domain = sender.split("@")[-1].lower() if sender and "@" in sender else None
    first_link_domain = None
    if per_url_reports:
        first_url = per_url_reports[0].get("url") or ""
        if first_url:
            ext = tldextract.extract(first_url)
            first_link_domain = (
                f"{ext.domain}.{ext.suffix}".lower()
                if ext.suffix
                else ext.domain.lower()
            )
    if sender_domain and first_link_domain and sender_domain != first_link_domain:
        rule_boost += 10
        extra_indicators.append(
            f"Sender domain ({sender_domain}) does not match the primary link domain ({first_link_domain})."
        )

    # ─────────────────────────────────────────────────────────────────
    # OVERALL EMAIL RISK SCORE:
    # An email containing a URL must NEVER dilute that URL's threat level.
    # The email risk is at least the highest URL score, plus any email-level
    # threats (suspicious sender, text urgency, brand mismatch).
    # ─────────────────────────────────────────────────────────────────
    if per_url_reports:
        email_content_risk = max(text_component, sender_component)
        final_score = max(max_url_score, email_content_risk) + rule_boost
    else:
        final_score = max(text_component, sender_component) + rule_boost

    final_score = max(0, min(final_score, 100))

    # ─────────────────────────────────────────────────────────────────────
    # 6. Labels and summary
    # ─────────────────────────────────────────────────────────────────────
    if final_score >= 60:
        final_label = "phishing"
        summary = "This email is highly likely to be a phishing attempt."
    elif final_score >= 30:
        final_label = "suspicious"
        summary = "This email shows several suspicious indicators and should be treated with caution."
    else:
        final_label = "safe"
        summary = "No strong phishing indicators were detected, but always verify before acting on emails."

    # 7. Recommendations
    recommendations: List[str] = []
    if final_label != "safe":
        recommendations.append(
            "Do not click on any links or open attachments from this email until you verify the sender through a trusted channel."
        )
    if per_url_reports:
        recommendations.append(
            "Hover over links in the email and verify they match the legitimate domain before visiting."
        )
    if sender_report.get("email_type") == "free_provider":
        recommendations.append(
            "Be extra careful with sensitive requests coming from free email providers claiming to be official institutions."
        )

    # Merge extra indicators into AI indicators
    combined_indicators = list(text_ai.get("indicators", []) or [])
    combined_indicators.extend(extra_indicators)

    return {
        "summary":                summary,
        "ai_text_score":          text_component,
        "ai_text_label":          text_ai.get("ai_text_label"),
        "ai_text_indicators":     combined_indicators,
        "per_url_reports":        per_url_reports,
        "sender_domain_report":   sender_report,
        "final_email_risk_score": final_score,
        "final_email_risk_label": final_label,
        "recommendations":        recommendations,
    }
