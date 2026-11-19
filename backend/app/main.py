import asyncio
import base64
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from app.services.url_scanner_service import scan_url_service
from app.services.openphish_service import openphish
from app.services.qr_decoder import decode_qr_image
from app.services.email_scanner_service import scan_email_service


app = FastAPI(
    title="Phishing Detection API",
    version="0.1.0",
    description="URL, QR, and Email phishing detection service",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # allow all origins during development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def load_feeds():
    await openphish.load_feed()


class URLScanRequest(BaseModel):
    url: str


class URLScanResponse(BaseModel):
    url: str
    label: str
    score: int
    reasons: list[str]
    domain_age: Optional[Dict[str, Any]] = None
    ssl_certificate: Optional[Dict[str, Any]] = None


class URLRequestModel(BaseModel):
    url: str


class EmailScanRequest(BaseModel):
    subject: Optional[str] = ""
    sender: Optional[str] = ""
    body: Optional[str] = ""
    links: Optional[List[str]] = None


class EmailScanResponse(BaseModel):
    summary: str
    ai_text_score: int
    ai_text_label: Optional[str] = None
    ai_text_indicators: List[str]
    per_url_reports: List[Dict[str, Any]]
    sender_domain_report: Dict[str, Any]
    final_email_risk_score: int
    final_email_risk_label: str
    recommendations: List[str]


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.post("/scan/url", response_model=URLScanResponse)
async def scan_url(payload: URLScanRequest):
    result = await scan_url_service(payload.url)
    return result


@app.post("/scan/qr")
async def scan_qr(file: UploadFile = File(...)):
    """
    Accepts image upload (PNG/JPG), decodes QR, and if QR contains URL,
    scans it using the URL scanner.
    """
    image_bytes = await file.read()
    decoded = decode_qr_image(image_bytes)

    if not decoded:
        return {
            "decoded": None,
            "type": "invalid",
            "message": "No valid QR code found in image."
        }

    # If QR contains URL → scan with centralized canonical URL scanner
    from app.services.url_scanner_service import normalize_url
    import validators

    clean_decoded = decoded.strip() if decoded else ""
    norm_url = normalize_url(clean_decoded)
    if clean_decoded.lower().startswith(("http://", "https://")) or (norm_url and validators.url(norm_url)):
        url_result = await scan_url_service(norm_url)
        return {
            "decoded": decoded,
            "type": "url",
            "report": url_result
        }

    # Otherwise → return plain text
    return {
        "decoded": decoded,
        "type": "text",
        "message": "QR contains text data."
    }


@app.post("/scan/email", response_model=EmailScanResponse)
async def scan_email(payload: EmailScanRequest):
    """
    Scans email content for phishing indicators.
    Accepts subject, sender, body, and optional list of links.
    """
    result = await scan_email_service(
        subject=payload.subject or "",
        sender=payload.sender or "",
        body=payload.body or "",
        links=payload.links or []
    )
    return result


@app.post("/url/screenshot")
async def analyze_url_screenshot(request: URLRequestModel):
    """
    Analyze URL and return screenshot and redirect chain.
    """
    try:
        # Import the screenshot service here to avoid issues during startup
        from app.services.screenshot_service import get_redirect_chain, capture_screenshot
        
        # Get redirect chain
        redirect_chain = await get_redirect_chain(request.url)
        
        # Capture screenshot
        screenshot_bytes = await capture_screenshot(request.url)
        screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
        
        return {
            "redirect_chain": redirect_chain,
            "screenshot": screenshot_base64
        }
    except Exception as e:
        return {
            "redirect_chain": [],
            "screenshot": None,
            "error": str(e)
        }


# Import the new router
from app.routers.url_scanner import router as url_scanner_router

# Include the new router
app.include_router(url_scanner_router)