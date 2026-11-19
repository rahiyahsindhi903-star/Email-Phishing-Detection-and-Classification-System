import io
import asyncio
import qrcode
from fastapi.datastructures import UploadFile
from app.main import scan_qr, URLScanRequest, scan_url, EmailScanRequest, scan_email

def make_qr_upload_file(data: str) -> UploadFile:
    qr = qrcode.QRCode(box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return UploadFile(filename="qr.png", file=buf)

test_cases = [
    ("Safe URL", "https://www.google.com"),
    ("Safe with Trailing Slash", "https://www.google.com/"),
    ("Suspicious IP Host", "http://192.168.1.1/admin"),
    ("Suspicious URL Shortener", "http://bit.ly/secure-login"),
    ("Phishing Lookalike Domain", "http://paypa1.tk/verify/login-account"),
    ("Phishing with Trailing Dot", "http://paypa1.tk/verify/login-account."),
    ("Phishing with Uppercase Scheme", "HTTP://PAYPA1.TK/VERIFY/LOGIN-ACCOUNT"),
    ("Phishing Brand Spoof", "https://paypal-update-account.com/login.php"),
]

async def run_tri_scanner_verification():
    print("=" * 80)
    print("TRI-CHANNEL SCANNER CONSISTENCY VERIFICATION")
    print("Testing URL Scanner, QR Scanner, and Email Scanner on Identical URLs")
    print("=" * 80)
    
    all_matched = True
    
    for label, raw_url in test_cases:
        print(f"\n--- Scenario: {label} [{raw_url}] ---")
        
        # 1. URL Scanner via FastAPI endpoint
        url_res = await scan_url(URLScanRequest(url=raw_url))
        url_score = url_res.get("score") if isinstance(url_res, dict) else url_res.score
        url_label = url_res.get("label") if isinstance(url_res, dict) else url_res.label
        norm_url = url_res.get("url") if isinstance(url_res, dict) else url_res.url
        
        # 2. QR Code Scanner via FastAPI endpoint
        qr_file = make_qr_upload_file(raw_url)
        qr_res = await scan_qr(file=qr_file)
        qr_report = qr_res.get("report", {})
        qr_score = qr_report.get("score")
        qr_label = qr_report.get("label")
        
        # 3. Email Scanner via FastAPI endpoint (URL in body)
        email_body = f"Please click this link immediately: {raw_url}"
        email_res = await scan_email(EmailScanRequest(body=email_body))
        
        url_reports = email_res.get("per_url_reports", []) if isinstance(email_res, dict) else email_res.per_url_reports
        if not url_reports:
            print("  ❌ Email Scanner failed to extract URL!")
            all_matched = False
            continue
            
        email_url_rep = url_reports[0]
        email_url_score = email_url_rep.get("score")
        email_url_label = email_url_rep.get("label")
        email_overall_score = email_res.get("final_email_risk_score") if isinstance(email_res, dict) else email_res.final_email_risk_score
        email_overall_label = email_res.get("final_email_risk_label") if isinstance(email_res, dict) else email_res.final_email_risk_label
        
        print(f"  Normalized URL     : {norm_url}")
        print(f"  URL Scanner        : Score = {url_score:>3}, Label = {url_label:<10}")
        print(f"  QR Scanner         : Score = {qr_score:>3}, Label = {qr_label:<10}")
        print(f"  Email Embedded URL : Score = {email_url_score:>3}, Label = {email_url_label:<10}")
        print(f"  Email Overall Risk : Score = {email_overall_score:>3}, Label = {email_overall_label:<10}")
        
        # Verify 100% score and label match across URL, QR, and Email embedded URL
        if url_score == qr_score == email_url_score and url_label == qr_label == email_url_label:
            print("  [PASS] 100% PERFECT MATCH across all 3 scanners!")
        else:
            print(f"  [FAIL] MISMATCH DETECTED: URL({url_score}, {url_label}) vs QR({qr_score}, {qr_label}) vs Email({email_url_score}, {email_url_label})")
            all_matched = False
            
    print("\n" + "=" * 80)
    if all_matched:
        print("ALL SCENARIOS PASSED: 100% TRI-SCANNER SCORE & CLASSIFICATION CONSISTENCY!")
    else:
        print("SOME SCENARIOS FAILED! Check mismatch logs above.")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_tri_scanner_verification())
