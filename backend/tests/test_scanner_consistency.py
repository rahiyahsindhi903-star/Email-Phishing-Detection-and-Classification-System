"""
Automated Test Suite for Tri-Channel Scanner Consistency
=========================================================
Ensures that the URL Scanner, QR Code Scanner, and Email Scanner
always produce 100% identical URL risk scores and classifications
for the same normalized URL.
"""

import io
import unittest
import qrcode
from fastapi.datastructures import UploadFile

from app.services.url_scanner_service import normalize_url, scan_url_service
from app.services.email_scanner_service import scan_email_service
from app.main import scan_url, scan_qr, scan_email, URLScanRequest, EmailScanRequest


def make_qr_upload(url_text: str) -> UploadFile:
    qr = qrcode.QRCode(box_size=10, border=2)
    qr.add_data(url_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return UploadFile(filename="test_qr.png", file=buf)


class TestScannerConsistency(unittest.IsolatedAsyncioTestCase):

    async def test_safe_url_consistency(self):
        """Safe URLs must return identical score (0) and label ('safe') across URL, QR, and Email."""
        url = "https://www.google.com"
        
        # 1. URL Scanner
        res_url = await scan_url(URLScanRequest(url=url))
        url_score = res_url.get("score") if isinstance(res_url, dict) else res_url.score
        url_label = res_url.get("label") if isinstance(res_url, dict) else res_url.label

        # 2. QR Scanner
        res_qr = await scan_qr(file=make_qr_upload(url))
        qr_rep = res_qr.get("report", {})
        qr_score = qr_rep.get("score")
        qr_label = qr_rep.get("label")

        # 3. Email Scanner (URL in body)
        res_email = await scan_email(EmailScanRequest(body=f"Visit our homepage: {url}"))
        email_url_rep = res_email.per_url_reports[0] if hasattr(res_email, "per_url_reports") else res_email["per_url_reports"][0]
        email_url_score = email_url_rep["score"]
        email_url_label = email_url_rep["label"]

        self.assertEqual(url_score, 0)
        self.assertEqual(url_label, "safe")
        self.assertEqual(url_score, qr_score)
        self.assertEqual(url_score, email_url_score)
        self.assertEqual(url_label, qr_label)
        self.assertEqual(url_label, email_url_label)

    async def test_phishing_url_consistency(self):
        """Phishing URLs must return identical high risk score and 'phishing' label across URL, QR, and Email."""
        url = "http://paypa1.tk/verify/login-account"

        # 1. URL Scanner
        res_url = await scan_url(URLScanRequest(url=url))
        url_score = res_url.get("score") if isinstance(res_url, dict) else res_url.score
        url_label = res_url.get("label") if isinstance(res_url, dict) else res_url.label

        # 2. QR Scanner
        res_qr = await scan_qr(file=make_qr_upload(url))
        qr_rep = res_qr.get("report", {})
        qr_score = qr_rep.get("score")
        qr_label = qr_rep.get("label")

        # 3. Email Scanner
        res_email = await scan_email(EmailScanRequest(body=f"Security alert link: {url}"))
        email_url_rep = res_email.per_url_reports[0] if hasattr(res_email, "per_url_reports") else res_email["per_url_reports"][0]
        email_url_score = email_url_rep["score"]
        email_url_label = email_url_rep["label"]

        self.assertEqual(url_score, 70)
        self.assertEqual(url_label, "phishing")
        self.assertEqual(url_score, qr_score)
        self.assertEqual(url_score, email_url_score)
        self.assertEqual(url_label, qr_label)
        self.assertEqual(url_label, email_url_label)

    async def test_suspicious_url_consistency(self):
        """Suspicious URLs (e.g. raw IP host) must return identical score and 'suspicious' label across all 3 scanners."""
        url = "http://192.168.1.1/admin"

        res_url = await scan_url(URLScanRequest(url=url))
        url_score = res_url.get("score") if isinstance(res_url, dict) else res_url.score
        url_label = res_url.get("label") if isinstance(res_url, dict) else res_url.label

        res_qr = await scan_qr(file=make_qr_upload(url))
        qr_score = res_qr.get("report", {}).get("score")
        qr_label = res_qr.get("report", {}).get("label")

        res_email = await scan_email(EmailScanRequest(body=f"Router panel: {url}"))
        email_url_rep = res_email.per_url_reports[0] if hasattr(res_email, "per_url_reports") else res_email["per_url_reports"][0]
        email_url_score = email_url_rep["score"]
        email_url_label = email_url_rep["label"]

        self.assertEqual(url_score, 30)
        self.assertEqual(url_label, "suspicious")
        self.assertEqual(url_score, qr_score)
        self.assertEqual(url_score, email_url_score)
        self.assertEqual(url_label, qr_label)
        self.assertEqual(url_label, email_url_label)

    async def test_normalization_invariance(self):
        """Trailing periods, trailing slashes, and uppercase schemes must normalize to the exact same score."""
        variants = [
            "http://paypa1.tk/verify/login-account",
            "http://paypa1.tk/verify/login-account/",
            "http://paypa1.tk/verify/login-account.",
            "HTTP://PAYPA1.TK/VERIFY/LOGIN-ACCOUNT",
        ]
        scores = []
        labels = []
        for v in variants:
            res = await scan_url(URLScanRequest(url=v))
            s = res.get("score") if isinstance(res, dict) else res.score
            l = res.get("label") if isinstance(res, dict) else res.label
            scores.append(s)
            labels.append(l)

        # All variants must yield identical results
        self.assertTrue(all(s == scores[0] for s in scores))
        self.assertTrue(all(l == labels[0] for l in labels))

    async def test_email_overall_score_never_dilutes_url_threat(self):
        """An email containing a phishing link must have an overall email risk score >= link's risk score."""
        url = "http://paypa1.tk/verify/login-account"
        res_email = await scan_email(EmailScanRequest(body=f"Link: {url}"))
        overall_score = res_email.final_email_risk_score if hasattr(res_email, "final_email_risk_score") else res_email["final_email_risk_score"]
        overall_label = res_email.final_email_risk_label if hasattr(res_email, "final_email_risk_label") else res_email["final_email_risk_label"]

        self.assertGreaterEqual(overall_score, 70)
        self.assertEqual(overall_label, "phishing")


if __name__ == "__main__":
    unittest.main()

