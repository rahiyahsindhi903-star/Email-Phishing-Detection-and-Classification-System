# Email Phishing Detection and Classification System

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Next.js 14](https://img.shields.io/badge/Frontend-Next.js%2014-black.svg)](https://nextjs.org/)
[![OpenCV](https://img.shields.io/badge/Computer%20Vision-OpenCV%20%7C%20Pyzbar-green.svg)](https://opencv.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A multi-channel, explainable cybersecurity threat detection suite designed to analyze and classify phishing attempts across **URLs**, **QR Codes (Quishing)**, and **Email Content**. 

Built with an asynchronous **FastAPI** backend and an interactive **Next.js** web interface, the system leverages multi-layered heuristic intelligence, lexical analysis, domain reputation, TLS/SSL inspection, and live threat intelligence feeds (Google Safe Browsing & OpenPhish).

---

## 📌 Repository Description (for GitHub "About")

> **A multi-channel, explainable phishing detection and classification system for URLs, QR codes (quishing), and emails. Features a centralized heuristic risk engine, Google Safe Browsing and OpenPhish threat intelligence, and an interactive Next.js dashboard.**

### Suggested GitHub Topics / Tags
`phishing-detection` • `email-security` • `cybersecurity` • `url-scanner` • `qr-code-scanner` • `quishing-defense` • `fastapi` • `nextjs` • `threat-intelligence` • `heuristic-analysis` • `python`

---

## 🌟 Key Features

### 1. Tri-Channel Phishing Scanners
- **🔗 URL Scanner**: Inspects submitted links against 12+ lexical rules, brand-spoofing dictionaries, domain age via WHOIS, SSL/TLS certificate validity, and follows HTTP redirect chains.
- **📷 QR Code Scanner (Anti-Quishing)**: Decodes QR codes from image uploads (OpenCV + pyzbar) or real-time webcam streams (`@zxing/browser`), extracting the target URL and routing it through the canonical risk engine.
- **📧 Email Scanner**: Analyzes raw email text/headers, parses embedded URLs, checks sender domain mismatch (e.g., claiming to be PayPal from a generic webmail address), and applies 8 categories of urgency/coercion heuristics.

### 2. Centralized Funnel Architecture
All URLs discovered—whether entered directly, extracted from an email body, or decoded from a QR code—are evaluated by the **single canonical URL Risk Engine**. This guarantees 100% cross-scanner score consistency across all input vectors.

### 3. Multi-Layered Heuristic & Threat Intelligence Scoring
- **Lexical & Syntactic Indicators**: Suspicious Top-Level Domains (TLDs like `.tk`, `.ml`, `.xyz`, `.top`), IP-based hostnames, excessive subdomains, brand typosquatting, URL shorteners, and high Shannon entropy.
- **Dynamic Threat Feeds**: Real-time lookups against **Google Safe Browsing API v4** and live **OpenPhish** community threat lists.
- **Domain & SSL Analysis**: Flags domains created within the last 30/180 days and identifies expired, self-signed, or untrusted TLS certificates.
- **Sandboxed Visual Previews**: Isolated Playwright browser capture that automatically enables a **Safety Block Card** whenever a URL is categorized as high-risk phishing.

---

## 📊 Classification & Risk Score Thresholds

Every scan generates an explainable **Risk Score (0–100)** and a clear security classification:

| Score Range | Classification | Color Code | Action / Meaning |
| :---: | :---: | :---: | :--- |
| **0 – 29** | `safe` | 🟢 Green | Low risk, legitimate domain, valid SSL, clean threat feeds. |
| **30 – 59** | `suspicious` | 🟡 Yellow | Moderate risk indicators (e.g., free mail sender + urgent phrasing). |
| **60 – 100** | `phishing` | 🔴 Red | High risk, confirmed threat feed match, or multiple phishing heuristics triggered. |

### Multi-Signal Email Risk Formula
$$\text{Score}_{\text{email}} = \max\left(\max(\text{URL Scores}),\; 0.4 \times S_{\text{text}} + 0.3 \times S_{\text{sender}} + 0.3 \times S_{\text{url\_penalty}}\right)$$

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend Framework** | Python 3.10+, FastAPI, Uvicorn, Pydantic |
| **HTTP & Networking** | HTTPX (Asynchronous HTTP client) |
| **Computer Vision / QR** | OpenCV (`cv2`), `pyzbar` (ZBar barcode reader) |
| **Threat Intelligence** | Google Safe Browsing API v4, OpenPhish Community Feed |
| **Domain & SSL** | `python-whois`, Python standard `ssl` / `socket` |
| **Browser Automation** | Playwright (Isolated screenshot rendering) |
| **Frontend Framework** | Next.js 14, React 18, Tailwind CSS / CSS Modules |
| **Client-Side Vision** | `@zxing/browser` (Real-time camera barcode decoder) |

---

## 📂 Project Directory Structure

```text
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI application entry point, CORS & routers
│   │   ├── config.py                  # Environment settings (API keys, feed URLs, timeouts)
│   │   ├── routers/
│   │   │   ├── scan.py                # Endpoints: /scan/url, /scan/qr, /scan/email
│   │   │   └── api_url.py             # Endpoint: /api/url/report (Full diagnostic reports)
│   │   └── services/
│   │       ├── url_scanner_service.py # Canonical 100-point URL heuristic scoring engine
│   │       ├── email_scanner_service.py # Email parser, sender verification & score aggregation
│   │       ├── ai_email_analyzer.py   # 8-category rule-based email text heuristic analyzer
│   │       ├── qr_decoder.py          # OpenCV & pyzbar image decoding pipeline
│   │       ├── gsb_service.py         # Google Safe Browsing API v4 client
│   │       ├── openphish_service.py   # OpenPhish live feed parser with local cache
│   │       ├── redirect_chain_service.py # Async HTTP redirect chain tracer
│   │       └── screenshot_service.py  # Playwright headless screenshot engine
│   ├── tests/
│   │   └── test_ai_phish_analyzer.py  # Comprehensive test cases for text heuristics
│   ├── requirements.txt               # Backend dependencies
│   └── run.py                         # Local backend startup script
│
├── frontend/
│   ├── pages/
│   │   ├── index.js                   # Unified security dashboard & hub
│   │   ├── url-scanner.js             # Standalone URL scanner interface
│   │   ├── qr-scanner.js              # QR image upload & live webcam scanner
│   │   └── email-scanner.js           # Full email content & header analysis page
│   ├── styles/                        # Modular and global CSS styling
│   ├── package.json                   # Frontend dependencies and scripts
│   └── next.config.js                 # Next.js configuration
│
├── .gitignore                         # Configured Git ignore rules
└── README.md                          # Project documentation
```

---

## 🚀 Getting Started

### Prerequisites
- **Python**: Version 3.10, 3.11, or 3.12
- **Node.js**: Version 18.x or 20.x (with `npm`)

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/<your-username>/email-phishing-detection-system.git
cd email-phishing-detection-system
```

---

### Step 2: Backend Setup (FastAPI)

1. Navigate to the `backend` directory:
   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. *(Optional)* Install Playwright browser binaries for visual screenshots:
   ```bash
   playwright install chromium
   ```

5. Configure environment variables:
   Create a `.env` file inside `backend/` (or copy from `.env.example`):
   ```env
   GSB_API_KEY=your_google_safe_browsing_api_key_here
   OPENPHISH_FEED_URL=https://openphish.com/feed.txt
   ```
   *(Note: The system functions seamlessly with fallback heuristics even without an external API key).*

6. Start the FastAPI development server:
   ```bash
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
   - API Server: `http://127.0.0.1:8000`
   - Interactive Swagger API Docs: `http://127.0.0.1:8000/docs`

---

### Step 3: Frontend Setup (Next.js)

1. Open a new terminal and navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the Next.js development server:
   ```bash
   npm run dev
   ```
   - Web Application: `http://localhost:3000`

---

## 🔌 API Endpoints Summary

| Method | Endpoint | Description | Request Payload |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Service health status check | None |
| `POST` | `/scan/url` | Fast URL risk scan | `{"url": "https://example.com"}` |
| `POST` | `/api/url/report` | Full diagnostic report with SSL, WHOIS & preview | `{"url": "https://example.com"}` |
| `POST` | `/scan/qr` | Decodes QR code and scores target URL | `multipart/form-data` (`file`) |
| `POST` | `/scan/email` | Multi-signal email risk analysis | `{"email_text": "...", "sender": "..."}` |

---

## 🧪 Running Unit Tests

Run the backend unit test suite to verify heuristic rules and scoring accuracy:

```bash
cd backend
python -m unittest tests/test_ai_phish_analyzer.py
```

Expected output:
```text
.......
----------------------------------------------------------------------
Ran 7 tests in 0.003s

OK
```

---

## 🎓 Academic Context

This project was developed as an **On-the-Job Training (OJT)** project for:
- **Institution**: AURO University, Surat, Gujarat
- **Department**: School of Information Technology
- **Degree**: Bachelor of Science in Information Technology (B.Sc. IT)
- **Academic Year**: 2026–27 (Semester VII, 6 Credits)

---

## 🛡️ Responsible Disclosure & License

This project is developed for educational, defensive, and research purposes. Testing should only be conducted on owned systems or authorized domains.

Distributed under the **MIT License**. See `LICENSE` for more information.

