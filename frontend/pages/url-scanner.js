import React, { useState } from "react";
import Link from "next/link";
import styles from "../styles/Home.module.css";
import scannerStyles from "../styles/Scanner.module.css";

export default function URLScanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [redirectChain, setRedirectChain] = useState(null);
  const [showPreview, setShowPreview] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url.trim()) {
      setError("Please enter a URL");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setRedirectChain(null);
    setShowPreview(false);

    try {
      const response = await fetch("http://127.0.0.1:8000/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to scan URL. Please check if the backend is running.");
      console.error("Scan error:", err);
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async () => {
    if (!url.trim()) {
      setError("Please enter a URL");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setRedirectChain(null);
    setShowPreview(false);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/url/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      const data = await res.json();

      setResult(data.scan_result);
      setRedirectChain(data.redirect_chain);
      // Automatically show preview when report is generated
      setShowPreview(true);
    } catch (err) {
      setError(err.message || "Failed to generate report.");
      console.error("Report error:", err);
    } finally {
      setLoading(false);
    }
  };

  const getLabelColor = (label) => {
    switch (label) {
      case "phishing":
        return "#d32f2f"; // Red
      case "suspicious":
        return "#f57c00"; // Orange
      case "safe":
        return "#388e3c"; // Green
      default:
        return "#757575"; // Gray
    }
  };

  const getLabelBgColor = (label) => {
    switch (label) {
      case "phishing":
        return "#ffebee";
      case "suspicious":
        return "#fff3e0";
      case "safe":
        return "#e8f5e9";
      default:
        return "#f5f5f5";
    }
  };

  // Function to get the sources/reasons for the flagging
  const getFlaggingSources = (result) => {
    const sources = [];

    // Check Google Safe Browsing
    if (result.reasons && result.reasons.some(reason => reason.includes("Google Safe Browsing"))) {
      sources.push("GSB");
    }

    // Check domain age
    if (result.reasons && result.reasons.some(reason => reason.includes("Domain is newly registered"))) {
      sources.push("Domain Age");
    }

    // Check SSL issues
    if (result.reasons && result.reasons.some(reason => reason.includes("SSL certificate"))) {
      sources.push("SSL Issues");
    }

    // Check AI analysis
    if (result.ai_analysis && result.ai_analysis.ai_score > 0) {
      sources.push(`AI Indicator: ${result.ai_analysis.indicators.slice(0, 2).join(", ")}`);
    }

    // Check OpenPhish
    if (result.reasons && result.reasons.some(reason => reason.includes("OpenPhish"))) {
      sources.push("OpenPhish");
    }

    return sources;
  };

  return (
    <div className={styles.container}>
      {/* Header */}
      <header className={styles.header}>
        <div className={styles.headerContent}>
          <div className={styles.logo}>
            <span className={styles.logoIcon}>🛡️</span>
            <span className={styles.logoText}>Phishing Detector</span>
          </div>
          <nav className={styles.nav}>
            <Link href="/" className={styles.navLink}>Home</Link>
            <Link href="/url-scanner" className={styles.navLink}>URL Scanner</Link>
            <Link href="/qr-scanner" className={styles.navLink}>QR Scanner</Link>
            <Link href="/email-scanner" className={styles.navLink}>Email Scanner</Link>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className={styles.main}>
        <div className={scannerStyles.scannerCard}>
          <h1 className={scannerStyles.title}>URL Scanner</h1>
          <p className={scannerStyles.description}>
            Paste a suspicious URL below and receive instant phishing analysis with detailed risk assessment.
          </p>

          <form onSubmit={handleScan} className={scannerStyles.form}>
            <div className={scannerStyles.inputGroup}>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL here (e.g., https://example.com)"
                className={scannerStyles.input}
                disabled={loading}
              />
              <button
                type="submit"
                className={scannerStyles.button}
                disabled={loading}
              >
                {loading ? "Scanning..." : "Scan URL"}
              </button>
            </div>
          </form>

          {/* Generate Report Button */}
          <div className={scannerStyles.screenshotButtonContainer}>
            <button
              onClick={generateReport}
              className={scannerStyles.screenshotButton}
              disabled={loading}
            >
              {loading ? "Generating Report..." : "Generate Full Report"}
            </button>
          </div>

          {error && (
            <div className={scannerStyles.errorBox}>
              <strong>Error:</strong> {error}
            </div>
          )}

          {result && (
            <div className={scannerStyles.resultBox}>
              <div
                className={scannerStyles.resultHeader}
                style={{
                  backgroundColor: getLabelBgColor(result.label),
                  borderLeft: `4px solid ${getLabelColor(result.label)}`,
                }}
              >
                <h2
                  className={scannerStyles.resultLabel}
                  style={{ color: getLabelColor(result.label) }}
                >
                  {result.label.toUpperCase()}
                </h2>
                <div className={scannerStyles.score}>
                  Risk Score: {result.score}/100
                </div>
              </div>

              <div className={scannerStyles.resultContent}>
                <div className={scannerStyles.resultItem}>
                  <strong>Scanned URL:</strong>
                  <a
                    href={result.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={scannerStyles.urlLink}
                  >
                    {result.url}
                  </a>
                </div>

                {result.reasons && result.reasons.length > 0 && (
                  <div className={scannerStyles.resultItem}>
                    <strong>Analysis Details:</strong>
                    <ul className={scannerStyles.reasonsList}>
                      {result.reasons.map((reason, index) => (
                        <li key={index}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.reasons && result.reasons.length === 0 && (
                  <div className={scannerStyles.resultItem}>
                    <p className={scannerStyles.noIssues}>
                      ✓ No suspicious indicators found
                    </p>
                  </div>
                )}

                {/* DOMAIN AGE */}
                <div className="result-section">
                  <h3>Domain Age</h3>
                  <p><strong>Created:</strong> {result.domain_age?.created}</p>
                  <p><strong>Age:</strong> {result.domain_age?.age_days} days</p>
                </div>

                {/* SSL CERTIFICATE */}
                <div className="result-section">
                  <h3>SSL Certificate</h3>
                  <p><strong>Issuer:</strong> {JSON.stringify(result.ssl_certificate?.issuer)}</p>
                  <p><strong>Valid From:</strong> {result.ssl_certificate?.valid_from}</p>
                  <p><strong>Valid To:</strong> {result.ssl_certificate?.valid_to}</p>
                  <p><strong>Status:</strong> {result.ssl_certificate?.valid ? "Valid" : "Invalid"}</p>
                </div>
              </div>
            </div>
          )}

          {/* Redirect Chain Display */}
          {redirectChain?.chain?.length > 0 && (
            <div className={scannerStyles.screenshotResultBox}>
              <h3>Redirect Chain Analysis</h3>
              <div className={scannerStyles.redirectChainSection}>
                {redirectChain.chain.map((step, i) => (
                  <div key={i} className={scannerStyles.redirectStep}>
                    <b>{step.status}</b> — {step.url}
                    {step.duration_ms && ` (${step.duration_ms}ms)`}
                    {step.error && ` - Error: ${step.error}`}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Website Preview for Safe Sites - With Sandboxed iframe */}
          {showPreview && result?.label === "safe" && (
            <div className={scannerStyles.websitePreviewContainer}>
              <h3 className={scannerStyles.previewTitle}>Website Preview</h3>
              <div className={scannerStyles.websitePreviewNotice}>
                <p>This preview is loaded in a sandboxed environment for your safety.</p>
                <p className={scannerStyles.previewWarning}>
                  ⚠️ Note: Some websites may not load properly due to security restrictions.
                </p>
              </div>
              {url ? (
                <iframe
                  src={url}
                  className={scannerStyles.websitePreviewFrame}
                  sandbox="allow-scripts allow-same-origin"
                  title="Website Preview"
                ></iframe>
              ) : (
                <p>No preview available</p>
              )}
            </div>
          )}

          {/* Blocked Preview for Unsafe Sites - Enhanced UI */}
          {showPreview && result && result.label !== "safe" && (
            <div className={scannerStyles.blockedPreviewCard}>
              <div className={scannerStyles.blockedPreviewHeader}>
                <h3 className={scannerStyles.blockedPreviewTitle}>
                  ⚠️ Preview Blocked for Your Safety
                </h3>
              </div>

              <div className={scannerStyles.blockedPreviewContent}>
                <p className={scannerStyles.blockedPreviewReason}>
                  This website has been flagged as <strong>{result.label}</strong> with a risk score of {result.score}/100.
                </p>

                <div className={scannerStyles.flaggingSources}>
                  <strong>Reasons blocked:</strong>
                  <ul className={scannerStyles.sourcesList}>
                    {getFlaggingSources(result).map((source, index) => (
                      <li key={index} className={scannerStyles.sourceItem}>{source}</li>
                    ))}
                  </ul>
                </div>

                <div className={scannerStyles.securityRisks}>
                  <p>For security reasons, the live preview is disabled to prevent:</p>
                  <ul className={scannerStyles.risksList}>
                    <li>Malware infection</li>
                    <li>Credential theft</li>
                    <li>Browser exploits</li>
                    <li>Social engineering attacks</li>
                  </ul>
                </div>

                <div className={scannerStyles.securityExplanation}>
                  <p className={scannerStyles.explanationLink}>
                    Why is preview blocked?
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}