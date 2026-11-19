import React, { useState } from "react";
import Link from "next/link";
import Navbar from "../components/Navbar";
import styles from "../styles/Home.module.css";
import scannerStyles from "../styles/Scanner.module.css";

export default function EmailScanner() {
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [links, setLinks] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    
    if (!sender.trim() && !subject.trim() && !body.trim()) {
      setError("Please fill in at least one field (Sender, Subject, or Body)");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    // Parse links from textarea (one per line or comma-separated)
    const linksArray = links
      .split(/[\n,]/)
      .map(link => link.trim())
      .filter(link => link.length > 0);

    try {
      const response = await fetch("http://127.0.0.1:8000/scan/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender: sender.trim(),
          subject: subject.trim(),
          body: body.trim(),
          links: linksArray.length > 0 ? linksArray : undefined,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Failed to scan email. Please check if the backend is running.");
      console.error("Scan error:", err);
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

  const getRiskLabelColor = (label) => {
    switch (label) {
      case "phishing":
        return "#d32f2f";
      case "suspicious":
        return "#f57c00";
      case "safe":
        return "#388e3c";
      default:
        return "#757575";
    }
  };

  const getRiskBgColor = (label) => {
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

  const getLinkLabelClass = (label) => {
    switch (label) {
      case "phishing":
        return scannerStyles.linkItemPhishing;
      case "suspicious":
        return scannerStyles.linkItemSuspicious;
      case "safe":
        return scannerStyles.linkItemSafe;
      default:
        return "";
    }
  };

  return (
    <div className={styles.container}>
      {/* Navbar with interactive buttons */}
      <Navbar />

      {/* Main Content */}
      <main className={styles.main}>
        <div className={scannerStyles.scannerCard}>
          <h1 className={scannerStyles.title}>Email Scanner</h1>
          <p className={scannerStyles.description}>
            Analyze email content for phishing indicators. Paste the sender, subject, body, 
            and any links from suspicious emails to receive a detailed risk assessment.
          </p>

          <form onSubmit={handleScan} className={scannerStyles.form}>
            <div className={scannerStyles.fieldGroup}>
              <label htmlFor="sender" className={scannerStyles.fieldLabel}>
                Sender Email (optional)
              </label>
              <input
                id="sender"
                type="email"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder="sender@example.com"
                className={scannerStyles.input}
                disabled={loading}
              />
            </div>

            <div className={scannerStyles.fieldGroup}>
              <label htmlFor="subject" className={scannerStyles.fieldLabel}>
                Subject (optional)
              </label>
              <input
                id="subject"
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="Email subject line"
                className={scannerStyles.input}
                disabled={loading}
              />
            </div>

            <div className={scannerStyles.fieldGroup}>
              <label htmlFor="body" className={scannerStyles.fieldLabel}>
                Email Body (optional)
              </label>
              <textarea
                id="body"
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="Paste the email body content here..."
                className={scannerStyles.textarea}
                disabled={loading}
              />
            </div>

            <div className={scannerStyles.fieldGroup}>
              <label htmlFor="links" className={scannerStyles.fieldLabel}>
                Links (optional) - One per line or comma-separated
              </label>
              <textarea
                id="links"
                value={links}
                onChange={(e) => setLinks(e.target.value)}
                placeholder="https://example.com&#10;https://another-link.com"
                className={scannerStyles.textarea}
                style={{ minHeight: "100px" }}
                disabled={loading}
              />
            </div>

            <button
              type="submit"
              className={scannerStyles.button}
              disabled={loading}
            >
              {loading ? "Scanning..." : "Scan Email"}
            </button>
          </form>

          {error && (
            <div className={scannerStyles.errorBox}>
              <strong>Error:</strong> {error}
            </div>
          )}

          {result && (
            <div className={scannerStyles.resultBox}>
              {/* Final Email Risk Header */}
              <div
                className={scannerStyles.resultHeader}
                style={{
                  backgroundColor: getRiskBgColor(result.final_email_risk_label),
                  borderLeft: `4px solid ${getRiskLabelColor(
                    result.final_email_risk_label
                  )}`,
                }}
              >
                <h2
                  className={scannerStyles.resultLabel}
                  style={{
                    color: getRiskLabelColor(result.final_email_risk_label),
                  }}
                >
                  {result.final_email_risk_label
                    ? result.final_email_risk_label.toUpperCase()
                    : "EMAIL RISK"}
                </h2>
                <div className={scannerStyles.scoreStack}>
                  <div className={scannerStyles.score}>
                    Overall Email Risk Score:{" "}
                    {result.final_email_risk_score ?? 0}/100
                  </div>
                </div>
              </div>

              <div className={scannerStyles.resultContent}>
                {/* Summary */}
                {result.summary && (
                  <div className={scannerStyles.resultItem}>
                    <strong>Summary</strong>
                    <p>{result.summary}</p>
                  </div>
                )}

                {/* AI Phishing Indicators */}
                {result.ai_text_indicators && (
                  <div className={scannerStyles.resultItem}>
                    <strong>AI Phishing Indicators</strong>
                    <ul className={scannerStyles.reasonsList}>
                      {result.ai_text_indicators.map((reason, index) => (
                        <li key={index}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Sender Analysis */}
                {result.sender_domain_report && (
                  <div className={scannerStyles.resultItem}>
                    <strong>Sender Analysis</strong>
                    <ul className={scannerStyles.reasonsList}>
                      {result.sender_domain_report.address && (
                        <li>Sender: {result.sender_domain_report.address}</li>
                      )}
                      {result.sender_domain_report.domain && (
                        <li>Domain: {result.sender_domain_report.domain}</li>
                      )}
                      {result.sender_domain_report.email_type && (
                        <li>
                          Email Type:{" "}
                          {result.sender_domain_report.email_type.replace(
                            "_",
                            " "
                          )}
                        </li>
                      )}
                      {result.sender_domain_report.domain_age && (
                        <li>
                          Domain Age:{" "}
                          {result.sender_domain_report.domain_age.age_days ??
                            "Unknown"}{" "}
                          days
                        </li>
                      )}
                      {result.sender_domain_report.warnings &&
                        result.sender_domain_report.warnings.map(
                          (w, idx) => (
                            <li key={`sender-warning-${idx}`}>{w}</li>
                          )
                        )}
                    </ul>
                  </div>
                )}

                {/* Per-URL Reports */}
                {result.per_url_reports &&
                  result.per_url_reports.length > 0 && (
                    <div className={scannerStyles.resultItem}>
                      <strong>
                        URL Analysis ({result.per_url_reports.length} URL
                        {result.per_url_reports.length > 1 ? "s" : ""})
                      </strong>
                      <div className={scannerStyles.linkAnalysis}>
                        {result.per_url_reports.map((urlItem, index) => (
                          <div
                            key={index}
                            className={`${scannerStyles.linkItem} ${getLinkLabelClass(
                              urlItem.label
                            )}`}
                          >
                            <div style={{ marginBottom: "0.5rem" }}>
                              <strong
                                style={{
                                  color: getLabelColor(urlItem.label),
                                }}
                              >
                                {urlItem.label
                                  ? urlItem.label.toUpperCase()
                                  : "UNKNOWN"}
                              </strong>
                              {typeof urlItem.score === "number" && (
                                <span
                                  style={{
                                    marginLeft: "1rem",
                                    color: "#555",
                                    fontWeight: "600",
                                  }}
                                >
                                  URL Risk Score: {urlItem.score}/100
                                </span>
                              )}
                            </div>
                            <a
                              href={urlItem.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className={scannerStyles.urlLink}
                              style={{
                                display: "block",
                                marginBottom: "0.5rem",
                              }}
                            >
                              {urlItem.url}
                            </a>
                            {urlItem.reasons &&
                              urlItem.reasons.length > 0 && (
                                <ul
                                  className={scannerStyles.reasonsList}
                                  style={{ marginTop: "0.5rem" }}
                                >
                                  {urlItem.reasons
                                    .slice(0, 4)
                                    .map((reason, reasonIndex) => (
                                      <li
                                        key={reasonIndex}
                                        style={{ fontSize: "0.9rem" }}
                                      >
                                        {reason}
                                      </li>
                                    ))}
                                </ul>
                              )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                {/* Recommendations */}
                {result.recommendations &&
                  result.recommendations.length > 0 && (
                    <div className={scannerStyles.resultItem}>
                      <strong>Recommendations</strong>
                      <ul className={scannerStyles.reasonsList}>
                        {result.recommendations.map((rec, idx) => (
                          <li key={idx}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}



