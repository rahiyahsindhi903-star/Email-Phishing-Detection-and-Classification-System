import React, { useState, useRef, useEffect, useCallback } from "react";
import Link from "next/link";
import Navbar from "../components/Navbar";
import styles from "../styles/Home.module.css";
import scannerStyles from "../styles/Scanner.module.css";

export default function QRScanner() {
  const [activeTab, setActiveTab] = useState("upload"); // "upload" or "camera"
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [decodedText, setDecodedText] = useState("");
  const [scanning, setScanning] = useState(false);
  
  const videoRef = useRef(null);
  const codeReaderRef = useRef(null);
  const fileInputRef = useRef(null);

  const handleQRScan = useCallback(async (url) => {
    if (!url) {
      setError("No URL found in QR code");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      // Use the same URL scanning engine as the URL scanner page,
      // and normalize the response into the full-report shape.
      const response = await fetch("http://127.0.0.1:8000/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const scanData = await response.json();
      const finalLabel = scanData.final_label || scanData.label;

      setResult({
        decoded: url,
        type: "url",
        report: {
          url: scanData.url,
          label: finalLabel,
          score: scanData.score,
          reasons: scanData.reasons || [],
          domain_age: scanData.domain_age,
          ssl_certificate_details: scanData.ssl_certificate,
          redirect_chain: null,
          website_preview: null,
          preview_blocked_reason: null,
        },
      });
    } catch (err) {
      setError(
        err.message ||
          "Failed to scan URL. Please check if the backend is running."
      );
      console.error("Scan error:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("http://127.0.0.1:8000/scan/qr", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      
      // Handle the response correctly based on the backend implementation
      if (data.type === "url" && data.report) {
        const scanReport = data.report;
        const label = scanReport.final_label || scanReport.label;

        setResult({
          decoded: data.decoded,
          type: "url",
          report: {
            url: scanReport.url || data.decoded,
            label,
            score: scanReport.score ?? scanReport.rule_based_score,
            reasons: scanReport.reasons || [],
            domain_age: scanReport.domain_age,
            ssl_certificate_details:
              scanReport.ssl_info || scanReport.ssl_certificate || scanReport.ssl_certificate_details,
            redirect_chain: scanReport.redirect_chain || null,
            website_preview: scanReport.website_preview || null,
            preview_blocked_reason:
              scanReport.preview_blocked_reason || null,
          },
        });
      } else {
        // For text or invalid QR codes
        setResult(data);
      }
      
      if (data?.decoded) {
        setDecodedText(data.decoded);
      }
    } catch (err) {
      setError(err.message || "Failed to scan QR code. Please check if the backend is running.");
      console.error("Scan error:", err);
    } finally {
      setLoading(false);
    }
  };

  // Camera scanning logic - dynamically load @zxing/browser only when camera is active
  useEffect(() => {
    let active = true;

    if (activeTab === "camera" && videoRef.current) {
      setScanning(true);
      import("@zxing/browser")
        .then(({ BrowserMultiFormatReader }) => {
          if (!active || !videoRef.current) return;
          const codeReader = new BrowserMultiFormatReader();
          codeReaderRef.current = codeReader;

          codeReader.decodeFromVideoDevice(
            null,
            videoRef.current,
            (result, err) => {
              if (result && active) {
                setDecodedText(result.getText());
                setScanning(false);
                codeReader.reset();
                codeReaderRef.current = null;

                // Auto-scan if it's a URL
                if (
                  result.getText().startsWith("http://") ||
                  result.getText().startsWith("https://")
                ) {
                  handleQRScan(result.getText());
                }
              }
            }
          );
        })
        .catch((err) => {
          console.error("Camera scanner loading error:", err);
          setError("Failed to initialize camera scanner.");
        });
    }

    return () => {
      active = false;
      if (codeReaderRef.current) {
        try {
          codeReaderRef.current.reset();
          codeReaderRef.current = null;
        } catch (e) {
          // Ignore cleanup errors
        }
      }
    };
  }, [activeTab, handleQRScan]);

  const getLabelColor = (label) => {
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

  const getAiBadge = (score) => {
    if (score >= 60) {
      return {
        label: "PHISHING",
        color: "#fff",
        background: "#d32f2f",
      };
    }
    if (score >= 30) {
      return {
        label: "SUSPICIOUS",
        color: "#4e3200",
        background: "#ffecb3",
      };
    }
    return {
      label: "SAFE",
      color: "#1b5e20",
      background: "#c8e6c9",
    };
  };

  return (
    <div className={styles.container}>
      {/* Navbar with interactive buttons */}
      <Navbar />

      {/* Main Content */}
      <main className={styles.main}>
        <div className={scannerStyles.scannerCard}>
          <h1 className={scannerStyles.title}>QR Scanner</h1>
          <p className={scannerStyles.description}>
            Upload a QR code image or use your camera to scan QR codes. If the QR code contains a URL, 
            it will be automatically scanned for phishing threats.
          </p>

          <div
            style={{
              marginBottom: "1.5rem",
              padding: "0.75rem 1rem",
              borderRadius: 8,
              backgroundColor: "#fff3e0",
              borderLeft: "4px solid #f57c00",
              color: "#4e342e",
              fontSize: "0.95rem",
            }}
          >
            <strong>Security Tip:</strong> QR codes can contain malicious URLs.
            Always scan them before opening.
          </div>

          {/* Tabs */}
          <div className={scannerStyles.tabs}>
            <button
              className={`${scannerStyles.tab} ${activeTab === "upload" ? scannerStyles.tabActive : ""}`}
              onClick={() => setActiveTab("upload")}
            >
              📁 Upload Image
            </button>
            <button
              className={`${scannerStyles.tab} ${activeTab === "camera" ? scannerStyles.tabActive : ""}`}
              onClick={() => setActiveTab("camera")}
            >
              📷 Camera Scanner
            </button>
          </div>

          {/* Upload Tab */}
          {activeTab === "upload" && (
            <div className={scannerStyles.tabContent}>
              <div className={scannerStyles.inputGroup}>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  onChange={handleFileUpload}
                  className={scannerStyles.fileInput}
                  id="qr-file-input"
                />
                <label
                  htmlFor="qr-file-input"
                  className={scannerStyles.fileInputLabel}
                >
                  {loading ? "Processing..." : "Choose QR Code Image"}
                </label>
              </div>

              {error && (
                <div className={scannerStyles.errorBox}>
                  <strong>Error:</strong> {error}
                </div>
              )}
            </div>
          )}

          {/* Camera Tab */}
          {activeTab === "camera" && (
            <div className={scannerStyles.tabContent}>
              <div className={scannerStyles.videoContainer}>
                <video
                  ref={videoRef}
                  className={scannerStyles.video}
                  autoPlay
                  playsInline
                />
                {scanning && !decodedText && (
                  <p>Point your camera at a QR code...</p>
                )}
              </div>

              {decodedText && (
                <div className={scannerStyles.decodedText}>
                  <strong>QR Code Decoded Successfully</strong>
                  <div style={{ marginTop: "0.35rem" }}>{decodedText}</div>
                  {decodedText.startsWith("http://") || decodedText.startsWith("https://") ? (
                    <div style={{ marginTop: "1rem" }}>
                      <button
                        className={scannerStyles.button}
                        onClick={() => handleQRScan(decodedText)}
                        disabled={loading}
                      >
                        {loading ? "Scanning..." : "Scan URL for Phishing"}
                      </button>
                    </div>
                  ) : (
                    <p style={{ marginTop: "0.5rem", color: "#757575" }}>
                      This QR code contains text data, not a URL.
                    </p>
                  )}
                </div>
              )}

              {error && (
                <div className={scannerStyles.errorBox}>
                  <strong>Error:</strong> {error}
                </div>
              )}
            </div>
          )}

          {/* Results */}
          {result && (
            <div className={scannerStyles.resultBox}>
              {result.type === "invalid" && (
                <div className={scannerStyles.resultContent}>
                  <p style={{ color: "#d32f2f" }}>{result.message}</p>
                </div>
              )}

              {result.type === "text" && (
                <div className={scannerStyles.resultContent}>
                  <div
                    style={{
                      marginBottom: "1rem",
                      padding: "0.5rem 0.75rem",
                      borderRadius: 6,
                      backgroundColor: "#e8f5e9",
                      color: "#1b5e20",
                      fontWeight: 500,
                    }}
                  >
                    QR Code Decoded Successfully
                  </div>
                  <div className={scannerStyles.resultItem}>
                    <strong>Decoded Text:</strong>
                    <p>{result.decoded}</p>
                  </div>
                  <p style={{ color: "#757575" }}>{result.message}</p>
                </div>
              )}

              {result.type === "url" && result.report && (
                <>
                  <div
                    className={scannerStyles.resultHeader}
                    style={{
                      backgroundColor: getLabelBgColor(result.report.label),
                      borderLeft: `4px solid ${getLabelColor(
                        result.report.label
                      )}`,
                    }}
                  >
                    <h2
                      className={scannerStyles.resultLabel}
                      style={{ color: getLabelColor(result.report.label) }}
                    >
                      {result.report.label?.toUpperCase()}
                    </h2>
                    <div className={scannerStyles.scoreStack}>
                      <div className={scannerStyles.score}>
                        Risk Score: {result.report.score ?? 0}/100
                      </div>
                    </div>
                  </div>

                  <div className={scannerStyles.resultContent}>
                    <div
                      style={{
                        marginBottom: "1rem",
                        padding: "0.5rem 0.75rem",
                        borderRadius: 6,
                        backgroundColor: "#e8f5e9",
                        color: "#1b5e20",
                        fontWeight: 500,
                      }}
                    >
                      QR Code Decoded Successfully
                    </div>

                    <div className={scannerStyles.resultItem}>
                      <strong>QR Code URL:</strong>
                      <a
                        href={result.report.url || result.decoded}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={scannerStyles.urlLink}
                      >
                        {result.report.url || result.decoded}
                      </a>
                    </div>



                    {result.report.domain_age && (
                      <div className={scannerStyles.resultItem}>
                        <strong>Domain Age</strong>
                        <p>
                          Created:{" "}
                          {result.report.domain_age.creation_date ||
                            result.report.domain_age.created ||
                            "Unknown"}
                        </p>
                        <p>
                          Age:{" "}
                          {result.report.domain_age.age_days ?? "Unknown"} days
                        </p>
                        {result.report.domain_age.error && (
                          <p className={scannerStyles.errorBox}>
                            Error: {result.report.domain_age.error}
                          </p>
                        )}
                      </div>
                    )}

                    {result.report.ssl_certificate_details && (
                      <div className={scannerStyles.resultItem}>
                        <strong>SSL Certificate</strong>
                        <p>
                          Issuer:{" "}
                          {JSON.stringify(
                            result.report.ssl_certificate_details.issuer
                          )}
                        </p>
                        <p>
                          Valid From:{" "}
                          {result.report.ssl_certificate_details.valid_from ||
                            "Unknown"}
                        </p>
                        <p>
                          Valid To:{" "}
                          {result.report.ssl_certificate_details.valid_to ||
                            "Unknown"}
                        </p>
                        {result.report.ssl_certificate_details.error && (
                          <p className={scannerStyles.errorBox}>
                            Error:{" "}
                            {result.report.ssl_certificate_details.error}
                          </p>
                        )}
                      </div>
                    )}

                    {result.report.reasons &&
                      result.report.reasons.length > 0 && (
                        <div className={scannerStyles.resultItem}>
                          <strong>Analysis Details:</strong>
                          <ul className={scannerStyles.reasonsList}>
                            {result.report.reasons.map((reason, index) => (
                              <li key={index}>{reason}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                    {result.report.reasons &&
                      result.report.reasons.length === 0 && (
                        <div className={scannerStyles.resultItem}>
                          <p className={scannerStyles.noIssues}>
                            ✓ No suspicious indicators found
                          </p>
                        </div>
                      )}
                  </div>

                  {/* Redirect Chain (if available from backend) */}
                  {result.report.redirect_chain?.chain?.length > 0 && (
                    <div className={scannerStyles.screenshotResultBox}>
                      <h3>Redirect Chain Analysis</h3>
                      <div className={scannerStyles.redirectChainSection}>
                        {result.report.redirect_chain.chain.map((step, i) => (
                          <div
                            key={i}
                            className={scannerStyles.redirectStep}
                          >
                            <b>{step.status}</b> — {step.url}
                            {step.duration_ms &&
                              ` (${step.duration_ms}ms)`}
                            {step.error && ` - Error: ${step.error}`}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Website Preview (safe only, when provided by backend) */}
                  {result.report.website_preview &&
                    !result.report.preview_blocked_reason && (
                      <div className={scannerStyles.screenshotResultBox}>
                        <h3 className={scannerStyles.websitePreviewTitle}>
                          Website Preview
                        </h3>
                        <div className={scannerStyles.websitePreviewContainer}>
                          <img
                            src={result.report.website_preview}
                            alt="QR code website preview"
                            style={{
                              width: "100%",
                              display: "block",
                              borderRadius: 8,
                            }}
                          />
                        </div>
                      </div>
                    )}

                  {/* Preview Blocked Reason */}
                  {result.report.preview_blocked_reason && (
                    <div
                      className={scannerStyles.warningPanel}
                      style={{
                        marginTop: "1rem",
                        backgroundColor: "#ffebee",
                        color: "#b71c1c",
                      }}
                    >
                      <h3 style={{ marginTop: 0 }}>
                        ⚠ Preview Blocked for Your Safety
                      </h3>
                      <p>{result.report.preview_blocked_reason}</p>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}