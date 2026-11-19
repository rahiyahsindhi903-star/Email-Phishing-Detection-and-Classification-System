import React from "react";
import Link from "next/link";
import Navbar from "../components/Navbar";
import styles from "../styles/Home.module.css";

export default function Home() {
  return (
    <div className={styles.container}>
      {/* Dynamic Navbar with interactive buttons */}
      <Navbar />

      {/* Main Content */}
      <main className={styles.main}>
        <div className={styles.heroCard}>
          <h1 className={styles.title}>Phishing Detection Suite</h1>
          <p className={styles.description}>
            Analyze URLs, QR codes, and email content in seconds. Our hybrid engine 
            combines rule-based heuristics with machine learning to highlight risks, 
            confidence scores, and actionable explanations.
          </p>

          {/* Feature Cards */}
          <div className={styles.featuresGrid}>
            {/* URL Scanner Card */}
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>🔗</div>
              <h2 className={styles.featureTitle}>URL Scanner</h2>
              <p className={styles.featureDescription}>
                Paste a suspicious link and receive real-time analysis with detailed feature insights.
              </p>
              <Link href="/url-scanner" className={styles.launchLink}>
                Launch Scanner →
              </Link>
            </div>

            {/* QR Scanner Card */}
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>📱</div>
              <h2 className={styles.featureTitle}>QR Scanner</h2>
              <p className={styles.featureDescription}>
                Upload QR images or scan live to decode embedded URLs and check for quishing signals.
              </p>
              <Link href="/qr-scanner" className={styles.launchLink}>
                Launch Scanner →
              </Link>
            </div>

            {/* Email Scanner Card */}
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>✉️</div>
              <h2 className={styles.featureTitle}>Email Scanner</h2>
              <p className={styles.featureDescription}>
                Assess sender reputation, urgency cues, and embedded links from suspicious emails.
              </p>
              <Link href="/email-scanner" className={styles.launchLink}>
                Launch Scanner →
              </Link>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
