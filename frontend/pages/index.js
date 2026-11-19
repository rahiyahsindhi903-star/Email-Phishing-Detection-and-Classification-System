import Link from "next/link";
import styles from "../styles/Home.module.css";

export default function Home() {
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
                Launch →
              </Link>
            </div>

            {/* QR Scanner Card */}
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>📱</div>
              <h2 className={styles.featureTitle}>QR Scanner</h2>
              <p className={styles.featureDescription}>
                Upload QR images to decode embedded URLs and instantly check for phishing signals.
              </p>
              <Link href="/qr-scanner" className={styles.launchLink}>
                Launch →
              </Link>
            </div>

            {/* Email Scanner Card */}
            <div className={styles.featureCard}>
              <div className={styles.featureIcon}>✉️</div>
              <h2 className={styles.featureTitle}>Email Scanner</h2>
              <p className={styles.featureDescription}>
                Assess sender reputation, urgency cues, and embedded links from any email.
              </p>
              <Link href="/email-scanner" className={styles.launchLink}>
                Launch →
              </Link>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
