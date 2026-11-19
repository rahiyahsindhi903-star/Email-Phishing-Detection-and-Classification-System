import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import styles from "../styles/Navbar.module.css";

const NAV_ITEMS = [
  { name: "Home", href: "/", icon: "🏠" },
  { name: "URL Scanner", href: "/url-scanner", icon: "🔗" },
  { name: "QR Scanner", href: "/qr-scanner", icon: "📱" },
  { name: "Email Scanner", href: "/email-scanner", icon: "✉️" },
];

export default function Navbar() {
  const router = useRouter();
  const [isNavigating, setIsNavigating] = useState(false);

  useEffect(() => {
    const handleStart = () => setIsNavigating(true);
    const handleComplete = () => setIsNavigating(false);

    router.events.on("routeChangeStart", handleStart);
    router.events.on("routeChangeComplete", handleComplete);
    router.events.on("routeChangeError", handleComplete);

    return () => {
      router.events.off("routeChangeStart", handleStart);
      router.events.off("routeChangeComplete", handleComplete);
      router.events.off("routeChangeError", handleComplete);
    };
  }, [router]);

  return (
    <header className={styles.header}>
      {/* Top feedback bar when navigating */}
      {isNavigating && <div className={styles.loadingBar} />}

      <div className={styles.headerContent}>
        <Link href="/" className={styles.logo} title="Back to Home">
          <span className={styles.logoIcon}>🛡️</span>
          <span className={styles.logoText}>Phishing Detector</span>
        </Link>
        <nav className={styles.nav} aria-label="Main Navigation">
          {NAV_ITEMS.map((item) => {
            const isActive = router.pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                prefetch={true}
                className={`${styles.navButton} ${
                  isActive ? styles.navButtonActive : ""
                }`}
                aria-current={isActive ? "page" : undefined}
              >
                <span className={styles.buttonIcon}>{item.icon}</span>
                <span className={styles.buttonText}>{item.name}</span>
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
