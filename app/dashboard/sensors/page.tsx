import type { Metadata } from "next";
import SensorMonitor from "./SensorMonitor";
import styles from "./page.module.css";

export const metadata: Metadata = {
  title: "Sensor Detector — Liberty Shield",
  robots: { index: false, follow: false },
};

export default function SensorsPage() {
  return (
    <main className={styles.page}>
      <header className={styles.header}>
        <div className={styles.breadcrumb}>
          <a href="/dashboard" className={styles.back}>← Dashboard</a>
          <span className={styles.sep}>/</span>
          <span>Sensor Detector</span>
        </div>
        <span className={styles.badge}>Cíl 3</span>
      </header>
      <SensorMonitor />
    </main>
  );
}
