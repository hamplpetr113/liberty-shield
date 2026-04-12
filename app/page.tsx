import WaitlistForm from "./components/WaitlistForm";
import styles from "./page.module.css";

export default function LandingPage() {
  return (
    <main className={styles.main}>
      <nav className={styles.nav}>
        <div className={styles.navLogo}>
          <span className={styles.navIcon}>⬡</span>
          LIBERTY SHIELD
        </div>
        <a href="/dashboard" className={styles.navLink}>
          Dashboard →
        </a>
      </nav>

      <section className={styles.hero}>
        <div className={styles.heroEyebrow}>FPQSS — Post-Quantum Security</div>
        <h1 className={styles.heroTitle}>
          Privacy protection<br />built for families
        </h1>
        <p className={styles.heroSub}>
          Liberty Shield wraps your home network, devices, and communications
          in post-quantum cryptography — so your children stay safe from
          threats that don&apos;t yet exist.
        </p>
        <WaitlistForm />
      </section>

      <section className={styles.features}>
        <Feature
          icon="⬡"
          title="Post-Quantum Core"
          desc="ML-KEM key encapsulation and ML-DSA signatures keep your data safe against quantum and classical attacks."
        />
        <Feature
          icon="◈"
          title="Mirror Labyrinth"
          desc="A zero-trust mesh that mirrors and fragments your traffic — making surveillance and interception practically impossible."
        />
        <Feature
          icon="◉"
          title="Sensor Guard"
          desc="Real-time detection of unauthorised microphone and camera access on every device in your home."
        />
        <Feature
          icon="▣"
          title="Secret Sharding"
          desc="Your keys are never whole in one place. Shamir sharding means no single breach can compromise your identity."
        />
      </section>

      <footer className={styles.footer}>
        <span>© {new Date().getFullYear()} Liberty Shield</span>
        <span className={styles.footerDivider}>·</span>
        <span>FPQSS v1 compliant</span>
        <span className={styles.footerDivider}>·</span>
        <span>No trackers. No analytics. No compromise.</span>
      </footer>
    </main>
  );
}

function Feature({
  icon,
  title,
  desc,
}: {
  icon: string;
  title: string;
  desc: string;
}) {
  return (
    <div className={styles.featureCard}>
      <span className={styles.featureIcon}>{icon}</span>
      <h3 className={styles.featureTitle}>{title}</h3>
      <p className={styles.featureDesc}>{desc}</p>
    </div>
  );
}
