import styles from "./page.module.css";

export default function DashboardPage() {
  return (
    <main className={styles.main}>
      <header className={styles.header}>
        <div className={styles.logo}>
          <span className={styles.logoIcon}>⬡</span>
          <span className={styles.logoText}>LIBERTY SHIELD</span>
        </div>
        <span className={styles.badge}>FPQSS v1</span>
      </header>

      <section className={styles.grid}>
        <StatusCard
          label="Shield Status"
          value="ACTIVE"
          status="ok"
          detail="All layers nominal"
        />
        <StatusCard
          label="PQC Layer"
          value="ML-KEM + ML-DSA"
          status="ok"
          detail="Post-quantum keys loaded"
        />
        <StatusCard
          label="Mesh VPN"
          value="ONLINE"
          status="ok"
          detail="Zero-trust mesh active"
        />
        <StatusCard
          label="Threat Level"
          value="LOW"
          status="ok"
          detail="No anomalies detected"
        />
      </section>

      <section className={styles.labyrinthSection}>
        <h2 className={styles.sectionTitle}>Mirror Labyrinth</h2>
        <div className={styles.labyrinthCanvas} aria-label="Mirror Labyrinth visualization">
          <MirrorLabyrinth />
        </div>
      </section>

      <section className={styles.modulesSection}>
        <h2 className={styles.sectionTitle}>Active Modules</h2>
        <div className={styles.moduleList}>
          <ModuleRow name="FVC" desc="Forward-Verified Chain" status="ok" />
          <ModuleRow name="FSR" desc="Failsafe Routing" status="ok" />
          <ModuleRow name="HSM" desc="Hardware Security Module" status="ok" />
          <ModuleRow name="mTLS" desc="Mutual TLS Termination" status="ok" />
          <ModuleRow name="Secret Sharding" desc="Shamir Secret Split" status="ok" />
          <ModuleRow name="Mic/Cam Detector" desc="Sensor access monitor" status="ok" href="/dashboard/sensors" />
        </div>
      </section>
    </main>
  );
}

function StatusCard({
  label,
  value,
  status,
  detail,
}: {
  label: string;
  value: string;
  status: "ok" | "warn" | "err";
  detail: string;
}) {
  return (
    <div className={`${styles.card} ${styles[`card_${status}`]}`}>
      <div className={styles.cardLabel}>{label}</div>
      <div className={styles.cardValue}>{value}</div>
      <div className={styles.cardDetail}>{detail}</div>
    </div>
  );
}

function ModuleRow({
  name,
  desc,
  status,
  href,
}: {
  name: string;
  desc: string;
  status: "ok" | "warn" | "pending";
  href?: string;
}) {
  const dot: Record<string, string> = {
    ok: "var(--green)",
    warn: "var(--yellow)",
    pending: "var(--text-muted)",
  };
  const inner = (
    <>
      <span
        className={styles.moduleDot}
        style={{ background: dot[status] }}
        aria-hidden="true"
      />
      <span className={styles.moduleName}>{name}</span>
      <span className={styles.moduleDesc}>{desc}</span>
      <span className={styles.moduleStatus}>{status.toUpperCase()}</span>
    </>
  );
  return href ? (
    <a href={href} className={`${styles.moduleRow} ${styles.moduleRowLink}`}>
      {inner}
    </a>
  ) : (
    <div className={styles.moduleRow}>{inner}</div>
  );
}

function MirrorLabyrinth() {
  const nodes = [
    { id: "A", x: 50, y: 50 },
    { id: "B", x: 150, y: 30 },
    { id: "C", x: 250, y: 70 },
    { id: "D", x: 350, y: 40 },
    { id: "E", x: 100, y: 130 },
    { id: "F", x: 200, y: 110 },
    { id: "G", x: 300, y: 130 },
    { id: "H", x: 400, y: 100 },
    { id: "I", x: 150, y: 200 },
    { id: "J", x: 300, y: 200 },
  ];

  const edges = [
    ["A", "B"], ["B", "C"], ["C", "D"],
    ["A", "E"], ["B", "F"], ["C", "G"], ["D", "H"],
    ["E", "F"], ["F", "G"], ["G", "H"],
    ["E", "I"], ["G", "J"], ["I", "J"],
  ];

  const nodeMap = Object.fromEntries(nodes.map((n) => [n.id, n]));

  return (
    <svg
      viewBox="0 0 460 240"
      xmlns="http://www.w3.org/2000/svg"
      className={styles.labyrinthSvg}
      role="img"
      aria-label="Mirror Labyrinth network graph"
    >
      <defs>
        <filter id="glow">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {edges.map(([a, b]) => {
        const na = nodeMap[a];
        const nb = nodeMap[b];
        return (
          <line
            key={`${a}-${b}`}
            x1={na.x} y1={na.y}
            x2={nb.x} y2={nb.y}
            stroke="#2563eb"
            strokeWidth="1"
            strokeOpacity="0.4"
          />
        );
      })}

      {nodes.map((n) => (
        <g key={n.id} filter="url(#glow)">
          <circle cx={n.x} cy={n.y} r="6" fill="#2563eb" fillOpacity="0.15" stroke="#2563eb" strokeWidth="1.5" />
          <circle cx={n.x} cy={n.y} r="2.5" fill="#60a5fa" />
        </g>
      ))}
    </svg>
  );
}
