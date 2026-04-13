'use client'

import { useSecurityStream, SecurityEvent } from '../hooks/useSecurityStream'
import styles from './page.module.css'
import liveStyles from './live.module.css'

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatTs(ms: number): string {
  return new Date(ms).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

function riskLabel(score: number): string {
  if (score >= 70) return 'HIGH'
  if (score >= 40) return 'MED'
  return 'LOW'
}

function riskVar(score: number): string {
  if (score >= 70) return 'var(--red)'
  if (score >= 40) return 'var(--yellow)'
  return 'var(--green)'
}

// ── Skeleton ──────────────────────────────────────────────────────────────────

function Skeleton({ w = '100%', h = '20px' }: { w?: string; h?: string }) {
  return (
    <div
      className={liveStyles.skeleton}
      style={{ width: w, height: h }}
      aria-hidden="true"
    />
  )
}

// ── Event Row ─────────────────────────────────────────────────────────────────

function EventRow({ ev }: { ev: SecurityEvent }) {
  const color = riskVar(ev.risk_score)
  const sensorIcon = ev.sensor === 'MICROPHONE' ? '🎙' : '📷'
  return (
    <div className={liveStyles.eventRow}>
      <span className={liveStyles.eventSensor}>{sensorIcon}</span>
      <span className={liveStyles.eventPkg} title={ev.package_name}>
        {ev.package_name.split('.').slice(-2).join('.')}
      </span>
      <span className={liveStyles.eventAction}
        style={{ color: ev.action === 'start' ? 'var(--green)' : 'var(--text-muted)' }}>
        {ev.action.toUpperCase()}
      </span>
      <span className={liveStyles.eventRisk} style={{ color }}>
        {riskLabel(ev.risk_score)} {ev.risk_score > 0 && `(${ev.risk_score})`}
      </span>
      {ev.misdirection_active && (
        <span className={liveStyles.msdBadge} title="Mirror Labyrinth active">MSD</span>
      )}
      <span className={liveStyles.eventTs}>{formatTs(ev.ingested_at)}</span>
    </div>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function LiveDashboard() {
  const { data, connected, error, reconnectCount } = useSecurityStream()

  const overview = data?.overview ?? null
  const events = data?.events ?? []
  const topThreats = data?.topThreats ?? []

  // Derive card values
  const shieldStatus = overview?.status ?? null
  const threatScore = overview?.top_threat_score ?? null
  const eventsLastHour = overview?.events_last_hour ?? null
  const lockdownActive = overview?.lockdown_active ?? false

  return (
    <>
      {/* Connection status bar */}
      <div className={liveStyles.statusBar}>
        <span className={liveStyles.statusDot} data-connected={connected} />
        <span className={liveStyles.statusLabel}>
          {connected ? 'LIVE' : error ? 'ERROR' : 'RECONNECTING…'}
        </span>
        {!connected && reconnectCount > 0 && (
          <span className={liveStyles.reconnectHint}>
            attempt {reconnectCount}
          </span>
        )}
        {error && (
          <span className={liveStyles.errorHint}>{error}</span>
        )}
        {lockdownActive && (
          <span className={liveStyles.lockdownBadge}>⚠ LOCKDOWN ACTIVE</span>
        )}
      </div>

      {/* Status cards */}
      <section className={styles.grid}>
        <div className={`${styles.card} ${styles.card_ok}`}>
          <div className={styles.cardLabel}>Shield Status</div>
          <div className={styles.cardValue}>
            {shieldStatus ?? <Skeleton h="28px" w="80px" />}
          </div>
          <div className={styles.cardDetail}>
            {overview ? `${overview.layers_active} layers active` : <Skeleton h="14px" w="120px" />}
          </div>
        </div>

        <div className={`${styles.card} ${threatScore != null && threatScore >= 70 ? styles.card_err : threatScore != null && threatScore >= 40 ? styles.card_warn : styles.card_ok}`}>
          <div className={styles.cardLabel}>Top Threat Score</div>
          <div className={styles.cardValue} style={{ color: threatScore != null ? riskVar(threatScore) : undefined }}>
            {threatScore != null ? `${threatScore}` : <Skeleton h="28px" w="50px" />}
          </div>
          <div className={styles.cardDetail}>
            {threatScore != null ? riskLabel(threatScore) + ' risk' : <Skeleton h="14px" w="80px" />}
          </div>
        </div>

        <div className={`${styles.card} ${styles.card_ok}`}>
          <div className={styles.cardLabel}>Events / Hour</div>
          <div className={styles.cardValue}>
            {eventsLastHour != null ? `${eventsLastHour}` : <Skeleton h="28px" w="40px" />}
          </div>
          <div className={styles.cardDetail}>
            {eventsLastHour != null ? 'sensor accesses detected' : <Skeleton h="14px" w="140px" />}
          </div>
        </div>

        <div className={`${styles.card} ${lockdownActive ? styles.card_err : styles.card_ok}`}>
          <div className={styles.cardLabel}>Lockdown</div>
          <div className={styles.cardValue}>{lockdownActive ? 'ACTIVE' : 'OFF'}</div>
          <div className={styles.cardDetail}>
            {lockdownActive ? 'All sensors blocked' : 'Normal operation'}
          </div>
        </div>
      </section>

      {/* Event feed */}
      <section className={styles.modulesSection}>
        <h2 className={styles.sectionTitle}>Live Event Feed</h2>
        {events.length === 0 ? (
          <div className={liveStyles.emptyFeed}>
            {connected
              ? 'Monitoring… no events yet.'
              : <Skeleton h="14px" w="240px" />}
          </div>
        ) : (
          <div className={liveStyles.eventList}>
            {events.slice(0, 20).map((ev, i) => (
              <EventRow key={`${ev.package_name}-${ev.ingested_at}-${i}`} ev={ev} />
            ))}
          </div>
        )}
      </section>

      {/* Top threats */}
      {topThreats.length > 0 && (
        <section className={styles.modulesSection}>
          <h2 className={styles.sectionTitle}>Top Threat Packages</h2>
          <div className={liveStyles.threatList}>
            {topThreats.slice(0, 10).map(({ key, score }, i) => {
              const pkg = key.replace('liberty:scores:', '')
              const color = riskVar(score)
              return (
                <div key={key} className={liveStyles.threatRow}>
                  <span className={liveStyles.threatRank}>#{i + 1}</span>
                  <span className={liveStyles.threatPkg}>{pkg}</span>
                  <span className={liveStyles.threatBar}>
                    <span
                      className={liveStyles.threatBarFill}
                      style={{ width: `${score}%`, background: color }}
                    />
                  </span>
                  <span className={liveStyles.threatScore} style={{ color }}>{score}</span>
                </div>
              )
            })}
          </div>
        </section>
      )}
    </>
  )
}
