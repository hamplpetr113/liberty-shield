"use client";

import { useEffect, useRef, useState } from "react";
import styles from "./page.module.css";

type SensorEvent = {
  device_id: string;
  sensor: "microphone" | "camera";
  app_package: string;
  app_label: string;
  action: "start" | "stop";
  ts: number;
};

type BrowserPermState = "granted" | "denied" | "prompt" | "unsupported";

type BrowserSensors = {
  microphone: BrowserPermState;
  camera: BrowserPermState;
};

const POLL_INTERVAL_MS = 5000;

export default function SensorMonitor() {
  const [events, setEvents] = useState<SensorEvent[]>([]);
  const [lastPoll, setLastPoll] = useState<Date | null>(null);
  const [pollError, setPollError] = useState(false);
  const [browser, setBrowser] = useState<BrowserSensors>({
    microphone: "unsupported",
    camera: "unsupported",
  });
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Browser sensor check via Permissions API
  useEffect(() => {
    async function checkBrowserSensors() {
      if (!navigator?.permissions) return;
      const check = async (
        name: "microphone" | "camera"
      ): Promise<BrowserPermState> => {
        try {
          const result = await navigator.permissions.query({
            name: name as PermissionName,
          });
          return result.state as BrowserPermState;
        } catch {
          return "unsupported";
        }
      };
      const [mic, cam] = await Promise.all([
        check("microphone"),
        check("camera"),
      ]);
      setBrowser({ microphone: mic, camera: cam });
    }
    checkBrowserSensors();
  }, []);

  // Poll feed
  async function fetchEvents() {
    try {
      const res = await fetch("/api/sensors/feed", { cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: { events: SensorEvent[] } = await res.json();
      setEvents(data.events);
      setLastPoll(new Date());
      setPollError(false);
    } catch {
      setPollError(true);
    }
  }

  useEffect(() => {
    fetchEvents();
    intervalRef.current = setInterval(fetchEvents, POLL_INTERVAL_MS);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  return (
    <div className={styles.monitor}>
      {/* Browser sensor status */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Browser Sensor Access</h2>
        <div className={styles.sensorGrid}>
          <SensorBadge
            label="Microphone"
            state={browser.microphone}
            icon="🎙"
          />
          <SensorBadge label="Camera" state={browser.camera} icon="📷" />
        </div>
        <p className={styles.hint}>
          Reflects this browser&apos;s current permission state — not
          system-wide. Android events appear in the log below.
        </p>
      </section>

      {/* Live event log */}
      <section className={styles.section}>
        <div className={styles.logHeader}>
          <h2 className={styles.sectionTitle}>Live Event Log</h2>
          <span className={styles.pollStatus}>
            {pollError ? (
              <span className={styles.pollErr}>⚠ Feed unavailable</span>
            ) : lastPoll ? (
              <span className={styles.pollOk}>
                ● Updated {lastPoll.toLocaleTimeString()}
              </span>
            ) : (
              <span className={styles.pollWait}>Connecting…</span>
            )}
          </span>
        </div>

        {events.length === 0 ? (
          <div className={styles.emptyLog}>
            <span className={styles.emptyIcon}>◎</span>
            <p>No events yet.</p>
            <p className={styles.emptyHint}>
              Connect an Android device and send events to{" "}
              <code>POST /api/sensors/event</code>
            </p>
          </div>
        ) : (
          <div className={styles.logTable}>
            <div className={styles.logRow + " " + styles.logHead}>
              <span>Time</span>
              <span>Sensor</span>
              <span>Action</span>
              <span>App</span>
              <span>Device</span>
            </div>
            {events.map((ev, i) => (
              <div
                key={i}
                className={`${styles.logRow} ${
                  ev.action === "start" ? styles.rowStart : styles.rowStop
                }`}
              >
                <span className={styles.logTs}>
                  {new Date(ev.ts).toLocaleTimeString()}
                </span>
                <span className={styles.logSensor}>
                  {ev.sensor === "microphone" ? "🎙 Mic" : "📷 Cam"}
                </span>
                <span
                  className={
                    ev.action === "start" ? styles.tagStart : styles.tagStop
                  }
                >
                  {ev.action.toUpperCase()}
                </span>
                <span className={styles.logApp} title={ev.app_package}>
                  {ev.app_label}
                </span>
                <span className={styles.logDevice}>
                  {ev.device_id.slice(0, 8)}…
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function SensorBadge({
  label,
  state,
  icon,
}: {
  label: string;
  state: BrowserPermState;
  icon: string;
}) {
  const colorMap: Record<BrowserPermState, string> = {
    granted: "var(--yellow)",
    denied: "var(--green)",
    prompt: "var(--text-muted)",
    unsupported: "var(--text-muted)",
  };
  const textMap: Record<BrowserPermState, string> = {
    granted: "GRANTED — access allowed",
    denied: "DENIED — blocked by browser",
    prompt: "PROMPT — not yet decided",
    unsupported: "UNSUPPORTED",
  };
  return (
    <div className={styles.sensorBadge}>
      <span className={styles.sensorIcon}>{icon}</span>
      <div>
        <div className={styles.sensorLabel}>{label}</div>
        <div
          className={styles.sensorState}
          style={{ color: colorMap[state] }}
        >
          {textMap[state]}
        </div>
      </div>
    </div>
  );
}
