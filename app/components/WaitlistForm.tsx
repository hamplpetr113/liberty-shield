"use client";

import { useState } from "react";
import styles from "./WaitlistForm.module.css";

type State = "idle" | "loading" | "success" | "duplicate" | "error";

export default function WaitlistForm() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<State>("idle");
  const [errorMsg, setErrorMsg] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (state === "loading" || state === "success") return;

    setState("loading");
    setErrorMsg("");

    try {
      const res = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const data: { ok?: boolean; new?: boolean; error?: string } =
        await res.json();

      if (!res.ok) {
        setErrorMsg(data.error ?? "Something went wrong");
        setState("error");
        return;
      }

      setState(data.new ? "success" : "duplicate");
    } catch {
      setErrorMsg("Network error — please try again");
      setState("error");
    }
  }

  if (state === "success") {
    return (
      <div className={styles.confirmation}>
        <span className={styles.confirmIcon}>✓</span>
        <p className={styles.confirmTitle}>You&apos;re on the list</p>
        <p className={styles.confirmSub}>
          We&apos;ll reach out when Liberty Shield is ready for your family.
        </p>
      </div>
    );
  }

  if (state === "duplicate") {
    return (
      <div className={styles.confirmation}>
        <span className={styles.confirmIcon}>◈</span>
        <p className={styles.confirmTitle}>Already registered</p>
        <p className={styles.confirmSub}>
          That address is already on the waitlist.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className={styles.form} noValidate>
      <div className={styles.inputRow}>
        <input
          type="email"
          name="email"
          autoComplete="email"
          placeholder="your@email.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          disabled={state === "loading"}
          className={styles.input}
          aria-label="Email address"
        />
        <button
          type="submit"
          disabled={state === "loading" || !email}
          className={styles.button}
        >
          {state === "loading" ? "…" : "Join waitlist"}
        </button>
      </div>
      {state === "error" && (
        <p className={styles.errorMsg} role="alert">
          {errorMsg}
        </p>
      )}
      <p className={styles.privacy}>
        No spam. No trackers. Unsubscribe any time.
      </p>
    </form>
  );
}
