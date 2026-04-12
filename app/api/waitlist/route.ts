/*
 * Waitlist API — Threat Model
 * ---------------------------
 * Boundary : public internet → this endpoint
 * Threats  :
 *   T1 Spam / bot flood  → rate-limit 3 req/IP/hour via KV counter
 *   T2 Injection         → email validated by regex; only scalar stored
 *   T3 Data exposure     → email never written to logs; stored in KV (AES-256 at rest, TLS in transit)
 *   T4 Duplicate signup  → SADD is idempotent; returns {new:false} silently
 *   T5 Oversized input   → email truncated to 254 chars (RFC 5321 max)
 */

import { Redis } from "@upstash/redis";
import { NextRequest, NextResponse } from "next/server";

const kv = new Redis({
  url: process.env.KV_REST_API_URL!,
  token: process.env.KV_REST_API_TOKEN!,
});

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{1,63}$/;
const RATE_LIMIT = 3;
const RATE_WINDOW_S = 3600;

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (
    !body ||
    typeof body !== "object" ||
    !("email" in body) ||
    typeof (body as Record<string, unknown>).email !== "string"
  ) {
    return NextResponse.json({ error: "email is required" }, { status: 400 });
  }

  const email = (body as { email: string }).email
    .trim()
    .toLowerCase()
    .slice(0, 254);

  if (!EMAIL_RE.test(email)) {
    return NextResponse.json({ error: "Invalid email address" }, { status: 400 });
  }

  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "unknown";
  const rateKey = `rl:waitlist:${ip}`;

  try {
    const count = await kv.incr(rateKey);
    if (count === 1) await kv.expire(rateKey, RATE_WINDOW_S);
    if (count > RATE_LIMIT) {
      return NextResponse.json({ error: "Too many requests" }, { status: 429 });
    }

    const isNew = await kv.sadd("waitlist:emails", email);
    if (isNew) {
      await kv.hset(`waitlist:meta:${email}`, {
        ts: Date.now(),
        src: "landing",
      });
    }

    return NextResponse.json({ ok: true, new: Boolean(isNew) });
  } catch (err) {
    console.error("[waitlist] KV error:", (err as Error).message);
    return NextResponse.json(
      { error: "Service temporarily unavailable" },
      { status: 503 }
    );
  }
}
