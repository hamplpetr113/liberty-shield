/*
 * Sensor Event API — Threat Model
 * ---------------------------------
 * Boundary : Android APK → this endpoint (public internet)
 * Auth     : Bearer token — SENSOR_API_KEY env var (set in Vercel dashboard)
 *
 * Android APK integration:
 *   POST /api/sensors/event
 *   Authorization: Bearer <SENSOR_API_KEY>
 *   Content-Type: application/json
 *   Body: {
 *     device_id  : string  — opaque device identifier (e.g. Android SSAID)
 *     sensor     : "microphone" | "camera"
 *     app_package: string  — e.g. "com.example.suspicious"
 *     app_label  : string  — human-readable app name
 *     action     : "start" | "stop"
 *     ts         : number  — Unix ms timestamp
 *   }
 *
 * Threats:
 *   T1 Unauthorized injection  → Bearer auth; 401 on missing/wrong token
 *   T2 Enum poisoning          → sensor + action validated against allowlists
 *   T3 Oversized strings       → all string fields capped before storage
 *   T4 Event flood per device  → rate-limit 120 events/device_id/hour via KV
 *   T5 Log leakage             → app_package logged, not device_id
 */

import { Redis } from "@upstash/redis";
import { NextRequest, NextResponse } from "next/server";

const kv = new Redis({
  url: process.env.KV_REST_API_URL!,
  token: process.env.KV_REST_API_TOKEN!,
});

const VALID_SENSORS = new Set(["microphone", "camera"]);
const VALID_ACTIONS = new Set(["start", "stop"]);
const MAX_EVENTS = 500;
const RATE_LIMIT = 120;
const RATE_WINDOW_S = 3600;

export async function POST(req: NextRequest) {
  // Auth
  const auth = req.headers.get("authorization") ?? "";
  const apiKey = process.env.SENSOR_API_KEY;
  if (!apiKey || !auth.startsWith("Bearer ") || auth.slice(7) !== apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (!body || typeof body !== "object") {
    return NextResponse.json({ error: "Invalid payload" }, { status: 400 });
  }

  const b = body as Record<string, unknown>;

  const device_id =
    typeof b.device_id === "string" ? b.device_id.slice(0, 128) : null;
  const sensor =
    typeof b.sensor === "string" ? b.sensor : null;
  const app_package =
    typeof b.app_package === "string" ? b.app_package.slice(0, 256) : "unknown";
  const app_label =
    typeof b.app_label === "string" ? b.app_label.slice(0, 128) : "Unknown";
  const action =
    typeof b.action === "string" ? b.action : null;
  const ts =
    typeof b.ts === "number" ? b.ts : Date.now();

  if (!device_id) {
    return NextResponse.json({ error: "device_id required" }, { status: 400 });
  }
  if (!sensor || !VALID_SENSORS.has(sensor)) {
    return NextResponse.json(
      { error: "sensor must be 'microphone' or 'camera'" },
      { status: 400 }
    );
  }
  if (!action || !VALID_ACTIONS.has(action)) {
    return NextResponse.json(
      { error: "action must be 'start' or 'stop'" },
      { status: 400 }
    );
  }

  try {
    // Rate limit per device
    const rateKey = `rl:sensors:${device_id}`;
    const count = await kv.incr(rateKey);
    if (count === 1) await kv.expire(rateKey, RATE_WINDOW_S);
    if (count > RATE_LIMIT) {
      return NextResponse.json({ error: "Too many requests" }, { status: 429 });
    }

    const event = { device_id, sensor, app_package, app_label, action, ts };
    await kv.lpush("sensors:events", JSON.stringify(event));
    await kv.ltrim("sensors:events", 0, MAX_EVENTS - 1);

    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("[sensors/event] KV error:", (err as Error).message);
    return NextResponse.json(
      { error: "Service temporarily unavailable" },
      { status: 503 }
    );
  }
}
