/*
 * Sensor Feed API
 * Returns the last N sensor events from Redis.
 * No auth — dashboard-facing, events contain no PII beyond app package names.
 */

import { Redis } from "@upstash/redis";
import { NextResponse } from "next/server";

const kv = new Redis({
  url: process.env.KV_REST_API_URL!,
  token: process.env.KV_REST_API_TOKEN!,
});

const PAGE_SIZE = 50;

export async function GET() {
  try {
    const raw = await kv.lrange("sensors:events", 0, PAGE_SIZE - 1);

    const events = raw
      .map((item) => {
        try {
          return typeof item === "string" ? JSON.parse(item) : item;
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    return NextResponse.json({ events }, { status: 200 });
  } catch (err) {
    console.error("[sensors/feed] KV error:", (err as Error).message);
    return NextResponse.json({ events: [] }, { status: 200 });
  }
}
