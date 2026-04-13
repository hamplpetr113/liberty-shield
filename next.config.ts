import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  typescript: {
    // Type checking runs in CI (tsc --noEmit) and local dev.
    // Skipped here because Vercel's bundler picks up services/sensor-ingest/
    // despite tsconfig exclude — those files use ioredis types not present
    // in the Next.js dependency tree.
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
