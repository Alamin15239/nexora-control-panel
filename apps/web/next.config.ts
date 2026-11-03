import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  // pnpm stores workspace dependencies at the repository root. Include that
  // directory in Next.js output tracing so OpenNext receives complete packages.
  outputFileTracingRoot: path.resolve(process.cwd(), "../.."),
};

export default nextConfig;
