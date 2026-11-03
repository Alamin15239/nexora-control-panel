import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  // OpenNext needs the complete Next.js runtime in its server bundle.
  // Include all Next.js dist modules and the runtime helpers that Next.js
  // resolves from its pnpm virtual store.
  outputFileTracingIncludes: {
    "/*": [
      "node_modules/next/dist/**/*",
      "node_modules/@swc/helpers/**/*",
      "node_modules/styled-jsx/**/*",
    ],
  },
};

export default nextConfig;
