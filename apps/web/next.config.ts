import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  // pnpm's symlinked Next.js package can be incompletely traced by nft.
  // Include the runtime modules OpenNext needs while keeping standalone output
  // rooted at apps/web/.next/standalone (the layout OpenNext expects).
  outputFileTracingIncludes: {
    "/*": [
      "node_modules/next/dist/server/**/*",
      "node_modules/next/dist/shared/**/*",
      "node_modules/next/dist/compiled/**/*",
    ],
  },
};

export default nextConfig;
