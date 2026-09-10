/** @type {import('next').NextConfig} */
const nextConfig = {
  // Emit the minimal production server and traced runtime dependencies used
  // by the multi-stage Docker image.
  output: 'standalone',
  // OAuth callbacks contain short-lived authorization codes in the query
  // string. Do not let Next.js print incoming request URLs to the terminal.
  logging: {
    incomingRequests: false,
  },
  // Webpack's eval-based development source maps can produce callback chunks
  // that some embedded Chromium builds reject as invalid JavaScript. Keep the
  // normal Webpack dev server (its route handlers share the in-memory OIDC
  // transaction/session store), but emit plain chunks instead.
  webpack: (config, { dev }) => {
    if (dev) config.devtool = false;
    return config;
  },
  // Production builds use Next.js's default Turbopack pipeline; the custom
  // Webpack hook above is intentionally limited to the HTTPS dev server.
  turbopack: {},
  // No rewrite is required. With IAM enabled, browser API calls use the
  // authenticated /api/backend route, whose server-only upstream is provided
  // through SBOM_API_URL. Local unauthenticated development continues to use
  // NEXT_PUBLIC_API_URL directly.
};

export default nextConfig;
