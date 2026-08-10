/** @type {import('next').NextConfig} */
const nextConfig = {
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
  // No Next.js proxy rewrites — all API calls go directly to FastAPI via
  // NEXT_PUBLIC_API_URL (http://localhost:8000 by default).
  // Proxying caused ECONNRESET on long-running analysis calls (47-120s)
  // because Node's http.request socket timeout killed the connection.
};

export default nextConfig;
