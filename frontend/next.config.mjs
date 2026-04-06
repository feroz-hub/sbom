/** @type {import('next').NextConfig} */
const nextConfig = {
  // No Next.js proxy rewrites — all API calls go directly to FastAPI via
  // NEXT_PUBLIC_API_URL (http://localhost:8000 by default).
  // Proxying caused ECONNRESET on long-running analysis calls (47-120s)
  // because Node's http.request socket timeout killed the connection.
};

export default nextConfig;
