/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    return [
      {
        source: '/api/:path*',
        destination: `${apiBase}/api/:path*`,
      },
      {
        source: '/dashboard/:path*',
        destination: `${apiBase}/dashboard/:path*`,
      },
      {
        source: '/health',
        destination: `${apiBase}/health`,
      },
      {
        source: '/analyze-:path*',
        destination: `${apiBase}/analyze-:path*`,
      },
    ];
  },
};

export default nextConfig;
