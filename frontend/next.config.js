/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Keep all pages compiled in memory so route switching is instant
  onDemandEntries: {
    maxInactiveAge: 60 * 60 * 1000, // 1 hour (prevents dumping compiled pages from cache)
    pagesBufferLength: 10,           // Keep all 4+ pages buffered in memory
  },
  webpack: (config, { dev, isServer }) => {
    if (dev && !isServer) {
      config.watchOptions = {
        aggregateTimeout: 200,
      };
    }
    return config;
  },
};

module.exports = nextConfig;
