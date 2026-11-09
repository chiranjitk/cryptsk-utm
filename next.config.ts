import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  /* config options here */
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  // ADR-008: the realtime mini-service (socket.io) listens on :3003. When the
  // console is browsed directly on :3000 there is no gateway to translate the
  // XTransformPort query, so proxy the socket.io path here — same-origin
  // realtime works on BOTH entry points (:3000 direct and :81 gateway).
  async rewrites() {
    return [
      {
        source: "/socket.io/:path*",
        destination: "http://127.0.0.1:3003/socket.io/:path*",
      },
    ];
  },
};

export default nextConfig;
