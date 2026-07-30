import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ mode }) => {
  const isRailway = !!process.env.RAILWAY_ENVIRONMENT;
  const isCloudflarePage = !!process.env.CF_PAGES;

  if (
    mode === "production" &&
    (isRailway || isCloudflarePage) &&
    !process.env.VITE_API_URL?.trim()
  ) {
    throw new Error(
      "VITE_API_URL is required for production builds (Railway / Cloudflare Pages). " +
        "Set it in Dashboard → Settings → Environment Variables."
    );
  }

  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target: "http://localhost:8000",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, ""),
        },
      },
    },
    build: {
      // A05: nói rõ ràng thay vì dựa vào default của Vite — source map trên
      // production làm lộ toàn bộ source, kể cả logic crypto phía client.
      sourcemap: false,
      rollupOptions: {
        output: {
          manualChunks: (id) => {
            if (id.includes("node_modules/react") || id.includes("node_modules/react-dom") || id.includes("node_modules/react-router-dom")) {
              return "vendor";
            }
            if (id.includes("node_modules/@noble")) {
              return "crypto";
            }
          },
        },
      },
      chunkSizeWarningLimit: 600,
    },
  };
});
