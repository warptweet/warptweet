import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://warptweet.com",
  output: "static",
  compressHTML: true,
  server: {
    host: "127.0.0.1",
    port: 4321
  },
  vite: {
    build: {
      sourcemap: false
    },
    server: {
      strictPort: true
    }
  }
});
