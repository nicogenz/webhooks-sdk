import { defineConfig } from "blume";

export default defineConfig({
  title: "webhooks-sdk",
  description:
    "One way to verify, parse, and route webhooks from every provider. Zero dependencies, Web Crypto only — runs on Node 22+, Cloudflare Workers, Deno, and Bun.",
  theme: {
    accent: "blue",
  },
  navigation: {
    tabs: [{ label: "Docs", path: "/docs" }],
  },
  deployment: {
    site: "https://webhooks-sdk.com",
  },
});
