import { defineConfig } from "blume";
import { manifestLinks } from "./integrations/manifest-links.ts";

export default defineConfig({
  title: "Webhooks SDK",
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
  redirects: [{ from: "/docs/guides/frameworks", to: "/docs/adapters" }],
  logo: "/logo.svg",
  integrations: [manifestLinks()],
  lastModified: true,
  github: {
    owner: 'nicogenz',
    repo: 'webhooks-sdk'
  }
});
