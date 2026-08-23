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
  // Inlined by Blume as SVG, so the mark stays crisp at any size and scales with
  // the header text. The wordmark beside it falls back to `title`. The favicon
  // and apple-touch icon in public/ are picked up by filename, no config needed.
  logo: "/logo.svg",
  // Blume emits no manifest link or theme-color metas of its own.
  integrations: [manifestLinks()],
});
