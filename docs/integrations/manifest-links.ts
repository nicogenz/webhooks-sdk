import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AstroIntegration } from "astro";

/**
 * Adds the two <head> tags Blume has no config surface for: the web app
 * manifest link and the theme-color metas.
 *
 * Blume auto-detects `public/favicon.ico` and `public/apple-touch-icon.png` by
 * filename, but it never references `site.webmanifest` and offers no `head`
 * option or layout slot to add one from — so without this the manifest, and the
 * android-chrome icons it points at, are dead weight in `public/` and the site
 * isn't installable.
 *
 * Build-time only, by necessity: Astro renders pages itself rather than through
 * Vite's HTML pipeline (it has no `transformIndexHtml` call anywhere), and the
 * only other seam is patching dev-server responses. So `blume dev` won't show
 * these tags — check them against `blume build` output or a preview deploy. The
 * tradeoff is deliberate: nothing about a manifest or a browser-chrome tint
 * affects local authoring, and the alternative is response-stream surgery.
 */

/** Manifest filename as it sits in `public/`, served from the site root. */
const MANIFEST_FILE = "site.webmanifest";

/**
 * `theme-color` tints mobile browser chrome, so these track Blume's page
 * background (`--blume-background`: `oklch(1 0 0)` / `oklch(0.085 0 0)`) rather
 * than the brand blue — the address bar should blend into the page, not sit
 * against it. `media` is the only conditional the tag supports, so this follows
 * the OS color scheme; a manual theme toggle can't be tracked declaratively.
 * The installed-app toolbar is tinted by the manifest's `theme_color` instead,
 * which is where the brand blue belongs.
 */
const THEME_COLOR_LIGHT = "#ffffff";
const THEME_COLOR_DARK = "#020202";

/** Join Astro's `base` (`"/"`, or `"/docs"` on a subpath deploy) to a filename. */
const withBase = (base: string, file: string): string =>
  `${base.replace(/\/$/u, "")}/${file}`;

const renderTags = (base: string): string =>
  [
    `<link rel="manifest" href="${withBase(base, MANIFEST_FILE)}">`,
    `<meta name="theme-color" content="${THEME_COLOR_LIGHT}" media="(prefers-color-scheme: light)">`,
    `<meta name="theme-color" content="${THEME_COLOR_DARK}" media="(prefers-color-scheme: dark)">`,
  ].join("");

/**
 * Append the tags to a document's <head>. Idempotent and total: a page that
 * already carries a manifest link is left alone (so a re-run, or a future Blume
 * that emits its own, can't double up), and so is anything with no `</head>` to
 * anchor on.
 */
const insertTags = (html: string, tags: string): string =>
  html.includes('rel="manifest"') || !html.includes("</head>")
    ? html
    : html.replace("</head>", `${tags}</head>`);

/** Every `.html` file under `dir`, at any depth. */
const htmlFilesIn = async (dir: string): Promise<string[]> => {
  const entries = await readdir(dir, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".html"))
    .map((entry) => join(entry.parentPath, entry.name));
};

export const manifestLinks = (): AstroIntegration => {
  // Resolved in `astro:config:done` so the value is whatever `base` survived
  // every integration's `updateConfig`, then read by the build hook.
  let tags = "";

  return {
    name: "blume-manifest-links",
    hooks: {
      "astro:config:done": ({ config }) => {
        tags = renderTags(config.base);
      },

      "astro:build:done": async ({ dir, logger }) => {
        const files = await htmlFilesIn(fileURLToPath(dir));
        let patched = 0;

        await Promise.all(
          files.map(async (file) => {
            const html = await readFile(file, "utf-8");
            const next = insertTags(html, tags);
            if (next !== html) {
              await writeFile(file, next);
              patched += 1;
            }
          })
        );

        logger.info(
          `manifest + theme-color tags added to ${patched}/${files.length} pages`
        );
      },
    },
  };
};
