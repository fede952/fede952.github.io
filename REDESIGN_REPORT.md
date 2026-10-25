# Redesign report — branch `redesign`

Running log of the redesign (mobile UX, design system, ad layout v2, new tools). Branched from `main` @ `c5e706a`
(the merged overhaul + the CI baseURL fix). Screenshots are referenced by path under `docs/screenshots/` (gitignored:
regenerate them with the commands below).

## Phase 0 — Regression harness

All tests run against the **local build** in `public/` through a small static server (`tests/lib/server.mjs`). Every
request that isn't to that server is aborted, so no test can reach production, AdSense or analytics. A missing URL gets
the nearest `404.html` up the tree (Cloudflare Pages behaviour), so `/it/missing/` shows the Italian 404 page.

```bash
npm install                      # Playwright 1.64.1 + jsqr/pngjs (devDependencies only; node_modules is gitignored)
npx playwright install chromium  # once
hugo --gc --minify
npm test                         # static checks + functional + tool pages + visual (no screenshots)
node tests/visual.mjs --out docs/screenshots/after
```

| Script | What it checks |
|---|---|
| `tests/visual.mjs` | 11 pages (home, /tools/, pass-fort, pixel-shrink, qr-generator, /learn/, the EXIF guide, the nmap cheatsheet, about, /tools/games/, 404) × EN + IT × 360×740, 390×844, 768×1024, 1440×900 = 88 runs. Full-page screenshots, plus: no horizontal overflow (`scrollWidth <= innerWidth`, also inside same-origin iframes); nothing painted over the H1 or the tool iframe (hit-tested while each scrolls through the viewport, the sticky header's area excluded); no positioned element (badge, floating button) over h1–h3 text anywhere on the page; no JS errors; every `<pre>` fits or scrolls horizontally and isn't clipped; every tap target ≥ 24 px or meets the WCAG 2.5.8 spacing rule (inline text links exempt). |
| `tests/functional.mjs` | One or more real actions per tool (compress, EXIF purge verified on the output bytes, QR decode of the downloaded PNG, chart, password, JWT, secrets, fingerprint, NetGuard with **mocked** ipwho.is, steganography round-trip, StringMaster counts, search palette, `?q=` deep link). Moved here from the overhaul's scratch scripts. |
| `tests/tool-pages.mjs` | Every tool page × 6 languages: one H1, JSON-LD types, FAQ DOM = schema, iframe `?lang`, iframe auto-resized, no JS errors. |
| `tests/static-checks.mjs` | Internal links in every HTML file, JSON-LD parse, sitemap URLs exist (`--expect tools/x,…` asserts new tool URLs in all 6 languages). |

Test fixture: `tests/fixtures/photo-gps.jpg` (480×360, 25 KB, real camera EXIF incl. GPS).

### Baseline (before any change)
Screenshots: `docs/screenshots/before/<lang>-<page>-<w>x<h>.png` (88 files) + `results.json`.

| Check | Result on `main` |
|---|---|
| Visual suite | **62 of 88 runs fail** |
| — card badge (`span.card-tag`) over card titles | 197 hits, home + /tools/ + /tools/games/, every viewport |
| — search FAB (`#search-fab`) over headings / the tool iframe | 159 + 8 hits, every page type, mobile and tablet |
| — scroll-to-top (`#top-link`) over headings | 18 hits |
| — `<pre>` clipped (overflow visible, wider than the column) | 133, nmap cheatsheet, EN + IT, all viewports |
| — horizontal overflow, JS errors, tap targets < 24 px | 0 |
| Functional suite | 13/13 pass |
| Tool pages | 144/144 pass |
| Static checks | 2,753 HTML files, 72,233 internal references, 0 broken; 1,075 JSON-LD blocks, 0 errors; 503 sitemap URLs |

Not caught by an automatic assertion, so checked on the screenshots: tables crushed into narrow columns on mobile
(EXIF guide), dates on tool cards, the 3-row mobile header.

## Phase 1 — Visual bugs

**Root cause found on the way:** since the overhaul's PaperMod bump, the theme styles Markdown through `.md-content`,
but our templates only emitted `.post-content` — so none of PaperMod's content styles (code blocks, tables, lists,
blockquotes) applied on tool, learn, about, stack, projects and game pages. That is what clipped the cheatsheet code
blocks. `md-content` is now on every content wrapper (6 templates). The unused `_default/tool.html` and
`_default/tool-split.html` (no content uses `layout: tool|tool-split`) were deleted.

1. **Card badges** (`partials/cyber-card.html`, now called with `dict "page" … "showType" …`): the absolute-positioned
   "TOOLS" pill is gone. A localized type label ("Tool", "Guide", "Cheatsheet", "Fix", …, from the new
   `partials/page-type.html`) sits inline above the title and only on mixed listings (home "Latest Guides"); single-section
   grids (/tools/, /tools/games/, home "Featured Tools") show none. The search palette labels results with the same
   localized types instead of the raw section name ("Learn", "Tools").
2. **Floating buttons:** the search FAB is removed; search is an icon button in the header (Ctrl/⌘+K and `?q=` still
   work; every `[data-search-trigger]` opens the palette). Scroll-to-top is bottom-right inside the safe area
   (`env(safe-area-inset-*)`), appears after 1.5 viewports, and hides itself whenever a heading, a control, a code block,
   an ad slot or the tool iframe is under it (hit-tested on scroll, rAF-throttled), so it never covers the tool.
3. **No dates on tool and game cards.** Learn cards keep theirs; learn articles keep "Updated <date>".
4. **Header** (`partials/header.html`, `site-header.css`, `assets/js/site.js`): logo + "Federico Sella" on the left;
   nav, search icon, a compact language menu ("EN ▾" `<details>`, full names inside, each linking to the page's own
   translation or that language's home) and, below 768 px, a hamburger. One row, sticky, 56 px on mobile (asserted in
   the functional suite), 64 px on desktop, shadow + border once scrolled. Escape and outside clicks close the menus.
   Without JS the nav stays visible as a row. Header links are now root-relative. PaperMod's footer scripts (menu
   scroll memory, theme toggle, anchor smooth-scroll, code copy) are replaced by one fingerprinted, deferred
   `assets/js/site.js` (smooth scrolling is CSS, off under `prefers-reduced-motion`).
   The global `html, body { overflow-x: hidden !important }` hack is removed: it broke `position: sticky` and hid real
   overflow. A new sweep (`tests/overflow-sweep.mjs`, every real page of the build at 360 px) found exactly one
   overflowing component (chmod calculator filename row, ES/FR/IT/PT) — fixed. Result: **1,456 pages, 0 overflow**.
5. **Code blocks** (`_markup/render-codeblock.html`): server-rendered header bar with the language and a localized
   Copy button ("Copy"/"Copied", "Copia"/"Copiato", …; no layout shift), the `<pre>` scrolls horizontally and a fade
   appears on whichever edge has more code. Copy puts exactly the code on the clipboard (functional test).
6. **Tables** (`_markup/render-table.html`): every Markdown table is wrapped in a keyboard-focusable, labelled,
   horizontally scrollable region with the same edge fade; cells have a minimum width so columns stop being crushed
   (the EXIF fields table now scrolls sideways at 390 px instead of wrapping one word per line).
7. **Jargon H2s:** 283 headings renamed across 28 learn pages × 6 languages, e.g. "System Init" → "Why one photo can
   reveal where you live" / "What this Nmap cheatsheet covers", "What Is EXIF" → "What EXIF metadata reveals",
   "Protection Protocol" → "How to remove EXIF data before you share a photo", "Mission Templates" → "Ready-to-use
   Nmap scan recipes", "End of Transmission" → "… cheatsheet: key takeaways". Four pages (nmap, git-for-hackers, EXIF
   guide, steganography guide) had **English `$ Snake_Case` headings in all five translations** — now written in each
   language. English pages written in Title Case keep Title Case for the new headings. Anchors: no internal link
   points at any learn-page heading (checked content, layouts and data), so no legacy anchors were needed.
   Found, not fixed here (see TODO): `git-disaster-recovery` and `networking-ports-protocols` have **all accents
   stripped** in ES/DE/FR/PT ("Anderungen Ruckgangig", "Codigos") — fixed in their headings only; the HTB Cap writeup
   body is still English in ES/DE/FR/PT.
8. `<meta name="mobile-web-app-capable" content="yes">` added next to the Apple one.

Also: breadcrumbs had 22 px tap targets and the long current-page item overflowed at 360 px (fixed: 28 px targets,
item truncates with an ellipsis); the visual harness's overflow check compared against `innerWidth`, which mobile
emulation widens to fit overflowing content — it now compares against the emulated screen width.

New functional tests: `header-mobile` (≤ 56 px, hamburger open/Escape, language switch lands on `/de/learn/`),
`header-search`, `code-copy` (clipboard content), `back-to-top`.

| Check | Result |
|---|---|
| Visual suite | **88/88 pass** (baseline: 62 failing) |
| Overflow sweep, 360 px | 1,456 pages, 0 overflow, 0 JS errors |
| Functional | 17/17 · Tool pages 144/144 · Static: 0 broken links (73,694 refs), 0 JSON-LD errors |

## Phase 2 — Design system and layout

**Tokens** (`assets/css/extended/tokens.css`): background layers (`--bg` → `--bg-raised` → `--surface` → `--surface-2/3`),
borders (incl. `--border-input`, ≥ 3:1 for form-control boundaries), three text levels, cyan `--accent` + violet
`--accent-2`, success/warn/danger (+ `-soft` tints), a 5-step `--viz-*` scale for meters, 4 px spacing scale, radii,
3 shadows, fluid `clamp()` type scale, focus ring, motion and layout widths. PaperMod's own variables are mapped onto
the tokens, so theme CSS follows. Contrast checked (WCAG AA) and recorded in the file header: body text 16.3:1, secondary
9.4:1, tertiary 5.7:1 on the page (4.8:1 on inputs; never used on `--surface-3`), accent 10.9:1, accent-ink on accent
10.5:1. Every custom stylesheet now uses tokens only (no literal colour outside `tokens.css`; brand colours such as the
GitHub Sponsors pink are tokens too). `prefers-reduced-motion` turns off all animations and transitions site-wide (also
inside the apps, which load the same tokens).

**CSS reorganised** — `custom.css` (1,500 lines), `cyber-cards.css`, `list-grid.css`, `related-tools.css`,
`learn-page.css`, `home-saas.css` deleted; replaced by `layout.css`, `cards.css`, `listing.css`, `home.css`,
`prose.css`, `search.css`, `components.css`, `games.css`, `tool-ui.css` (+ the rewritten `tool-page.css`,
`footer.css`, `share-buttons.css`, `ad-slot.css`, `site-header.css`, `content-blocks.css`). Dead code removed with it:
the never-rendered `comments.html` sponsor box ("I'm a Junior Developer raising funds…"), `cyber-card.html`,
`uni-card.html`, `related-guides.html`, the split-view tool styles, `/tools/games/page/1/` pagination stubs.

**Embedded tools unified** (`/css/tool-base.css`): generated at build time by `partials/tool-base.html` from
`tokens.css` + `tool-ui.css` + `assets/css/tool-app.css`, so the 18 apps share the site's exact tokens and cannot
drift (the plan named `static/css/tool-base.css`; generating it is the same URL with a single source of truth). Every
app links it first; then, per app:
- its own palette variables were mapped onto tokens (same-name variables like `--text`, `--border`, `--accent` were
  removed so the shared token wins); 
- body font sans, mono only for data (passwords, hashes, codes); neon glows, wide uppercase letter-spacing, gradient
  text and cyan→magenta gradients removed;
- primary actions are one filled accent button (PassFort "Generate", NetGuard "Run Privacy Scan", PixelShrink
  "Compress", EXIF "Purge", GlitchForge "Download", ZenFocus Start/Reset, …), secondary actions outline;
- inputs, selects, toggles, sliders, checkboxes and focus rings come from the base; Chart.js (RateMate) reads its colours
  from the tokens; drop-zone emoji replaced by the site's stroke icons;
- personality = `--tool-accent` on the logo mark only (PassFort/NetGuard/GlitchForge/RateMate green, ZenFocus amber,
  ChronoSync/NeonPalette/PixelShrink/GhostPrint violet, the rest cyan); "$ " title prefixes removed;
- ZenFocus (purple gradient + glass panels + orange) and RateMate (a light theme) re-skinned fully; EasyCron's own
  light/dark toggle removed (light-mode remnant; its `easycron-theme` key dropped from the cookie pages, as was
  `menu-scroll-position`, which nothing sets since Phase 1).
Inline tools (hash, Base64, Caesar, chmod, password generator, Link Hazmat) use `tool-ui.css` and tokens directly.
Canvas drawing colours were left alone on purpose: GhostPrint's canvas probe (changing it would change the
fingerprint it measures), its shareable card image, and ReflexGrid's game graphics.
**Bug found and fixed:** the new 1 px border on the tool iframe started a resize feedback loop — ReflexGrid (a 100vh
app) reported 2 px less than its frame on every round and shrank to 150 px. `iframe-resizer.js` now adds the frame's
border/padding; `tests/tool-pages.mjs` fails if a frame keeps shrinking or never settles (verified to catch the bug).

**Tool / learn / game pages** (`.page-grid`, `partials/sidebar.html`): at ≥ 1100 px a 760 px main column + a 300 px
sidebar with *Related tools* (icon + name), *Related guides* (tool pages, from `data/related.yaml`) or *More guides*
(learn pages, same section), and the `sidebar` ad slot; below 1100 px the sidebar content follows the article (two
columns from 600 px) and the ad slot is not rendered. The old bottom "related" card grids are gone (the sidebar
replaces them). An eyebrow above the H1 shows the icon and category (tools, linking to `/tools/#<category>`) or the
type and reading time (learn).

**Icons** (`data/tool_icons.yaml`, `partials/icon.html`, `partials/page-meta.html`): 24 original stroke icons, one per
tool, plus category, games and learn-type icons, all 24×24 / 1.75 px round strokes; used on cards, in the sidebar, in
eyebrows, category headings and filter chips. No emoji as UI icons in the site chrome (footer lock emoji, card CTAs
"📞 READ FIX" etc. are gone).

**Home**: hero (value proposition + search), every tool grouped by category (Security & Privacy · Images & Media ·
Developer · Productivity) as compact icon cards (≈ 125 px tall on desktop; title-only on phones so 24 tools stay
scannable), *Popular guides* (`popular_guides` in hugo.toml — hand-picked, see TODO), and a *Who builds this* strip
(photo, one line, link to About). **/tools/**: the same grouping + filter chips (All / Security / Images / Dev /
Productivity) + a text filter (accent-insensitive, matches title, description and keywords; `/tools/#security` deep
links a chip; hidden without JS), then the games. **/learn/**: one mixed list, newest first, with type chips (Guides /
Cheatsheets / Fixes / Interview prep / Roadmaps / Writeups) and the text filter; every card shows type, title, 2-line
description and reading time. Sub-sections and tag pages use the same cards (type label only on mixed listings).

**Footer**: 4 columns on desktop, 2 on tablets/phones; headings are now `h2` (they were `h3` with no `h2` above).
Cookie Settings link unchanged. **Search palette**: fully localized (it was English-only), token styling.
**Light-mode remnants**: `<html>` is always `data-theme="dark"`; the two conflicting `theme-color` metas (`#2e2e33`
from PaperMod, `#1d1e20` ours) are one, `#0b0e12` = `--bg`, also in `manifest.json`; EasyCron's toggle removed.

Screens reviewed at 390 / 1440 px: home, /tools/, /learn/, a tool page (EN/IT), a guide, a game, all 18 apps,
4 inline tools. New functional tests: hash (MD5/SHA-256 test vectors), Base64 (UTF-8, unpadded decode), Caesar.

| Check | Result |
|---|---|
| Visual suite | 88/88 pass |
| Overflow sweep, 360 px | 1,456 pages, 0 overflow, 0 JS errors |
| Functional | 20/20 · Tool pages 144/144 (incl. the new frame-stability check) |
| Static | 2,747 HTML files, 0 broken links, 0 JSON-LD errors, 503 sitemap URLs |
