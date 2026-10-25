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

## Phase 3 — Ad layout v2

- **Tool pages:** intro → tool → `tool_after` → How to use → long-form text with `article_mid` before its 3rd `<h2>` → FAQ; `sidebar` unit at ≥ 1100 px. `tool_top` is no longer placed; its config key `slot_tool_top` stays in `hugo.toml` (documented there) so the position can be reused. `slot_sidebar = ""` added (falls back to `slot_default`).
- **Learn pages:** `article_mid` before the 2nd and 5th `<h2>` as before, plus the desktop sidebar unit.
- **One ad per screen:** `ads/inject-content.html` only places an in-content unit at least 450 words after the previous ad (the How-to words count). Otherwise the unit moves to the next `<h2>`, or is dropped. The sidebar unit (`site.js`) gets a "track" where no in-content ad is within one viewport and it never sits beside the tool; inside that track it is sticky. If there's no such track, it is never inserted or requested.
- **No ad within 150 px of a tool control:** `tool_after` has 144 px of space above it.
- **Above the fold:**
  - Nothing sits between the intro and the tool, and the mobile tool header is tighter.
  - ReflexGrid's start overlay is now aligned to the top.
  - GhostPrint's frame may only grow during its first 3 s (`tool_settle_ms`). It used to shrink and then grow back, which caused a layout shift.
- **New test, `tests/ads.mjs`:** one ad per screen, first control visible without scrolling, 150 px rule, CLS.
  - Tool pages, 6 languages at 390×844 and 1440×900: **420 runs, 0 problems; max CLS 0.002**; the sidebar unit was placed on 144 of 210 desktop runs.
  - Learn pages at all 3 viewports (390×844, 768×1024, 1440×900): last full run was EN+IT, with only button-distance failures, since fixed. Re-run in Phase 6.

## Phase 4 — Content fixes

1. **About page (6 languages)** rewritten from the confirmed facts only:
   - Network Security Analyst (L2) at a large enterprise, on SSE/SASE platforms: Zero Trust access, the secure web gateway, and client connectivity troubleshooting. No employer or client is named.
   - About a year as SOC Tier 1 before that.
   - Career changer: CNC machining/programming and technical drafting, then a technical diploma at evening school.
   - eJPT; cybersecurity bootcamp; Python, C#, Next.js.
   - Why the site exists, plus contact links.

   Removed: "Security Developer", "Red Team Aspirant", the contradictory "7+ years" and "over 10 years", "Zero-Error precision", "Arsenal", "digital warfare", and a home-town keyword.

   The other certifications (Cisco Ethical Hacker, ISC2 CC, Google Cybersecurity) and the years of CNC work are kept only in a `TODO(Federico): confirm` YAML comment in each file's front matter. They are not rendered.

   Photo kept, now styled by CSS (`.about-photo`) instead of inline styles. The translations use gender-neutral phrasing.
2. **Consistency:**
   - Person `jobTitle` is "Network Security Analyst", matching the About page; "Secure web gateway" added to `knowsAbout`.
   - Author-box bio rewritten in 6 languages to the same facts. It used to say "working in SOC and L2 network security".
   - `/links/` bio "Cyber Security & DevOps Engineer" now reads `jobTitle`.
   - The unused `profileMode.subtitle` ("Software Developer (.NET / C#) | AI Integration Specialist…") aligned.
3. **`robots.txt`:** only `User-agent: * / Allow: /` and the sitemap. The GPTBot, Google-Extended, CCBot, ClaudeBot and anthropic-ai blocks are removed, since AI-crawler policy is handled at Cloudflare.
4. **`static/.well-known/security.txt`** (RFC 9116): Contact, Expires 2027-10-25, Preferred-Languages en, it, Canonical.
5. **Games:**
   - Every game page now has a "How to play" section. Added in 6 languages for SysAdmin Tycoon (none before; written from the game's code: tabs, power/heat limits, DDOS and power-surge events, sell mode, 8-hour offline earnings) and in 5 languages for NeonBlocks.
   - Trademarked names removed from titles, descriptions, keywords and tags: Space Invaders, Tetris, Arkanoid, Breakout, Snake. "Cyber Snake: Data Eater" is now "Data Eater: Retro Grid Chase" in 6 languages; its URL is unchanged.
   - Generic genre words stay (brick breaker, Sudoku, 2048, Minesweeper/Campo Minato as the genre name).
   - Found, not fixed: SysAdmin Tycoon's built-in UI strings have lost their accents in ES/DE/FR/PT ("Kuhlung", "Energie", "fur").

Checks: build clean, 0 broken links, visual suite on About and games clean.

## Phase 5 — New tools

Seven new tools, each with a 6-language page (`reviewed: false`: how-to, FAQ, "How it works", use cases), an icon and category in `data/tool_icons.yaml`, related tools and guides in `data/related.yaml`, and new learn-page → tool links. All of them run in the browser; none uploads a file or text.

The new apps share:
- a small kit, `static/js/tool-kit.js` (UI language, `{placeholder}` strings, copy, download, delegated `[data-copy]`);
- the `tb-*` app-shell classes in `assets/css/tool-app.css`, built on the design tokens.

Their logic lives in DOM-free ES modules under `static/js/tools/`, unit-tested with `node --test "tests/unit/*.test.mjs"`: 8 files, 55 tests.

| Tool | Slug | What it does | Libraries (self-hosted) |
|---|---|---|---|
| Subnet calculator | `subnet-calculator` | IPv4 (incl. /31 per RFC 3021 and /32), IPv6 with RFC 5952 compression and address scopes, VLSM split | — |
| HEIC converter | `heic-converter` | HEIC/HEIF → JPEG/PNG, batch with ZIP. EXIF is kept or stripped, with orientation reset and a GPS warning | libheif-js 1.23.5 (LGPL-3.0, lazy WASM), JSZip 3.10.2 |
| PDF merge & split | `pdf-merge-split` | Merge with drag-and-drop thumbnails (also keyboard buttons), rotate and remove pages, split by ranges into a ZIP | pdf-lib 1.17.1, pdfjs-dist 6.4.299 (thumbnails; cMaps, standard fonts and WASM vendored), JSZip |
| Images to PDF | `images-to-pdf` | JPG/PNG/WebP → one PDF. Page size A4/Letter/fit, margins, EXIF orientation applied | pdf-lib |
| JSON formatter | `json-formatter` | Format/minify/validate with an exact line:column error and a caret; sort keys; tree view; JSON ⇄ YAML; JSON → CSV (RFC 4180). Above 2 MB the work moves to a Web Worker | js-yaml 4.1.0 (lazy) |
| Text diff | `text-diff` | Side-by-side and inline views; word or character highlights; ignore whitespace/case; folded context; copy or download a unified diff | jsdiff 9.0.0 (BSD-3) |
| Security headers & CSP analyzer | `security-headers` | Paste headers, a bare CSP or a CSP `<meta>` tag. Checks HSTS, CSP (directive fallback, unsafe-inline/eval, wildcards, scheme sources, JSONP/AngularJS bypass hosts, nonce length, strict-dynamic, syntax mistakes), XCTO, framing, Referrer-Policy, Permissions-Policy, COOP, CORS, every Set-Cookie, and version disclosure. Grade A+–F, plain-text report. **No network request** (asserted by its test) | — |

**Decision: two PDF pages rather than one.**
- "merge/split PDF" and "JPG to PDF" are separate search intents with different first actions.
- Both pages share `js/tools/pdf-kit.mjs` and link to each other.

**Upgrades to existing tools:**
- **PassFort — opt-in breach check.**
  - It runs only on a click of **Check against known breaches**, which sits under the auditor.
  - It uses the Have I Been Pwned range API with k-anonymity. Only the first 5 hex characters of the SHA-1 are sent, with `Add-Padding: true` and `no-referrer`. Padding rows (count 0) are ignored, and the match happens locally.
  - The result clears when the password changes.
  - Disclosed in the app's privacy badge and footer, in the PassFort page (intro, how-to, a new FAQ, a "How it works" subsection) and on the privacy page in 6 languages, as a second exception after NetGuard/ipwho.is.
- **QR generator — Wi-Fi and Contact modes.**
  - Wi-Fi uses the ZXing `WIFI:` format, with `\ ; , : "` escaped. vCard 3.0 uses RFC 2426 escaping and CRLF line endings.
  - An "Encoded text" preview shows the exact payload.
  - Verified by decoding the downloaded PNG with jsQR, including names and passwords full of special characters.
  - Also fixed: the QR canvas overflowed its panel at 390 px.
- **`tools/_index` (6 languages):** the description and intro no longer say "no data sent to servers". They now name the two tools that contact a service (NetGuard → ipwho.is, PassFort → Have I Been Pwned, on request).

**Tests added:**
- Functional:
  - `subnet-calculator`, `heic-converter`, `pdf-merge-split`, `images-to-pdf`, `json-formatter`, `text-diff`: the `.diff` it produces applies back.
  - `security-headers`: weak sample → F, strong → A+, CSP-only paste, Italian, no external request.
  - `pass-fort-hibp`: mocked range API. Checks there is no request before the click, the exact prefix URL and the padding header, then found / not found / offline.
  - `qr-wifi-vcard`.
- Unit tests for every module. `diff.test.mjs` also runs a real `git apply` on the generated patch.

**Vendored:** `static/vendor/README.md` now lists libheif-js, JSZip, pdf-lib, pdfjs-dist, js-yaml and jsdiff, with versions, licences and users.

Checks:
- `hugo --gc --minify`: 0 errors, 0 warnings.
- Static checks: 2,876 HTML files, 0 broken internal links, 1,201 JSON-LD blocks with 0 errors. The sitemap has 545 URLs, including every new tool in 6 languages.
- `tool-pages.mjs`: frame-settle check and mobile layout pass on every new page.
- Full `npm test` passed:
  - static checks clean;
  - unit 55/55;
  - every functional check passed;
  - tool pages: 186 runs, 0 problems;
  - visual: 88 page/viewport runs, 0 problems;
  - ads: 420 runs, 0 problems, max CLS 0.019.

## Phase 6 — Final verification

**Lighthouse 12.6.1, mobile** (default Moto G Power emulation, simulated slow 4G and 4× CPU), run on the local build only.

| Page | Perf | A11y | BP | SEO | LCP | TBT | CLS |
|---|---|---|---|---|---|---|---|
| Home `/en/` | 96 | 100 | 100 | 100 | 2.55 s | 0 ms | 0.000 |
| PassFort (existing tool) | 94 | 100 | 100 | 100 | 2.85 s | 44 ms | 0.000 |
| QR generator (existing tool) | 94 | 100 | 100 | 100 | 2.85 s | 27 ms | 0.000 |
| Subnet calculator | 94 | 100 | 100 | 100 | 2.85 s | 36 ms | 0.000 |
| PDF merge & split | 95 | 100 | 100 | 100 | 2.78 s | 0 ms | 0.000 |
| Guide (`osint-privacy-exif-data`) | 97 | 100 | 100 | 100 | 2.40 s | 0 ms | 0.000 |

- **Which pass this table is:** third-party requests were blocked (AdSense, Umami), so the numbers measure the site itself and are repeatable.
- **Second pass, with AdSense and Umami allowed:** Perf 94–96, everything else identical, CLS 0.000. Ad slot IDs are still empty, so this pass has no filled ad units. Re-measure once real units serve.

**Two fixes made by this phase:**
1. **CLS 0.057 on every page (now 0.000).**
   - Before the deferred `site.js` added `.js` to the header, the mobile header rendered its no-JS layout, with the nav wrapped onto a second row (97 px instead of 56 px).
   - When the script ran, the header collapsed and `<main>` shifted up 41 px. The Phase 3 CLS checks missed it because they run unthrottled.
   - Fix: an inline one-liner right after `</header>` adds the class before first paint. The no-JS fallback is unchanged.
2. **Label-in-name (WCAG 2.5.3).** The language switcher showed "EN" but was named "Language: English". The `aria-label` was replaced by visually hidden text, so the accessible name now starts with the visible code.

**Final suite, after both fixes:**
- `npm test` passes.
- Static: 2,876 HTML files, 0 broken internal links; 1,201 JSON-LD blocks, 0 errors.
- Sitemap: 545 URLs, every new tool present in all 6 languages.
- Unit 55/55. Functional: all pass, HIBP mocked.
- Tool pages: 186 runs, 0 problems. Visual: 88 runs, 0 problems. Ads: 420 runs, 0 problems, max CLS 0.019.

**Screenshots:** the after set is in `docs/screenshots/after/` (89 files, matching `docs/screenshots/before/`). The folder is git-ignored.

## Phase 7 — Personal data hardening and leftover TODOs

### 7.1 Personal location and mailbox removed

Every hit of a case-insensitive search for the home town, its province, the personal mailbox, `gmail.com`, `+39` and street-address patterns (`streetAddress`, `postalCode`, "Via …", postcodes), across tracked files and the built `public/` (JSON-LD included), and what was done:

| File | Was | Now |
|---|---|---|
| `content/privacy/index{,.it,.es,.de,.fr,.pt}.md` | "Federico Sella — ‹town› (‹province›), Italy" (localised) | "Federico Sella — Italy / Italia / Italien / Italie / Itália"; the `privacy@federicosella.com` address stays |
| `content/contact/index.*.md` (6) | personal mailbox | `contact@federicosella.com` |
| `hugo.toml` profileMode "Contact" button | `mailto:` personal mailbox | `mailto:contact@federicosella.com` |
| `layouts/links/list.html` (2 links) | `mailto:` personal mailbox | `mailto:contact@federicosella.com` |
| `static/.well-known/security.txt` | personal mailbox | `Contact: mailto:security@federicosella.com` |
| `content/apps/pasta-stack/privacy/index{,.it}.md` | personal mailbox | `privacy@federicosella.com` (only the email line changed) |
| `REDESIGN_REPORT.md` (Phase 4 note) | named the home-town keyword | "a home-town keyword" |
| `static/tools/json-to-csharp/index.html` | sample "John Doe, 123 Main St, New York" | unchanged: fictional sample data |

No `+39` number, street address or postcode anywhere. After the build, `public/` has no hit; the only `email` value in any JSON-LD-like block is the tool's `john@example.com` sample.

### 7.2 Metadata hygiene

1. **Test fixtures.** `tests/fixtures/photo-gps.jpg` and `photo-gps.heic` are rebuilt by the new `tests/fixtures/make-photos.py` (synthetic 480×360 image): GPS 0°30′0″S 25°0′0″W (open South Atlantic), Make `FixtureCam`, Model `Model T-1`. The old fixtures carried a point near the owner's home area and a real camera model. Updated assertions: `exif-cleaner` waits for "GPS|FixtureCam", `images-to-pdf` checks that `FixtureCam` does not leak into the PDF. The HEIC unit test only checks that a GPS block exists, so it was unaffected.
2. **Published images.** A byte-level scan of all 17 images under `static/`, `assets/` and `content/`. Five carried metadata, stripped losslessly at chunk level (pixels verified identical after decoding; colour profiles kept):
   - `favicon.png`, `images/icon-192.png`, `images/icon-512.png`: an XMP packet (orientation only);
   - `images/pixel-shrink-icon.webp`: EXIF with the generator's `Artist` UUID and an `ImageDescription` "Signature: …" blob;
   - `images/social-banner.png` (actually a JPEG): the same generator EXIF.

   The other 12 were clean. All icons generated in this phase come from headless Chromium screenshots, which carry no metadata.
3. **New default share card.** `static/images/og-card.png` is 1200×630, rendered by `scripts/og-card.mjs` from the design tokens: the new mark, "Federico Sella", "Free, privacy-first web tools", "federicosella.com", in the self-hosted JetBrains Mono. `params.images` points to it.
   - `og:image:width` (1200), `og:image:height` (630), `og:image:type` and `og:image:alt` are read from the file. They are emitted right after `og:image`, through a copy of PaperMod's `templates/opengraph.html` with only that block added, and only where the default card is used. Pages with their own cover (the writeup, projects) keep theirs.
   - The old portrait `social-banner.png` stays at its URL, metadata stripped, so cached shares still resolve.
4. **Guard: `tests/privacy-guard.mjs`.** No dependencies, needs only Node and git. It fails when:
   - a tracked or new, non-ignored file outside `static/vendor/` matches the home town or the personal mailbox. The patterns are built from fragments, so the guard never matches itself;
   - an image under `static/`, `assets/` or `content/` has EXIF GPS. It parses the real container (JPEG APP1, PNG `eXIf`, WebP `EXIF`, HEIF/TIFF) and looks for the GPS IFD pointer (tag 0x8825), and also catches GPS fields in XMP.

   It runs as the first step of `npm test` (`npm run test:privacy` alone) and as a **"Privacy guard" step in `.github/workflows/production.yaml` before "Build Site"**, with no secrets and no `npm install`. Verified both ways: 0 problems on the tree, and 4 of 4 planted probes caught (JPEG GPS, PNG `eXIf` GPS, HEIC GPS, a file containing the old mailbox).

### 7.3 Leftover TODOs

1. **Stripped accents restored**, checked with a dictionary pass (`pyspellchecker`, es/fr/pt/de).
   - **Scope:** a scan of every ES/DE/FR/PT page and i18n file found the damage only in `networking-ports-protocols` and `git-disaster-recovery` (both born without accents in `8e8ecf2`, so there was no original to restore), `code-breaker-typing`, `sysadmin-tycoon`, and SysAdmin Tycoon's in-game strings. The few hits elsewhere were valid verb forms or English terms (*indica*, *calculo*, *publica*, `penetration-testing`) and were left alone.
   - **Method:**
     - Unambiguous words were auto-fixed only in those files.
     - Homographs (*esta/está*, *a/à*, *e/é*, *chiffre/chiffré*, *mochte/möchte*…) were fixed by reading every file and applying 125 exact edits.
     - Translated comments inside code blocks (PT, DE) were fixed too: 48 lines. Commands are untouched.
   - **Three wrong automatic changes caught in review and reverted:**
     - "s'écoulé" back to "s'écoule";
     - "envío una respuesta" to "envió";
     - the Spanish tag `versión-control` back to `version-control`, since tags are identifiers.
   - **Choices:** Brazilian Portuguese spellings (*mnemônico*, *cronômetro*); Spanish *¡…!*/*¿…?* added where the sentence is an exclamation or question.
   - **Re-run of the dictionary pass on the 16 files:** 0 candidates left.
   - **Game strings:**
     - The ES/FR/DE/PT UI strings now carry their accents, e.g. *Kühlung*, *Énergie*, *Amélior.*, *Núcleo Quântico*, *¡APAGÓN!*.
     - The font is the site's monospace stack, which covers accented Latin, and the page declares UTF-8.
     - The game pages quote the new tab labels.
2. **HTB Cap writeup — EN + IT only.**
   - **What was removed:** the ES/DE/FR/PT files (English bodies) and the then-empty ES/DE/FR/PT writeups sections.
   - **Redirects:** both come from `data/removed_translations.yaml`, read by `layouts/home.redirects`:
     - 301s to the English page in Cloudflare's `_redirects`;
     - a published `noindex` meta-refresh page with a canonical tag at each old URL (8 for the writeup, 8 for the section), for GitHub Pages, which ignores `_redirects`.
   - **hreflang** on the writeup lists only `en`, `it` and `x-default`.
   - **Language switcher:** a missing translation now leads to the nearest translated ancestor (here `/es/learn/`, …) instead of the language's home page.
   - **Learn hub:** it only shows type chips that have articles in that language, so there's no "Writeups" chip in ES/DE/FR/PT.
   - **Sitemap:** 545 → 537 URLs.
3. **PassFort vs Password Generator (6 languages, URLs kept).**
   - **PassFort's page** is refocused on strength + breach testing: title/H1, meta description, keywords, `tool_title`, and an intro that points generation to the Random Password Generator, e.g. "Password Strength Checker & Breach Test" / "Verifica Password: Sicurezza e Violazioni" / "Passwort-Check: Stärke und Datenlecks". The how-to now starts with checking.
   - **In the app:** the **Auditor** tab opens first. The Generator tab links to the generator page in the visitor's language with `target="_top"`; the sandbox gained `allow-top-navigation-by-user-activation`, so it works only on a click.
   - **The generator pages' link sentence** now mentions the breach check.
   - **Side fix found by the visual suite:** the eye and clear buttons, now visible by default, were 23×35 px and too close together. They are now 44×44 and spaced apart.
   - **Test:** `pass-fort-page` checks the checker opens first, the Italian H1, and that the link navigates the top window to `/it/tools/password-generator/` and back-links.
4. **Small-size logo.** `static/images/logo-mark.svg` is a silhouette of the raven's head drawn from the full mark: one red (`#e91e20`, sampled from the logo) on the site's `--bg`, with the long beak, angled eye and shaggy throat kept. It's used for:
   - the header (28 px);
   - `favicon.svg`, plus `favicon-16x16.png` and `favicon-32x32.png` (the legacy `/favicon.png` now has the 32 px mark);
   - `apple-touch-icon.png` (180 px), and the manifest icons 192/512, which are full-bleed with the mark inside the maskable safe zone (`purpose: any maskable`);
   - `safari-pinned-tab.svg`, which was a shield and is now the one-colour silhouette.

   The full `logo.webp` stays for large uses. Old vs new at 16/24/32 px: `docs/screenshots/logo-comparison.png`.
5. **Home on phones.**
   - Below 768 px, each category shows its three `top` tools, and a `<details>` "Show all N" reveals the rest. It's pure CSS with `:has()`, and the summary follows the list in source order.
   - The picks live in `data/tool_icons.yaml` (`top:` per category, first three by title if absent).
   - Desktop renders every card in alphabetical order exactly as before; the summary is hidden at 768 px and up.
   - Result on a phone: 12 cards and 4 summaries instead of 31 cards.

### 7.4 Verification

- **Privacy guard:** 957 files, 20 images, 0 problems. **Static:** 2,840 HTML files, 0 broken internal links; 1,189 JSON-LD blocks, 0 errors; sitemap 537 URLs, all new tools in 6 languages.
- **Unit:** 55/55. **Functional:** all pass, including the updated fixtures and the new `pass-fort-page` test.
- **Tool pages:** 186 runs, 0 problems. **Visual:** 88 runs, 0 problems (after the PassFort tap-target fix). **Ads:** 420 runs, 0 problems, max CLS 0.019.
- **Lighthouse 12.6.1 mobile**, third parties blocked / allowed:

  | Page | Perf | A11y | BP | SEO | CLS |
  |---|---|---|---|---|---|
  | Home | 97 / 97 | 100 | 100 | 100 | 0.000 |
  | PassFort | 95 / 96 | 100 | 100 | 100 | 0.000 |

- **Screenshots:** the after set in `docs/screenshots/after/` is refreshed.

### Ad slots (separate commit `7e31d1c`)

- `slot_tool_after` 9173467729, `slot_article_mid` 2061972307, `slot_sidebar` 9967674640 (client and `slot_default` unchanged).
- **Fix needed to verify them:** on tool pages `article_mid` targeted the 3rd `<h2>`, which tool bodies rarely have, so it never rendered on any tool page. It now targets the 2nd, with the 450-word gap after `tool_after` unchanged, and renders on 55 of 186 tool pages.
- **Rendered at 1280 px:** a tool page shows `tool_after` + `article_mid` + `sidebar`; a learn page shows `article_mid` ×2 + `sidebar`. At 1024 px there's no sidebar unit.

## Federico TODO

Things only you can decide or provide. Nothing below was guessed. Resolved since Phase 6: AdSense slots (commit `7e31d1c`), accent-stripped content, the HTB Cap translations, and the small-size logo (Phase 7).

1. **About page** (6 languages): confirm or correct the facts parked in the `TODO(Federico)` front-matter comment before they are shown:
   - Cisco Ethical Hacker, ISC2 CC and Google Cybersecurity certificates;
   - the years of CNC work.
2. **`popular_guides`** (`hugo.toml`) and the **home `top:` tools per category** (`data/tool_icons.yaml`): both are hand-picked. Re-rank them from Umami.
3. **Review new and rewritten pages:** 186 pages carry `reviewed: false`, including every new tool page in 6 languages and PassFort's refocused copy. Read them, especially the non-English ones, and flip the flag.
4. **PassFort breach check in production:** after deploy, press **Check against known breaches** once on the live site and confirm a result appears. The `Add-Padding` header triggers a CORS preflight, and this could not be verified offline. If it fails, users see the "could not be reached" message, nothing worse.
5. **Translations of PassFort's UI:** the app itself is English-only, as it was before; the pages around it are localised.
6. **Email aliases:** check that Cloudflare Email Routing delivers `contact@`, `privacy@` and `security@federicosella.com` before deploy. The site now publishes only those.
7. **Logo:** look at `docs/screenshots/logo-comparison.png`. If you have a designer's simplified mark, swap it into `static/images/logo-mark.svg`. The favicon, touch and manifest PNGs were rendered from that SVG with headless Chromium (not scripted in the repo), so regenerate them the same way, and rerun `node scripts/og-card.mjs` for the share card.
8. **Merge:** branch `redesign` holds one commit per phase (plus the ad-slot commit) and is not pushed.
