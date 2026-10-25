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
