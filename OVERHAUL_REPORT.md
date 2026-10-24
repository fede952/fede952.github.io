# Overhaul report — branch `overhaul`

Running log of the site overhaul. This file replaces all the old planning docs
(PHASE*_COMPLETED.md, PROJECT_SUMMARY.md, SITE_CONTENT_AUDIT.md, SEO_CONFIGURATION.md).

## Phase 0 — Baseline

- Branched `overhaul` from `origin/main` @ `3466769` (after pulling the NewsBot commits).
- Hugo: local was 0.153.4, CI was 0.146.0. Both are now **0.168.0 Extended** (latest stable, released 2026-10-13).
  CI `production.yaml` → `HUGO_VERSION: 0.168.0`, build now runs `hugo --gc --minify`.
- Deprecations surfaced by the bump, all fixed:
  - `languageCode` → `locale`, `languages.*.languageName` → `label`, `languagedirection` → `direction` (hugo.toml)
  - `.Language.LanguageName/LanguageDirection` → `.Language.Label/Direction` (our layout overrides)
  - Theme-internal deprecations (`.Language.LanguageCode` in rss/opengraph): PaperMod submodule bumped
    `7d061d5` (2025-12-20) → `26523e0` (upstream master, which includes the v0.158 deprecation fix and the
    new template system). Diffed the full `public/` output before/after: only the stylesheet hash and
    `og:locale` (`en-us` → `en_us`) changed.
  - `lang:` front matter (deprecated since 0.144): only used in `content/news/**`, removed in Phase 2.

### Baseline numbers (Hugo 0.168.0, `hugo --gc --minify`, Windows dev box)

| Metric | Value |
|---|---|
| Pages (Hugo count, all languages) | **14,457** |
| HTML files in `public/` | 17,221 |
| `public/` size | **535 MB** |
| Build time | **~162 s** |
| Content files | 10,703 (of which ~10,500 under `content/news/`) |

Pages per language:

| EN | IT | ES | ZH-CN | HI | AR | PT | FR | DE | JA | RU | KO |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2341 | 2648 | 947 | 956 | 942 | 954 | 948 | 948 | 946 | 955 | 949 | 923 |

## Phase 1 — Ad serving fix

**Root cause confirmed.** Playwright pass over the *baseline* build (old meta CSP), 42 pages
(home + 3 tools + 3 learn × EN/IT/ES/DE/FR/PT): **684 CSP violations**. Blocked hosts:

| Host | Violations | Effect |
|---|---|---|
| `pagead2.googlesyndication.com` (connect/frame) | 180 | AdSense requests/creatives blocked |
| `ep1.adtrafficquality.google` | 84 | AdSense traffic-quality beacon blocked → unfilled/invalid impressions |
| `region1.google-analytics.com` | 210 | GA4 hits blocked |
| `gateway.umami.is` | 126 | **Umami analytics was broken too** (new endpoint not in connect-src) |
| `federicosella.com` (absolute script URL, a localhost-testing artefact) | 84 | n/a in production |

Same pass on the new build: **0 CSP violations, 0 uncaught JS errors, 0 console errors, 42/42 HTTP 200.**

Changes:
- Meta CSP is now `upgrade-insecure-requests; object-src 'none'; base-uri 'self'; form-action 'self'` — no host allowlists.
- **Deleted:** `layouts/partials/adblock-detector.html`, `assets/css/extended/adblock-detector.css`,
  `static/js/ads.js` (adblock bait file, unreferenced), i18n keys `adblock_message` / `adblock_dismiss` (12 files).
- **Config-driven ad units** (`[params.ads]` in hugo.toml; empty slot → `slot_default`):
  - `partials/ads/enabled.html` — allowlist: only single pages in `tools` (incl. games) and `learn`; `noads: true` opts out.
    Home, section lists, about, contact, privacy, cookies, stack, links, projects and 404 never get units.
  - `partials/ads/unit.html` — one responsive unit with the CLS-safe reserved-height `.ad-slot` container; takes `position`.
  - `partials/ads/inject-content.html` — learn pages: `article_mid` auto-injected before the 2nd and 5th `<h2>`
    (= end of the 1st and 4th sections) when they exist.
  - `{{< ad-banner position="…" >}}` shortcode now wraps the partial and respects the allowlist.
  - Tool pages: `tool_top` below H1 + intro, `tool_after` right after the tool, `article_mid` before the 3rd `<h2>` of the
    long-form text (max 3). Applied to all 4 tool templates (tools/single, tool, tool-split, game).
  - Removed the manual `{{< ad-banner >}}` calls from easy-cron, freelance-calculator, netguard, pass-fort, pixel-shrink,
    reflex-grid (66 files) — they duplicated `tool_top`. News articles keep theirs until Phase 2 deletes them (they render
    nothing now, since news isn't in the allowlist).
- The AdSense loader now loads on every page except 404, including About (it used to be skipped there). Reason: Google's CMP is
  injected by adsbygoogle.js, so the footer "Cookie Settings" reopen link only works where the loader is present. If
  **Auto ads** is on in AdSense, exclude `/*/about/`, `/*/privacy/`, `/*/cookies/`, `/*/contact/` there, or keep Auto ads off.
- **GA4 removed:** `[services.googleAnalytics]`, `layouts/partials/google_analytics.html` (the gtag + Consent Mode default
  block existed only for GA4). Umami (cookieless) kept. Footer "Cookie Settings" link no longer depends on gtag: it pre-creates
  `googlefc.callbackQueue` and queues `showRevocationMessage()`, so it also works when clicked before the CMP has loaded.
- **Fonts self-hosted:** JetBrains Mono variable woff2 (latin 31 KB + latin-ext 12 KB, weights 400–700 in one file),
  `font-display: swap`, latin file preloaded, OFL licence included. Google Fonts `<link>` and both preconnects removed.
- Also fixed: `_default/single.html` rendered a nested `<main>` inside baseof's `<main>`, and had a dead
  "OPEN FULL SCREEN MODE" block for tools/games (those sections never use that template).

## Phase 2 — Automated news system removed

- **Deleted 9,728 tracked files**: 9,719 under `content/news/` (EN + 11 translations of every story, the section `_index.*`
  and `welcome-to-news.*`), plus `layouts/news/single.html`, `layouts/_default/news.html`, `layouts/partials/news-card.html`,
  shortcodes `cyber-report` and `netrunner-insight` (news-only), `scripts/fetch_news.py`, `scripts/.news_cache.json`,
  `scripts/requirements.txt` (only served fetch_news.py) and `.github/workflows/daily_news.yml`.
- Kept `layouts/_default/force-list.html`: it is also the layout of `/tools/` and `/tools/games/`; only its news branch was removed
  (same for `_default/list.html`).
- hugo.toml: `news` permalink, `news-categories` taxonomy and its `[related]` index removed; `[related]` kept (tags + date) because
  `partials/related-tools.html` uses `.Related`. `news` dropped from `mainSections` and from all 12 menus.
- Removed: home-page "Recent News" strip (+ its CSS), footer News link, `.news-card` / `.news-source` CSS,
  i18n key `home_recent_news` (12 files). Orphan i18n check after the cut: 0 orphaned keys.
- Search index and sitemap are generated from `site.RegularPages` / `.Data.Pages`, so news simply disappears from both.
- **Redirects:** `aliases: ["/news/"]` on every `content/learn/_index.*` → `/<lang>/news/` is a canonical meta-refresh to
  `/<lang>/learn/`. Deep news URLs (`/<lang>/news/2026/…`, `/news/…`) are caught by a small script in `static/404.html`
  (GitHub Pages has no server redirects); on Cloudflare `_redirects` does it with a real 301 (Phase 8).
- Build: 14,457 → ~4,600 pages, 162 s → 20 s.

## Phase 3 — Languages reduced to EN, IT, ES, DE, FR, PT

- hugo.toml: removed `zh-cn`, `hi`, `ar` (incl. `direction = "rtl"`), `ja`, `ru`, `ko`. Kept languages re-weighted
  EN 1 · IT 2 · ES 3 · DE 4 · FR 5 · PT 6 and given a proper `locale` each (`en-US`, `it-IT`, `es-ES`, `de-DE`, `fr-FR`,
  `pt-BR` — the PT copy uses Brazilian vocabulary, e.g. "senha"), so `og:locale` is now correct per language.
- **Deleted 489 content files** (`*.hi|ar|ru|ja|ko|zh-cn.md`) and 6 i18n files.
- Static tools/games: removed the ru/ja/ko/zh/zh-cn/ar/hi dictionaries from 10 embedded apps (chrono-sync, exif-cleaner,
  json-to-csharp, neon-palette, pixel-shrink, qr-generator, steganography, string-master, neon-blocks, sysadmin-tycoon —
  ~76 KB of strings), narrowed their `SUPPORTED_LANGS` / `LANGS` arrays and URL-language regexes to the 6 kept languages, and
  removed the `ar` → RTL branches. Every inline script re-parsed OK afterwards (node `vm.Script` syntax check); none of the
  apps had a visible language picker (they follow the parent page's `<html lang>`).
- hreflang audit over all of `public/`: only `en/it/es/de/fr/pt/x-default`, 0 duplicate tags, 0 targets that don't exist,
  `x-default` always → `/en/…`. PaperMod emits the per-translation tags but no `x-default`, so the custom x-default loop in
  `extend_head.html` was **kept** (it produces no duplicates).
- Language switcher (`partials/header.html`): links to the page's real translation, otherwise to the target language's home
  page, so it can never point at a missing translation.
- Old-language URLs: `static/404.html` sends `/hi|ar|ru|ja|ko|zh-cn/*` to `/en/*` on GitHub Pages; `_redirects` does a 301 on
  Cloudflare (Phase 8).

Pages per language after the cut:

| EN | IT | ES | DE | FR | PT |
|---|---|---|---|---|---|
| 392 | 391 | 382 | 382 | 382 | 382 |

## Phase 4 — Repo hygiene and dead code

- **Deleted planning docs (6):** PHASE1/2/3_COMPLETED.md, PROJECT_SUMMARY.md, SITE_CONTENT_AUDIT.md, SEO_CONFIGURATION.md.
  `ARCHITECTURE.md` rewritten from 26 KB to a ~100-line current description.
- **Deleted one-shot scripts (6):** create_password_gen_i18n.py, fix_language_links.py, force_hugo_build.py,
  replicate_content_globally.py, localize_sections.py, generate_i18n_indexes.py (only referenced by the gitignored local
  `.claude/settings.local.json` permission list), plus untracked `scripts/.claude/`. `scripts/` is gone.
- `.hugo_build.lock` was not tracked; `.gitignore` already covers `/public/`, `/resources/_gen/` and `.hugo_build.lock`.
  Local `public/` and `resources/_gen/` deleted.
- **Unused templates deleted (8)**, each with zero references, and confirmed by diffing the full `public/` build before/after
  (byte-identical): shortcodes `exercise-java`, `exercise-python`, `game-embed`, `tool-embed`; partial `tool-embed.html`;
  layouts `games/list.html`, `games/single.html`, `writeups/single.html` (no content uses `type: games|writeups`).
  Kept on purpose despite zero current uses: `ad-banner` (manual-placement API from Phase 1) and `partner-card` (Phase 7).
- **Unused CSS removed** from custom.css (~150 lines): the old `.tools-hero` / `.tools-grid` / `.tool-card*` product grid,
  `.tool-embed-container`, `.game-embed-container`, `.hljs`. Every other class in `assets/css/extended/*.css` is in use.
- **Images** (`static/images`):
  - Converted, all referenced from static apps or raw HTML: `pixel-shrink-icon.png` 1,063 KB → `.webp` 14 KB (resized to 2× display),
    `nordvpn-box.png` 631 KB → `.webp` 49 KB, `profile.jpg` 112 KB → `.webp` 8 KB (About ×6 with width/height; the
    `links` template now runs it through Hugo's pipeline, `Fill 240x240 webp`).
  - Deleted as unreferenced: `sysadmin-icon.png` (1.2 MB), `neon-blocks-icon.png`, `stego-tool.png`, `json-csharp.png`, `exif-tool.png`
    (2.4 MB total). The `image:` front-matter field pointing at them was read by no template (two paths were even wrong);
    removed from 30 content files, plus 6 `image:` lines pointing at a file that never existed (sysadmin-tycoon).
  - Markdown images already go through the render hook (`_markup/render-image.html` → WebP + width/height + lazy).
  - Left as is: `social-banner.png` (375 KB, the default OG image) — it is 784×1168 portrait, a poor OG shape; see TODO.
    `icon-192/512.png` are handled with the service-worker decision in Phase 6.
- **Workflow actions:** checkout v4→**v7**, configure-pages v5→**v6**, upload-pages-artifact v3→**v5**, deploy-pages v4→**v5**.
- **Third-party CDN removed (GDPR, same reasoning as the fonts):** medium-zoom and Fuse.js (loaded on *every* page from
  jsDelivr), exif-js, chart.js, browser-image-compression and qrcode-generator are now self-hosted in `static/vendor/`
  (pinned versions, licence table in `static/vendor/README.md`). PixelShrink's Web Worker gets `libURL` so it no longer
  pulls the library from jsDelivr either.
- **README honesty fix:** the "No servers. No tracking." claims are gone. It now says what is true: tools process all data
  locally and nothing you enter is uploaded; the site is funded by AdSense (with Google's consent management) and uses
  cookieless Umami analytics. The tools table was re-checked against the code (e.g. JWT Inspector verifies HS/RS/PS/ES,
  QR exports PNG only).
  The same false claim was in the home hero (`hero_subtitle`) and the footer tagline: both rewritten in 6 languages.
- **Privacy + Cookie pages rewritten in all 6 languages** to match reality: GA4 removed (and its cookies), Google Fonts/CDN
  removed (self-hosted), AdSense + Google CMP (TCF, `FCCDCF`/`FCNEC` consent cookies), Umami cookieless, hosting on GitHub
  Pages, the actual localStorage keys in use (the stale `adblock_acknowledged` row is gone), an affiliate-links section
  (NordVPN affiliate links already exist on NetGuard/Link Hazmat), and a disclosure that **NetGuard's Scan sends a request
  to ipwho.is** (inevitably revealing the visitor's IP) — the old text claimed no tool made any network request.
- Verification: Playwright exercised the tools touched here (PixelShrink compress via worker, EXIF purge, QR render,
  RateMate chart, PassFort, JWT decode, secrets scan, GhostPrint, NetGuard scan) and the Fuse.js search palette: all OK,
  0 JS errors, 0 CSP violations.

## Phase 5 — Tool pages: one template, real content, fixed tools

### Template (`layouts/tools/single.html`, one for all 24 tools)
- Structure: breadcrumbs → H1 → intro → ad `tool_top` → **tool** → ad `tool_after` → How to use (front matter `howto`)
  → How it works / Use cases (the Markdown body; the affiliate slot sits before its 2nd `<h2>`, Phase 7) → ad
  `article_mid` → FAQ (front matter `faq`, rendered as h3 + answer) → related guides + related tools (`data/related.yaml`).
- The tool comes from front matter, never from shortcodes: `tool_file` (self-contained app in `static/tools/<x>/`, embedded
  as an iframe with per-tool `tool_sandbox`/`tool_allow` — only the tokens each app needs, e.g. `allow-downloads` only for
  tools that save files, popups only for NetGuard/ZenFocus links), `tool_partial` (inline tool in `partials/tools/`) or
  `tool_html`+`tool_js`. The three shortcodes that held tools moved to `partials/tools/`; front matter of all 144 pages
  migrated (`layout:` and hand-written `schema_json` removed).
- The iframe `src` carries `?lang=<page language>` so localized apps follow the page, not the browser language
  (EN pages have no path prefix to sniff). `?lang` now takes precedence in StringMaster, ChronoSync, NeonPalette and
  QR Generator (they used to read their *own* `<html lang>` when opened directly).
- **Iframe auto-resize** (`/js/embed-resize.js` in every app and game → `/js/iframe-resizer.js` on the page): the child
  posts its content height to `location.origin` only; the parent accepts only same-origin messages whose `event.source`
  is one of its own iframes, then sets the height and `scrolling=no` (no scroll-in-scroll on mobile). The child also
  un-pins `min-height:100vh` wrappers that would otherwise lock the frame to its initial height. A start-up race (an app
  that finished loading before the parent listener existed and never changed height again — ReflexGrid — kept its
  scrollbar) is fixed with a `requestHeight` handshake from the parent.
- **JSON-LD**: `WebApplication` (name, `app_category`, operatingSystem Any, free `Offer`), `BreadcrumbList`, `FAQPage`
  generated from the same `faq` list the page renders — they cannot drift apart.
- **Ad slots without CLS**: `adsbygoogle.js` forces `height:auto!important;min-height:0!important` on *every ancestor* of
  the `<ins>`, so a reserved min-height on a wrapper collapses the moment the script runs. `partials/ads/unit.html` now
  reserves space with a sibling `.ad-slot-spacer` in the same CSS grid cell (`ad-slot.css`), which AdSense never touches.
  Measured layout shift of the slots: 0.
- New: `tool-page.css`, `partials/breadcrumbs.html` (`.Ancestors`, `<ol>`), `partials/related-guides.html`;
  `related-tools.html` reads `data/related.yaml` instead of picking by tag.

### Copy
All 24 tools × 6 languages rewritten from the tool's actual code (every number, limit and label checked against the
source): EN 723–1,188 words, translations ≤1,450; title ≤60 chars including " | Federico Sella", description 140–155
chars, 5–8 FAQs. UI labels are quoted exactly as the app shows them in that language (apps that are English-only are
quoted in English). **Every page is `reviewed: false`** — see TODO.

### Bugs found and fixed while documenting the tools
- PassFort + Password Generator: modulo bias → rejection sampling.
- PixelShrink: AVIF offered where the browser can't encode it (now feature-checked via `canvas.toBlob`), format choice
  reset on new file, no warning when the "compressed" file was larger than the original.
- QR Generator: non-ASCII text encoded wrong (now UTF-8), quiet zone < 4 modules, tiny PNG export (now ~1,200 px; output
  verified with a decoder).
- EXIF Cleaner: `DateTimeOriginal` and `LensModel` were not shown/purged (verified with piexif).
- ChronoSync: 13+ digit timestamps (milliseconds) misread as seconds.
- JSON→C#: missing `using System;` when `DateTime` properties are generated.
- Hash / Base64 / Caesar: logic moved to `static/js/tools/*.js`, UI localized; Base64 decode accepts Base64URL and
  missing padding and reports invalid UTF-8 instead of printing mojibake.
- chmod calculator: localized, "Others (o)", shell-quoted output. Link Hazmat: brand-impersonation check no longer flags
  the real domain itself.
- Steganography: semi-transparent pixels silently corrupted the message (canvas premultiplied alpha) — only opaque
  pixels carry data now; decoding no longer builds a string as long as the image (early exit on the signature);
  trailing whitespace of the message is preserved; iframe lacked `allow-downloads`, so **Encode & Download did nothing
  on the page**; UI strings had lost their accents (fixed in IT/ES/FR/DE/PT). Round-trip verified (UTF-8 + emoji,
  transparent areas, over-capacity rejection).
- StringMaster: "Characters" counted UTF-16 units (an emoji = 2) → grapheme count via `Intl.Segmenter`; Copy lacked
  `clipboard-write`.
- ZenFocus: the countdown decremented on each `setInterval` tick and drifted — badly in background tabs, where Chrome
  throttles timers — now computed from a fixed end time; the looped pink/brown noise clicked at every loop boundary
  (start/end mismatch, now removed); Share needed `web-share`/`clipboard-write`.
- Removed fake "ad unit" placeholders inside PassFort, NetGuard, RateMate and ReflexGrid.

### Verification
- `hugo --gc --minify`: 0 errors, 0 warnings.
- Playwright, all 144 tool pages (24 × 6): H1 present, JSON-LD parses with WebApplication + BreadcrumbList + FAQPage,
  FAQ count in DOM = in schema, iframe `?lang` matches the page, iframe resized → **144/144 OK**, 0 JS errors.
- Functional suite (one core action per tool: compress, purge, QR render, chart, password, JWT decode, secrets scan,
  fingerprint, NetGuard scan, site search) all OK; steganography round-trip, StringMaster counts, ZenFocus timer
  (pause holds), localized UI via `?lang` — OK.
- CSP/JS regression check on the Phase 1 page sample (42 pages): 0 violations, 0 errors.
