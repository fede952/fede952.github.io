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

## Phase 6 — E-E-A-T and technical SEO

### Author identity (one Person, everywhere)
- `[params.person]` in `hugo.toml`: name, jobTitle **Network Security Analyst**, photo, `sameAs` (the LinkedIn and GitHub
  URLs already in the config), `knowsAbout` (network security, SSE, SASE, Zero Trust, SOC operations, penetration testing).
- `templates/schema_json.html` rewritten: every block is a `dict | jsonify` (no hand-assembled JSON). The Person has a
  stable `@id` (`https://federicosella.com/#person`) and is embedded in full as `author` and `publisher` of every
  TechArticle, BlogPosting and WebApplication (crawlers don't resolve `@id` across pages). Home emits a `@graph` of
  WebSite + Person; the About page emits `ProfilePage` → Person. Zero dates are no longer emitted (pages without a
  `date` used to publish `0001-01-01`). The bulky `articleBody` copy of the whole article was dropped.
- **150 hand-written `schema_json` front-matter blocks removed** (all learn pages, 6 languages). They suppressed the
  generated schema and had no author, no dates and no headline; the 18 on roadmaps declared `HowTo` without any steps
  (invalid). The only useful field, `proficiencyLevel`, was migrated to a `proficiency:` param and is emitted on the
  TechArticle. The `schema_json` code path in `extend_head.html` is gone.
- Validation: all 2,787 built HTML files' JSON-LD parses (0 errors): 497 BreadcrumbList, 210 WebApplication, 144 FAQPage,
  168 TechArticle, 44 BlogPosting, 6 ProfilePage, 6 WebSite+Person graphs.

### Learn pages
- Breadcrumbs (same partial and BreadcrumbList as tools), a byline under the title — *By Federico Sella · Updated
  &lt;lastmod, localized date&gt;* linking to About with `rel=author` — and an **author box** after the article (photo,
  role, first-person bio: SOC / L2 network security, SSE/SASE, Zero Trust, eJPT; no employer or client named; links to
  About, LinkedIn, GitHub with `rel=me`). Strings in 6 languages, phrased gender-neutrally.
- **Related tools** on every learn article from `data/related.yaml` (`learn:` keys = path under `/learn/`), then tag
  similarity, then newest — same partial as tool pages.

### Search
- `WebSite` `SearchAction` → `/<lang>/?q={search_term_string}`. The search palette now honours `?q=` (opens with the
  query and results), and text typed while the index was still loading is no longer ignored. Note: Google retired the
  sitelinks search box in Nov 2024, so this markup won't produce a Google feature any more; it is valid schema and the
  deep link is useful on its own.

### Sitemap, robots, canonical
- Tag and category listings (139 tag + 15 category pages per language — over 60% of the old sitemap) are now
  `noindex` via a config `cascade` (`robotsNoIndex`, which PaperMod reads) and are excluded from the sitemap; they stay
  as navigation. The sitemap template lists only pages without `robotsNoIndex`, adds `x-default`, and drops
  `changefreq`/`priority` (ignored by Google; the old section-based priorities pointed at sections that no longer exist).
  Result: **503 URLs** across the 6 language sitemaps, all indexable (baseline: 1,398 in those 6 languages, mostly tags
  and news).
- `robots.txt`: removed `Disallow` lines for `/private/` and `/admin/` (paths that don't exist), kept the AI-crawler
  allowances and added the current `ClaudeBot` token next to the retired `anthropic-ai`; sitemap index URL declared.
- Canonical host checked: every canonical, hreflang and sitemap URL is `https://federicosella.com/…` (apex, matches
  `CNAME`); embedded apps' canonicals point to their EN tool page. The root `/` and alias pages are still meta-refresh
  pages on GitHub Pages → real 301s in Phase 8.

### Service worker: removed (kill switch)
- The old worker cached `/js`, `/vendor` and CSS **cache-first from unversioned URLs**: after this deploy, returning
  visitors would have kept the old scripts (e.g. the old iframe resizer) indefinitely. Registration removed; `/sw.js` is
  now a kill switch that deletes all caches, unregisters itself and reloads open tabs once. Verified in Chromium: a
  context running the old worker (1 registration, `fedesella-v1` cache) ends with 0 registrations and no caches.
- The cookie page's "Service Worker cache" row removed in all 6 languages. `manifest.json` and `icon-192/512.png` kept
  (installability doesn't require a service worker any more).

### Performance and accessibility (Lighthouse 13.5, mobile, local production build)
| Page | Perf | A11y | Best pr. | SEO | LCP | CLS | TBT |
|---|---|---|---|---|---|---|---|
| /en/ | 99 | 91 → **100** | 100 | 92 → **100** | 2.0 s | 0 | 0 ms |
| /en/tools/pass-fort/ | 97 | 92 | 100 | 100 | 2.3 s | 0.015 | 40 ms |
| /en/tools/pixel-shrink/ | 95 | 88 → **100** | 100 | 100 | 2.6 s | 0.014 | 50 ms |
| /en/learn/guides/osint-privacy-exif-data/ | 99 | 88 → **100** | 100 | 100 | 2.0 s | 0 | 0 ms |
| /it/learn/cheatsheets/nmap-network-scanning/ | 99 | 92 | 100 | 100 | 2.0 s | 0 | 0 ms |

Fixes behind the deltas: card CTAs "Read More" now carry the article title for screen readers (`.visually-hidden`);
contrast of the ad label, hero shortcut hint, GitHub-Sponsors button (#ea4aaa → #bf3989, 5:1) and tag chips; language
switcher links meet the 24 px target size; logo `<img>` had both `alt=""` and `aria-label`; links inside running text
are underlined (not colour-only). Lab numbers are from a local server without real ad fill — field data in Search
Console will be the real reference once the site is live.

### Verification
`hugo --gc --minify` 0 errors/warnings · 144/144 tool pages pass the Phase 5 audit · functional tool suite OK · CSP/JS
check 0/42 · search deep link OK · learn page visually checked at 1280 px and 390 px.

## Phase 7 — Affiliate partner blocks

- **Config-driven** (`[params.affiliate]` in `hugo.toml`): one partner per category, `<category>_name` +
  `<category>_url`, and a tool → category map (`[params.affiliate.tools]`, keyed by the tool's content directory).
  A block renders **only when both name and URL are set**; empty placeholders render nothing (verified: hash-generator
  and every unset category produce no markup).

  | Category | Tools | Status |
  |---|---|---|
  | `password_manager` | pass-fort, password-generator | **placeholder, empty** |
  | `vpn` | netguard, ghostprint, link-hazmat | pre-filled: NordVPN, your existing link (see below) |
  | `privacy` | exif-cleaner, steganography | **placeholder, empty** |
  | `devsec` | secrets-scanner, jwt-inspector | **placeholder, empty** |

- **Placement**: right after "How it works", before "Use cases" (inserted by `layouts/tools/single.html` before the
  2nd `<h2>`; checked on 4 tools).
- **Markup** (`partials/affiliate/block.html`): an "Affiliate link" label, a category heading and a short, accurate pitch
  (e.g. the VPN text says plainly that a VPN does not stop browser fingerprinting), a CTA with
  `rel="sponsored noopener"` and `target="_blank"`, and a localized disclosure: *"Affiliate link — I may earn a
  commission at no extra cost to you."* plus a privacy sentence ("the button opens <partner>'s website; nothing you
  entered in this tool is shared") linking to the privacy policy, whose section 7 (written in Phase 4, 6 languages)
  already describes affiliate links and referral cookies. All copy in EN/IT/ES/DE/FR/PT, gender-neutral where it
  refers to the author.
- **Existing NordVPN placements moved into the system.** Your real affiliate link
  (`go.nordvpn.net/aff_c?offer_id=15&aff_id=140342&url_id=858`) was hard-coded in three places: two banners in NetGuard
  (both with `id="vpn-cta"` — duplicate IDs; one sat above the Scan button, one was revealed after the scan) and an
  alert in Link Hazmat promising to "open safely with NordVPN Threat Protection" (an overclaim). All three removed; the
  same URL is now `vpn_url`, unchanged. **Small deviation from the plan's tool list:** Link Hazmat is mapped to `vpn`
  as well, so the placement it already had isn't lost — delete that one line in `[params.affiliate.tools]` if you
  don't want it. The two banner images (`nordvpn-box.webp`, `nordvpn-wide.png`) were left unreferenced and deleted
  (they remain in git history if you want image creatives back).
- Verification: a build with test partners injected via `HUGOxPARAMSxAFFILIATEx…` env vars rendered the right
  category on all 9 tools and none elsewhere; real build renders only the 3 VPN blocks. Screenshots at 1280 px/390 px.
  Tool suite (incl. NetGuard scan after the banner JS was removed), 144-page audit and CSP check: all pass.

## Phase 8 — Cloudflare `_headers` / `_redirects`

### Pre-existing bug found and fixed: legacy URLs of IT/ES/DE/FR/PT were 404
Hugo resolves `aliases` relative to the page's **language root**. The content declared them with the language prefix
(`/it/cheatsheets/x/` on an IT page), so Hugo wrote the redirect stub to **`/it/it/cheatsheets/x/`** — the old URL
`/it/cheatsheets/x/` had no redirect at all (same in the baseline build of `main`). EN had the same doubled form
(`/en/en/…`) next to a correct twin. **270 content files fixed** (225 non-EN aliases made language-relative; 41
redundant EN `/en/…` aliases dropped where the twin already existed, 4 converted). The `/xx/xx/` stub directories are
gone and every legacy URL now has a stub at the right path (works on GitHub Pages today).

### `_redirects` — generated, not hand-written
`public/_redirects` is produced by Hugo (`layouts/home.redirects`, output format `redirects` written to the publish
root) so it can never drift from the content:
- `/` → `/en/` **302** (a language-root redirect; kept temporary so language negotiation stays possible later).
- **319 alias rules (301)**: every front-matter alias → its page; EN aliases also without `/en` for the pre-`/en/`
  root-level URLs — except where a real static file lives (e.g. `static/games/<x>/`, which the game pages embed;
  caught by a `fileExists` guard after the first draft would have redirected them).
- Removed languages: `/zh-cn|hi|ar|ja|ru|ko/*` → `/en/:splat` (301). Removed news: `/news/*` and `/<lang>/news/*` →
  that language's Learn hub (301). 13 dynamic + 319 static rules (Cloudflare Pages limits: 100 / 2,000).
- Checked against the build: every target exists, no source shadows a real page.
- `static/404.html` (the GitHub Pages fallback) also sends old root-level English URLs to `/en/…` now (no loops).

### `_headers`
- All paths: `nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, HSTS 1 year (no `includeSubDomains`/
  `preload` until you confirm every subdomain is HTTPS-only), CSP = the minimal meta policy + `frame-ancestors 'self'`,
  `X-Frame-Options: SAMEORIGIN`, `Permissions-Policy` disabling camera/microphone/geolocation/payment/usb (unused
  anywhere — checked; ad APIs deliberately untouched), `COOP: same-origin-allow-popups`.
- Caching: `immutable` 1 year for fingerprinted `/assets/`, versioned `/vendor/…@x.y.z/` and `/fonts/`; 1 day +
  SWR for `/images/`; 1 h for `/js/`; always revalidate `/tools/*`, `/games/*` (apps) and `/sw.js` (kill switch);
  1 h for the search index.
- Verified with a local server that emulates Cloudflare Pages semantics (merged header rules, first-match redirects,
  `:splat`/`:placeholder`): redirect probes behave as listed above, and with all headers active the 144-page audit
  (iframes under `frame-ancestors`/XFO), the functional tool suite and the CSP check all pass.

### Docs and cleanup
- README → "Cloudflare": both setups (Cloudflare Pages = files work as-is, with build settings and post-deploy `curl`
  checks; Cloudflare proxy in front of GitHub Pages = files are inert, recreate headers with Transform Rules) and the
  dashboard settings (Full (strict), Always HTTPS, TLS ≥ 1.2, Rocket Loader **off**, no Auto Minify, respect existing
  cache headers, HSTS via header only).
- ARCHITECTURE.md updated (redirects, headers, sitemap, structured data, affiliate, related content).
- Dead code removed: the unused `partner-card` shortcode + its CSS + `partner_label` i18n key (superseded by the
  Phase 7 block).

## Phase 9 — Final verification

### Numbers vs baseline (same machine, Hugo 0.168.0, `hugo --gc --minify`)
| Metric | Baseline (`main`) | `overhaul` |
|---|---|---|
| Pages (Hugo count, all languages) | 14,457 | **2,509** (EN 413 · IT 424 · ES 419 · DE 417 · FR 419 · PT 417) |
| HTML files in `public/` | 17,221 | **2,753** |
| `public/` size | 535 MB | **43 MB** |
| Build time | ~162 s | **~9.5 s** |
| Content files | 10,703 | **495** |
| Tracked files in repo | 10,865 | **637** |
| URLs in the 6 kept languages' sitemaps | 1,398 (mostly tags + news) | **503**, all indexable |
| CSP violations on the 42-page sample | 684 | **0** |
| Tool pages with full copy + FAQ + schema | 0 | **24 × 6 = 144** |

### Checks on the final build
- Build: 0 errors, 0 warnings.
- **Internal link check** over every HTML file (2,753 files, 72,233 internal `href`/`src`/`srcset` references):
  **0 broken**. The only failure found — `/safari-pinned-tab.svg`, which PaperMod links from every page (1,462 pages)
  but which never existed — fixed by adding a small monochrome SVG mask icon.
- Playwright (Chromium): 144/144 tool pages (H1, JSON-LD types, FAQ DOM = schema, iframe `?lang` + auto-resize, 0 JS
  errors); functional suite for every tool with an action (compress, purge, QR, chart, password, JWT, secrets,
  fingerprint, NetGuard, search); steganography round-trip; StringMaster/ZenFocus/`?lang` checks; learn page
  breadcrumbs/byline/author box/related tools; `?q=` search deep link; service-worker kill switch; GitHub Pages 404
  fallbacks; Cloudflare headers/redirects via an emulating server. All pass.
- JSON-LD: every block on every page parses (0 errors).
- Lighthouse (mobile, local): Performance 95–99, Accessibility/Best Practices/SEO 100 on the re-measured pages
  (Phase 6 table).
- Not verifiable locally: real ad fill and AdSense policy review, Cloudflare's actual behaviour (emulated only),
  field Core Web Vitals.

## Federico TODO (what still needs you)

**Merge & deploy**
- [ ] Review the branch (`git log main..overhaul`, 9 commits) and merge it yourself. Nothing was pushed.
- [ ] After the first deploy: open a page you visited before in your normal browser and check DevTools → Application →
      Service workers shows nothing registered (the kill switch ran).

**AdSense**
- [ ] Create three display units (AdSense → Ads → By ad unit) and paste their IDs into `hugo.toml`
      `[params.ads]`: `slot_tool_top`, `slot_tool_after`, `slot_article_mid` (until then all use `slot_default`).
- [ ] If Auto ads is on, exclude `/*/about/`, `/*/privacy/`, `/*/cookies/`, `/*/contact/` (Phase 1).
- [ ] A week after deploy, compare impressions/RPM against the period before (the CSP fix should show up).

**Affiliate**
- [ ] Fill `[params.affiliate]` in `hugo.toml` once you have the programs: `password_manager_name/url`,
      `privacy_name/url`, `devsec_name/url`. Empty = no block (safe as is).
- [ ] Confirm the NordVPN link (`vpn_url`, moved unchanged from NetGuard/Link Hazmat) is still valid in your NordVPN
      affiliate dashboard; decide whether Link Hazmat should keep the VPN block (one line in `[params.affiliate.tools]`).

**Content review**
- [ ] Every tool page is `reviewed: false` (144 pages). Read the EN copy of the 24 tools, then spot-check the
      translations; flip to `reviewed: true` as you go. Translations were written directly in each language, so a native
      read matters most for IT (your language) first.
- [ ] Check the author-box bio and `jobTitle` ("Network Security Analyst") match how you want to present yourself; the
      About page still says "SOC Analyst" / "Security Developer" — align the two if you like.

**Cloudflare / hosting** (README → Cloudflare)
- [ ] Decide: move hosting to Cloudflare Pages (then `_headers` and the generated `_redirects` just work) or keep GitHub
      Pages behind Cloudflare (then recreate headers with Transform Rules). Apply the listed dashboard settings
      (Full (strict), Always HTTPS, Rocket Loader off, etc.).
- [ ] After switching: `curl -I` checks from the README (root 302, a legacy `/it/cheatsheets/…` URL 301, headers present).
- [ ] Only if every subdomain is HTTPS-only: add `includeSubDomains; preload` to HSTS.

**Search Console**
- [ ] Submit `https://federicosella.com/sitemap.xml` again; expect a wave of "Page with redirect" / "Not found" for the
      removed news and languages — that's intended.
- [ ] Watch "Duplicate without user-selected canonical" for the tag pages (now `noindex`) — they should drop out.

**Assets**
- [ ] `social-banner.png` (default share image) is 784×1168 portrait; replace it with a 1200×630 landscape image.
