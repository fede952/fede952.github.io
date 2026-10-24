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
