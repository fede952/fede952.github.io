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
