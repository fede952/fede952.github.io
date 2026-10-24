# Architecture

Static Hugo site (Extended 0.168, PaperMod theme as a git submodule) deployed to GitHub Pages by
`.github/workflows/production.yaml`. Six languages, all in subdirectories: `/en/ /it/ /es/ /de/ /fr/ /pt/`.

## Content model

| Path | What | Layout |
|---|---|---|
| `content/tools/<tool>/index.<lang>.md` | One page per tool: front matter + long-form copy | see "Tool pages" |
| `content/tools/games/<game>/` | Browser games | `layout: game` or tools/single |
| `content/learn/<sub>/<page>/` | guides, cheatsheets, interviews, roadmaps, writeups, debug-sys | `_default/single.html` |
| `content/about|contact|privacy|cookies|stack|links|projects/` | Site pages | various |
| `content/apps/pasta-stack/privacy/` | Live privacy policy of a mobile app — **do not move or delete** | `_default/single.html` |

The English file is `index.md` (no suffix); translations are `index.<lang>.md` in the same bundle, so Hugo links them
as translations automatically.

## Tool pages

The interactive part of a tool is a self-contained HTML app in `static/tools/<tool>/index.html` (or
`static/games/<game>/`), embedded in the page with an `<iframe>`. These apps are `noindex` with a canonical pointing to
the parent tool page, pick their UI language from the parent page's `<html lang>`, and never send user data anywhere.
Four templates render tool pages:

- `layouts/tools/single.html`: default for the `tools` section (iframe or shortcode inside the markdown body)
- `layouts/_default/tool.html`: `layout: tool`, iframe from `tool_file` front matter
- `layouts/_default/tool-split.html`: `layout: tool-split`, inline tool (`tool_html` + `tool_js`) next to an explanation
- `layouts/_default/game.html`: `layout: game`

`partials/related-tools.html` closes every tool page with 4 related tools (Hugo `.Related` on tags).

## Monetization

**AdSense.** `extend_head.html` loads `adsbygoogle.js` on every page except 404 (it also injects Google's consent
banner, which the footer "Cookie Settings" link reopens). Manual units are config-driven:

- `[params.ads]` in hugo.toml: `client`, `slot_default`, `slot_tool_top`, `slot_tool_after`, `slot_article_mid`.
  An empty slot falls back to `slot_default`.
- `partials/ads/enabled.html`: the allowlist. Only single pages in `tools` and `learn` get units; `noads: true` opts out.
- `partials/ads/unit.html`: one responsive unit in a CLS-safe reserved-height container (`ad-slot.css`).
- `partials/ads/inject-content.html`: learn pages get `article_mid` before the 2nd and 5th `<h2>`; tool pages before the 3rd.
- Tool templates place `tool_top` under the intro and `tool_after` after the tool (max 3 units per page).
- `{{< ad-banner position="…" >}}` places a unit manually in markdown.

**Affiliate.** `partner-card` shortcode/partial, config under `[params.affiliate]`; a block whose URL is empty
renders nothing. Links are `rel="sponsored noopener"` with a visible localized disclosure.

## Head, privacy, security

- Meta CSP is minimal on purpose (`upgrade-insecure-requests; object-src 'none'; base-uri 'self'; form-action 'self'`).
  Host allowlists broke AdSense, whose creative hosts rotate. Full security headers live in `static/_headers`
  (applied by Cloudflare Pages; GitHub Pages ignores the file).
- Analytics: Umami, cookieless, production builds only. No Google Analytics.
- Fonts (`static/fonts/`) and JS libraries (`static/vendor/`) are self-hosted; no third-party CDN.
- `layouts/partials/extend_head.html` also emits the hreflang `x-default` (PaperMod emits the per-language ones).

## Search, sitemap, redirects

- Search: `layouts/_default/index.json` builds a per-language JSON index of regular pages; the command palette in
  `extend_footer.html` loads it lazily with Fuse.js (Ctrl/Cmd+K).
- Sitemap: `layouts/_default/sitemap.xml`, skips pages with `robotsNoIndex`.
- Removed sections/languages: `/<lang>/news/` is a Hugo alias of `/<lang>/learn/`. Deeper old URLs are redirected
  by `static/_redirects` (Cloudflare, 301) and by a small script in `static/404.html` (GitHub Pages fallback).

## Caching

`partials/footer.html` is `partialCached` in `baseof.html` keyed by `.Layout .Kind .Section` (+ two params, and
implicitly the language). Anything inside the footer may only depend on those inputs.

## Build

```bash
hugo --gc --minify     # → public/   (~10 s, ~2,300 pages)
```

CI and Cloudflare Pages both pin `HUGO_VERSION=0.168.0` and need submodules checked out.
