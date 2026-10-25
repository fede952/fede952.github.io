<div align="center">

# Federico Sella
### Privacy-First Web Utilities

![Hugo](https://img.shields.io/badge/Hugo-0.168-ff4088?style=for-the-badge&logo=hugo&logoColor=white)
![Vanilla JS](https://img.shields.io/badge/JS-ES6+-f7df1e?style=for-the-badge&logo=javascript&logoColor=black)
![Local processing](https://img.shields.io/badge/Tools-Local%20processing-00c853?style=for-the-badge&logo=shield&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-2196f3?style=for-the-badge)

![Build Status](https://github.com/fede952/fede952.github.io/actions/workflows/production.yaml/badge.svg)

---

**Browser-based security and developer tools, plus practical guides and cheatsheets.**

[**federicosella.com**](https://federicosella.com/)

</div>

---

## Privacy, honestly

- **The tools process everything locally in your browser. Nothing you enter is uploaded**: no passwords, files, images,
  tokens or text ever reach a server. You can check this in your browser's Network tab. The one deliberate exception is
  NetGuard, which asks `ipwho.is` for your public IP (that is the point of the tool).
- **The site itself is funded by Google AdSense**, with Google's certified consent management (IAB TCF) for EEA/UK/CH
  visitors, and it uses **cookieless [Umami](https://umami.is/) analytics**. There is no Google Analytics.
- Some tool pages carry clearly labelled **affiliate links** (`rel="sponsored"`).
- Fonts and JS libraries are self-hosted. No Google Fonts, no public CDN.

Details: [Privacy Policy](https://federicosella.com/en/privacy/) · [Cookie Policy](https://federicosella.com/en/cookies/)

## Languages

EN · IT · ES · DE · FR · PT

## The tools

| Tool | What it does | Under the hood |
|:-----|:-------------|:---------------|
| **PassFort** | Password & passphrase generator + strength auditor with crack-time estimate | Web Crypto API (`crypto.getRandomValues`) |
| **Password Generator** | Quick secure password generator | Web Crypto API |
| **PixelShrink** | Image compressor (AVIF/WebP/PNG/JPEG), quality / size / resolution controls | browser-image-compression (Web Worker) |
| **QR Generator** | QR codes from any URL or text, PNG download | qrcode-generator + Canvas |
| **EXIF Cleaner** | Shows and strips photo metadata (GPS, camera, timestamps) | exif-js + Canvas re-encode |
| **NetGuard** | Public IP, WebRTC leak and GPU fingerprint check, privacy score | ipwho.is, RTCPeerConnection, WebGL |
| **GhostPrint** | Browser-fingerprint exposure test with uniqueness score | Canvas, WebGL, AudioContext, font probing |
| **JWT Inspector** | Decodes JWTs and verifies HS/RS/PS/ES signatures locally | Web Crypto API (`crypto.subtle.verify`) |
| **Secrets Scanner** | Finds API keys, tokens and private keys in pasted code/config | Regex rules + entropy, all in-page |
| **RateMate** | Freelance hourly-rate calculator (taxes, expenses, billable hours) | Chart.js |
| Hash Generator · Base64 · Easy Cron · chmod Calculator · Caesar · Steganography · ChronoSync · String Master · JSON→C# · Neon Palette · GlitchForge · ZenFocus · ReflexGrid · Link Hazmat | Smaller utilities | Vanilla JS / Web APIs |

Plus a handful of browser games under `/tools/games/`.

## Quick start

```bash
git clone https://github.com/fede952/fede952.github.io.git
cd fede952.github.io
git submodule update --init --recursive   # PaperMod theme
hugo server                               # http://localhost:1313/
```

Requires [Hugo Extended](https://gohugo.io/installation/) **0.168.0** (the version pinned in CI) and Git.
Production build: `hugo --gc --minify` → `public/`.

## Project structure

```
content/
  tools/          Tool pages (front matter + long-form copy, 6 languages); tools/games/ for games
  learn/          Guides, cheatsheets, interviews, roadmaps, writeups, debug-sys
  about/ contact/ privacy/ cookies/ stack/ links/ projects/
  apps/pasta-stack/   Privacy policy of the Pasta Stack mobile app (live, linked from the stores)
static/
  tools/ games/   Self-contained HTML/JS apps embedded by the tool pages (iframe targets, noindex)
  vendor/         Self-hosted third-party JS libraries (see static/vendor/README.md)
  fonts/          Self-hosted JetBrains Mono
layouts/          Hugo overrides, ad + affiliate partials, shortcodes
data/             related.yaml (tool ↔ guide internal links)
.github/workflows/production.yaml   Build + deploy to GitHub Pages
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the pieces fit together.

## Deployment

Every push to `main` runs `.github/workflows/production.yaml`: Hugo 0.168.0 Extended builds the site and deploys it to
GitHub Pages (custom domain `federicosella.com`).

### Cloudflare

The build also emits two files that only **Cloudflare Pages** reads (GitHub Pages serves them as plain files and
ignores them):

- `static/_headers`: security headers (nosniff, referrer policy, HSTS, CSP incl. `frame-ancestors`, frame options,
  permissions policy) and cache rules (a year for fingerprinted `/assets/`, versioned `/vendor/` and fonts; short for
  unversioned `/js/` and `/images/`; always revalidate the embedded apps and `/sw.js`).
- `public/_redirects`, **generated** by Hugo (`layouts/home.redirects`, output format `redirects` in `hugo.toml`) from
  every front-matter `aliases` entry, plus the removed languages (`/ar/*` … → `/en/:splat`) and the removed news section
  (→ `/<lang>/learn/`). Don't add a `static/_redirects`: it would collide with the generated one. Add an alias to the
  page instead (aliases are relative to the page's language: `/old-path/` on an IT page means `/it/old-path/`).

How to use them, depending on how Cloudflare is set up:

1. **Cloudflare Pages (recommended).** Create a Pages project from this repo with build command
   `hugo --gc --minify` (set `HUGO_VERSION=0.168.0`, and `HUGO_ENV=production`), output directory `public`, then move the
   custom domain to it and turn off the GitHub Pages workflow. Both files then work as-is. After the first deploy, check:
   `curl -I https://federicosella.com/` (expect `302` → `/en/`), `curl -I https://federicosella.com/it/cheatsheets/nmap-network-scanning/`
   (expect `301`), and that `Content-Security-Policy` and `Cache-Control` headers are present.
2. **Cloudflare as a proxy in front of GitHub Pages.** The files do nothing; the alias pages (meta refresh) and
   `static/404.html` keep handling old URLs. Recreate the important parts in the dashboard instead: Rules → Transform
   Rules → *Modify response header* for the security headers above, and Rules → Redirect Rules for `/` and the removed
   languages (`/ar/*` etc.) if you want true 301s.

Dashboard settings in either case: SSL/TLS mode **Full (strict)**; **Always Use HTTPS** on; minimum TLS 1.2;
**HSTS** only via the header (turn on `includeSubDomains`/`preload` in `_headers` only once every subdomain is
HTTPS-only, because preload is hard to undo); Speed → **Rocket Loader off** (it rewrites script loading and breaks
AdSense and the tool apps); **Auto Minify** is not needed (Hugo already minifies); Caching → **Browser Cache TTL:
Respect Existing Headers**; leave **Email Obfuscation** and **Bot Fight Mode** off if they interfere with AdSense
crawling (check AdSense → Sites for crawler errors after switching).

## License

MIT, see [LICENSE](LICENSE). Vendored libraries keep their own licences (static/vendor/README.md, static/fonts/).
