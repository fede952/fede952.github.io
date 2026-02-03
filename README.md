<div align="center">

# Federico Sella Suite
### Privacy-First Web Utilities

![Hugo](https://img.shields.io/badge/Hugo-Framework-ff4088?style=for-the-badge&logo=hugo&logoColor=white)
![Vanilla JS](https://img.shields.io/badge/JS-ES6+-f7df1e?style=for-the-badge&logo=javascript&logoColor=black)
![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-00c853?style=for-the-badge&logo=shield&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-2196f3?style=for-the-badge)

![Build Status](https://github.com/fede952/fede952.github.io/actions/workflows/hugo.yaml/badge.svg)

---

**A collection of high-performance, browser-based tools designed for privacy and speed.**
**No servers. No tracking. No bloat.**

<br>

[**View Live Demo**](https://federicosella.com/)

</div>

---

## Key Features

- **Global** — Translated into **12 languages**: EN, IT, ES, FR, DE, PT, RU, JA, KO, ZH, AR, HI
- **Lightweight** — Built with Hugo + Pure JavaScript. No React, no Angular, no framework overhead
- **Secure** — All processing (image compression, password auditing, fingerprint detection) happens in the browser via Web APIs and JS libraries. Nothing leaves your device

---

## The Tools

| Tool | Description | Tech |
|:-----|:------------|:-----|
| **NetGuard** | IP leak detector, WebRTC exposure test, GPU fingerprint scanner, Privacy Score (0-100). Includes VPN partner deals. | Fetch API, RTCPeerConnection, WebGL |
| **PixelShrink Pro** | Client-side image compressor with AVIF/WebP/PNG/JPEG support, quality slider, max file size and resolution controls. 9-language UI. | browser-image-compression.js |
| **PassFort** | Entropy-based password auditor with brute-force crack time estimator, passphrase generator, and strength scoring. | Web Crypto API |
| **ReflexGrid** | Cyberpunk aim trainer and reaction time test. 60-second sessions with accuracy and speed tracking. Built for FPS gamers. | Canvas API, requestAnimationFrame |
| **RateMate** | Freelance hourly rate calculator with tax, expense, and billable hours modeling. | Reactive DOM |
| **EasyCron** | Visual cron job builder with schedule explainer and next-run calculator. | Custom parser |
| **GlitchForge** | Glitch art generator with RGB shift, pixel sorting, and scanline effects. | Canvas pixel manipulation |
| **ZenFocus** | Ambient noise mixer and Pomodoro timer with rain, white noise, and brown noise channels. | Web Audio API |
| **Hash Generator** | MD5, SHA-1, SHA-256, SHA-512 hash generator. | Web Crypto API |
| **Base64** | Encode and decode text with full UTF-8 support. | btoa/atob + TextEncoder |
| **Caesar Cipher** | Classic shift cipher with configurable key. | String manipulation |

---

## Why This Exists

Most online tools are data traps. Upload an image to "compress" it and a stranger's server now has a copy. Run a "privacy test" and the test itself fingerprints you. Check your password strength and the password gets sent over the wire.

This suite takes a different approach:

- **Zero uploads.** Files are processed in-browser using modern Web APIs.
- **Zero tracking.** No analytics cookies, no third-party scripts harvesting behavioral data.
- **Zero accounts.** No sign-ups, no email collection. Open the tool and use it.
- **Open source.** Every line of code is inspectable in this repository.

---

## Quick Start

```bash
# Clone
git clone https://github.com/fede952/fede952.github.io.git
cd fede952.github.io

# Init theme submodule
git submodule update --init --recursive

# Run dev server
hugo server -D
```

Open `http://localhost:1313/` in your browser.

> Requires [Hugo Extended](https://gohugo.io/installation/) and Git.

---

## Project Structure

```
content/
  about/              Multilingual About page (12 langs)
  games/              Browser games (Deploy on Friday, Sudo Type)
  guides/             In-depth tutorials (DeepSeek vs ChatGPT, Local AI Setup)
  news/               Automated tech news feed (EN + IT)
  projects/           Portfolio projects
  tools/              Markdown content for each tool (multilingual)
  writeups/           CTF walkthroughs

static/
  tools/              Self-contained HTML/JS/CSS per tool (iframe targets)
  games/              Game builds
  js/tools/           Shared JS modules (base64, caesar, hash)
  images/             Logos, banners, icons

layouts/              Hugo template overrides and shortcodes
.github/workflows/    CI/CD (Hugo build + deploy, daily news automation)
```

---

## Tech Stack

| Layer | Technology |
|:------|:-----------|
| Static Site Generator | [Hugo](https://gohugo.io/) Extended |
| Theme | PaperMod (customized) |
| Styling | CSS Custom Properties, scoped inline styles |
| Tools Runtime | Vanilla JavaScript (ES6+), Web APIs |
| Image Compression | [browser-image-compression](https://github.com/nicolo-ribaudo/browser-image-compression) v2.0.2 |
| Hosting | GitHub Pages |
| CI/CD | GitHub Actions |
| PWA | Service Worker + Web App Manifest |
| Internationalization | 12 languages with Hugo i18n |

---

## Deployment

Fully automated. Every push to `main` triggers a GitHub Actions workflow that builds the site with Hugo and deploys to GitHub Pages.

---

## License

This project is open source and available under the [MIT License](LICENSE).
