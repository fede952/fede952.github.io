# Federico Sella Suite

![Built with Hugo](https://img.shields.io/badge/Built_with-Hugo-ff4088?style=flat-square&logo=hugo)
![Privacy First](https://img.shields.io/badge/Privacy-First-00e5ff?style=flat-square&logo=shield)
![100% Client-Side](https://img.shields.io/badge/100%25-Client--Side-00ff88?style=flat-square)
![Build Status](https://github.com/fede952/fede952.github.io/actions/workflows/hugo.yaml/badge.svg)
![License](https://img.shields.io/github/license/fede952/fede952.github.io)

**A collection of privacy-focused, browser-based utilities that never upload your data to the cloud.**

Every tool in this suite runs entirely in your browser. No server-side processing, no telemetry, no accounts. Your files and data stay on your device from start to finish.

---

## The Tools

### NetGuard
**Browser Leak & Fingerprint Detector**

Instantly audit your digital exposure. NetGuard reveals your public IP, ISP, approximate location, WebRTC leak status, GPU fingerprint, battery level, screen resolution, and browser metadata. Each data point is scored into a final **Privacy Score** (0-100) so you can see exactly how trackable you are. Includes exclusive VPN partner deals for users who want to lock things down.

### PixelShrink Pro
**Privacy-First Image Compressor**

Compress PNG, JPG, WebP, and AVIF images without uploading a single byte. Powered by `browser-image-compression`, PixelShrink runs locally via JavaScript with full control over quality, output format, maximum file size (MB), and maximum resolution (px). The before/after stats panel shows file size reduction and resolution changes in real time. Available in 9 languages with automatic locale detection.

### PassFort
**Secure Password Generator**

Generate cryptographically strong passwords with configurable length, character sets, and entropy display. Everything is computed client-side using the Web Crypto API.

### ReflexGrid
**Reaction Speed Trainer**

A fast-paced grid game that tests and trains your reflexes. Tracks your reaction times and displays statistics. Built for fun, stays private.

### And More

The suite also includes **EasyCron** (visual cron job generator), **GlitchForge** (glitch art creator), **ZenFocus** (Pomodoro timer), **Base64 Encoder/Decoder**, **Caesar Cipher**, **Hash Generator**, and **Freelance Calculator** - all running locally in your browser.

---

## Why This Exists

Most online tools are data traps. Upload an image to "compress" it and a server you don't control now has a copy. Run a "privacy test" and the test itself fingerprints you. Check your password strength and the password gets sent over the wire.

This suite takes a different approach:

- **Zero uploads.** Files are processed in-browser using modern Web APIs and JavaScript libraries.
- **Zero tracking.** No analytics, no cookies, no third-party scripts collecting behavioral data.
- **Zero accounts.** No sign-ups, no email harvesting. Open the tool and use it.
- **Open source.** Every line of code is inspectable in this repository.

---

## Live

### **[federicosella.com](https://federicosella.com/)**

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Static Site Generator** | [Hugo](https://gohugo.io/) (Extended) |
| **Theme** | PaperMod (customized) |
| **Styling** | CSS Custom Properties, inline scoped styles |
| **Tools Runtime** | Vanilla JavaScript (ES6+), Web APIs |
| **Image Compression** | [browser-image-compression](https://github.com/nicolo-ribaudo/browser-image-compression) via CDN |
| **Hosting** | GitHub Pages |
| **CI/CD** | GitHub Actions |
| **Internationalization** | 11 languages (EN, IT, ES, FR, DE, PT, RU, JA, ZH, KO, AR) |

## Getting Started

```bash
# Clone the repository
git clone https://github.com/fede952/fede952.github.io.git
cd fede952.github.io

# Initialize theme submodule
git submodule update --init --recursive

# Run the local dev server (drafts included)
hugo server -D
```

Open `http://localhost:1313/` in your browser.

## Project Structure

```
content/
  tools/           # Markdown content pages for each tool (multilingual)
  posts/           # Blog posts
static/
  tools/           # Self-contained HTML/JS/CSS for each tool (iframe targets)
  images/          # Logos, banners, and assets
  js/tools/        # Shared JavaScript modules
layouts/           # Hugo template overrides
.github/workflows/ # CI/CD pipeline configuration
```

## Deployment

Fully automated. Every push to `main` triggers a GitHub Actions workflow that builds the site with Hugo and deploys to GitHub Pages. No manual steps required.

## License

This project is open source and available under the [MIT License](LICENSE).
