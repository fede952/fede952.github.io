---
title: "Browser Fingerprint Test: Am I Unique?"
description: "See the fingerprint your browser gives every website (canvas, WebGL GPU, audio, fonts, screen, time zone) and an estimated uniqueness score. No upload."
intro: "**GhostPrint** reads the same signals that tracking and anti-fraud scripts read silently on most websites, shows them to you one by one, and estimates how identifiable they make your browser. Every probe runs in this page; nothing is sent anywhere."
date: 2026-07-06
lastmod: 2026-10-24
reviewed: false
keywords: ["browser fingerprint test", "am i unique", "browser fingerprinting", "canvas fingerprint", "webgl fingerprint", "audio fingerprint", "how trackable am i", "fingerprint checker"]
tags: ["privacy", "security", "fingerprinting", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/ghostprint/"
tool_title: "GhostPrint browser fingerprint test"
tool_height: 2200
tool_settle_ms: 3000
tool_sandbox: "allow-scripts allow-same-origin allow-downloads allow-modals"
tool_allow: "clipboard-write"
howto:
  - "Open the page: the scan starts by itself. GhostPrint probes 12 signals in about two seconds and lists each one as it is read; **Re-scan** runs it again."
  - "Read the verdict and the headline number, for example \"1 in 2.1 million\": the estimated number of browsers you would have to look at before finding one with the same fingerprint."
  - "Scroll through the signal cards. Each shows the raw value, the bits of identifying information it contributes and a one-line explanation."
  - "Note your **Fingerprint ID**. Open this page in a private window or after clearing cookies: the ID stays the same, which is the whole point of fingerprinting."
  - "Use **Download shareable card** or **Copy summary** to compare browsers, or to show a colleague why clearing cookies is not enough."
faq:
  - q: "What is browser fingerprinting?"
    a: "It is a way to recognise a browser without storing anything on it. A script reads dozens of small properties (screen size, installed fonts, GPU model, how your machine renders a hidden image) and combines them into an identifier. No cookie is involved, so the identifier survives private browsing, cookie deletion and most \"clear data\" buttons."
  - q: "Is the uniqueness score a measurement?"
    a: "It is an estimate. Each signal is given a fixed weight in bits, based on how much identifying information that kind of signal typically carries in published fingerprinting research; the weights are summed, discounted by 18% because signals are correlated, and the result is capped at about 5.5 billion, the number of internet users. GhostPrint does not compare you with a database of other visitors, which is why it can run without collecting anything."
  - q: "Does incognito or private mode stop fingerprinting?"
    a: "No. Private mode deletes cookies and history when you close it, but your GPU, fonts, screen and canvas rendering are the same, so the fingerprint is the same. You can test it: the Fingerprint ID shown here does not change in a private window."
  - q: "Which browsers resist fingerprinting best?"
    a: "Tor Browser makes all its users look alike, which is the most effective approach. Brave randomises canvas, WebGL and audio readouts per site. Firefox has `privacy.resistFingerprinting`, which standardises many values. Safari reduces some signals by default. Chrome and Edge expose most of them unless you add an extension."
  - q: "Do anti-fingerprinting extensions help?"
    a: "Some do, especially those that randomise canvas and audio, but a rare extension can itself become a distinguishing trait. Blocking a signal outright, such as WebGL, can also make you more unusual. The goal is to look common, not invisible."
  - q: "Is any of my data sent to your server?"
    a: "No. All probes run in JavaScript inside this page and the result is rendered locally. There is no request to an analytics or fingerprinting service from the tool, and the downloadable card is generated on a canvas in your browser."
---

## How it works

GhostPrint collects twelve signals. Five are actively *measured* by drawing or rendering something; the rest are read from standard browser APIs.

**Rendering signals**

- **Canvas.** The page draws text (including an emoji and accented letters), a filled rectangle and an arc onto a hidden 240 × 60 canvas, exports it with `toDataURL()` and hashes the result with 32-bit FNV-1a. Fonts, anti-aliasing, the GPU and the graphics driver all leave tiny pixel differences, so the hash differs between machines. A blank or tiny output is treated as blocked.
- **WebGL.** It opens a WebGL context, reads the unmasked GPU vendor and renderer through `WEBGL_debug_renderer_info`, and hashes them together with the WebGL version, shading-language version, maximum texture and renderbuffer sizes, vertex-attribute limit and the full list of supported extensions.
- **Audio.** An `OfflineAudioContext` renders one second of a 10 kHz triangle wave through a dynamics compressor. The sum of 1,000 output samples is hashed; floating-point differences in each audio stack make it vary between devices. The probe gives up after 900 ms.
- **Fonts.** A hidden 72 px test string is measured in the three generic families (serif, sans-serif, monospace), then again with each of **53 common fonts** placed first. If the width or height changes, the font is installed. Your font set reflects your operating system, its language and the software you have installed.

**Read-only signals:** user-agent string, platform, screen resolution with pixel ratio and colour depth, time zone with UTC offset, preferred languages, CPU cores, device memory and touch points, colour-scheme and reduced-motion preferences, and cookie, Do-Not-Track and Global Privacy Control flags.

### From signals to "1 in N"

Each signal carries a fixed weight in bits:

| Signal | Bits |
|---|---|
| Canvas fingerprint | 8 |
| Fonts | 0.45 per detected font, max 8 |
| GPU model (WebGL) | 7 |
| User agent | 6 (8 if unusually long) |
| Audio fingerprint | 5 |
| Screen, time zone | 2 each |
| Languages, hardware | 1.5 each |
| Platform | 1 |
| Display preferences, privacy flags | 0.5 each |

A blocked or randomised signal counts as 0 bits. The total is multiplied by **0.82** to account for correlation (a given GPU usually implies a given platform, for example), then converted to "1 in 2^bits", capped at 5.5 billion. The verdict tiers are *Blending in* below 10 bits, *Identifiable* from 10, *Highly unique* from 18 and *Ghost-level exposure* from 28.

The **Fingerprint ID** is three 4-character FNV-1a hashes: of the user agent, platform and screen; of the WebGL and canvas hashes; and of every signal together. Its stability across private windows is the practical demonstration.

## Use cases

- **Understand why "clear cookies" is not privacy.** Run the test, clear everything, run it again: same ID.
- **Compare browsers and settings.** Try Firefox with `resistFingerprinting`, Brave, Tor Browser and your daily browser, and watch which cards drop to 0 bits.
- **Security awareness training.** A 30-second demo of the GPU and font cards makes the concept concrete for non-technical colleagues.
- **Check anti-fraud assumptions.** Developers building risk scoring can see which signals are stable and which are easily blocked.
- **Share the result.** The downloadable 1200 × 630 card (social-preview size) shows your verdict, entropy and ID without exposing the raw values.
