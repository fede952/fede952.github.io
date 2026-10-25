---
title: "What Is My IP? Browser Privacy & Leak Test"
description: "See your public IP, ISP and location, check WebRTC local-IP exposure, GPU and device fingerprint signals, and get a privacy score. Free, one click."
intro: "**NetGuard** shows what any website can learn about you the moment you connect: your public IP address, ISP and approximate location, plus the device signals your browser hands out for free. One click, a privacy score, and plain explanations."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["what is my ip", "my ip address", "ip leak test", "webrtc leak test", "browser privacy test", "check my vpn", "what websites know about me", "privacy score"]
tags: ["privacy", "network", "vpn", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/netguard/"
tool_title: "NetGuard browser privacy and IP leak test"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
howto:
  - "Press **Run Privacy Scan**. The scan takes about four seconds, most of it spent waiting for the WebRTC check."
  - "Read **Network & Location**: the public IP address, ISP and city every web server sees when you connect, looked up through ipwho.is."
  - "Check the **WebRTC** card. Green means your browser did not expose a private network address; red lists the addresses it leaked."
  - "Look at the fingerprint cards (operating system, browser, screen, GPU, language and time zone, battery). Each one is readable by any site without a permission prompt."
  - "Compare the **Privacy Score** before and after a change, for example connecting a VPN, switching browser or blocking WebGL, and press **Scan Again**."
faq:
  - q: "What is my IP address and who can see it?"
    a: "Your public IP address is the address your internet provider (or VPN) assigns to your connection. Every website, ad server and CDN you contact sees it, because it is needed to send the page back to you. It usually reveals your provider and your city or region, rarely your exact street."
  - q: "Does a VPN hide my IP from this test?"
    a: "Yes, the IP, ISP and location cards will then show the VPN server's details instead of yours, which is the point of a VPN. The privacy score itself does not know whether an address belongs to a VPN, so it deducts the same points for any visible IP: compare the cards, not just the number."
  - q: "What is a WebRTC leak?"
    a: "WebRTC lets browsers make peer-to-peer connections for video calls. To do that, it gathers \"ICE candidates\", the network addresses where your device can be reached. Older browsers exposed the device's private LAN address (such as 192.168.1.23) to any page through this mechanism. NetGuard checks exactly that, and modern browsers now hide it behind a random `.local` name."
  - q: "Can NetGuard tell if my VPN leaks my real IP through WebRTC?"
    a: "Not completely. The check runs without a STUN server, so it reveals local network addresses but does not ask an outside server what your public address looks like over WebRTC. To test that specific VPN leak, enable the VPN, open a dedicated STUN-based WebRTC test, and compare the public address it reports with the IP shown here."
  - q: "Why is my GPU model visible?"
    a: "Through the WebGL extension `WEBGL_debug_renderer_info`, a page can read the exact graphics renderer string, for example an NVIDIA or Apple GPU model. Combined with screen size, time zone and language it narrows you down to a small group of devices. Some browsers return a generic value or block it, which NetGuard reports as safe."
  - q: "Does this tool store or send my data?"
    a: "Only one request leaves your browser: the lookup to ipwho.is that returns your public IP and its location, which any site you visit could make. Everything else is read and displayed locally, and nothing is saved when you close the page."
---

## How it works

The scan runs five checks in sequence, entirely in the page, then turns them into a score.

**1. Network identity.** The browser calls `https://ipwho.is/`, a public IP-geolocation API. The response contains the address your request came from, the ISP or organisation that owns it, and the country, city and approximate coordinates of that address. This is the same information any web server can derive from your connection, which is why the card is marked as a warning.

**2. Connection quality.** Where the **Network Information API** exists (Chromium-based browsers), `navigator.connection` reports the estimated downlink in Mbps, an effective connection type such as `4g`, and the round-trip time. Firefox and Safari do not expose it, and the card says so.

**3. Device fingerprint.** NetGuard reads the signals that fingerprinting scripts collect most often:

- operating system and browser version parsed from the `User-Agent` string, plus `navigator.platform`;
- screen resolution, device pixel ratio, viewport size and colour depth;
- the **GPU renderer and vendor**, from a WebGL context through the `WEBGL_debug_renderer_info` extension;
- `navigator.language` and the time zone from `Intl.DateTimeFormat().resolvedOptions()`;
- battery level and charging state through `navigator.getBattery()`, where the browser still implements it.

**4. WebRTC local-address check.** The page creates an `RTCPeerConnection` with no ICE servers, opens a data channel and generates an offer. The browser then emits *host* ICE candidates, each containing a network address. NetGuard collects the IPv4 addresses, ignoring mDNS names ending in `.local`, which modern browsers use to hide the real LAN address. Any address it does collect is listed as exposed. After four seconds the check ends.

**5. Privacy score.** The score starts at 100 and loses points for each exposure found:

| Signal | Points |
|---|---|
| Public IP and location could be looked up | −30 |
| Private IP exposed via WebRTC | −20 |
| OS, browser and screen readable | −10 |
| Exact GPU model readable | −10 |
| Language and time zone readable | −5 |
| Battery status readable | −5 |

Desktop Chrome typically scores 40 (we measured exactly that); browsers that hide the GPU string or do not implement the Battery API score 5–15 points higher. The number is a conversation starter rather than a lab measurement; the individual cards are what matter.

## Use cases

- **Check that your VPN is on.** Connect it and scan: the IP, ISP and city should belong to the VPN provider, not your home connection.
- **See what a website learns before you sign up.** The cards are exactly what an analytics or ad script can read on its first page view.
- **Compare browsers.** Run the scan in Chrome, Firefox, Brave and Safari; the GPU, battery and connection cards differ a lot between them.
- **Troubleshoot geo-blocking.** If a streaming site thinks you are in the wrong country, the location card shows which country your IP appears to be in.
- **Teach the basics.** A two-minute demo of NetGuard explains IP addresses, fingerprinting and WebRTC better than a slide deck. For a deeper fingerprint analysis, try GhostPrint.
