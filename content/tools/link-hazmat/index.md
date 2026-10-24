---
title: "Is This Link Safe? Phishing URL Checker"
description: "Paste a suspicious link and see the phishing tricks in its structure: IP hosts, hidden @ logins, punycode look-alikes, risky TLDs. Without opening it."
intro: "**LinkHazmat** dissects a URL *without visiting it* and flags the structural tricks phishing links rely on: IP-address hosts, hidden `@` logins, punycode look-alike domains, risky TLDs, brand names in subdomains and open-redirect parameters. Then it hands you one-click links to deeper reputation scanners."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["is this link safe", "check url safety", "phishing link checker", "suspicious link checker", "url scanner", "how to check if a link is safe", "phishing url detector", "link safety test"]
tags: ["security", "phishing", "url-scanner", "tool"]
app_category: "SecurityApplication"
tool_partial: "link-hazmat"
howto:
  - "Copy the suspicious link *without opening it*: long-press or right-click it and choose \"Copy link address\"."
  - "Paste it into the box and press **INITIATE SCAN** (or Enter). A missing `http://` is added automatically."
  - "Read the verdict: **LOW RISK**, **SUSPICIOUS** or **HIGH RISK**, with every trick that was detected listed under *Tricks detected*."
  - "Check the protocol, the real domain and the extension (TLD) the link actually points to; the real domain is often very different from what the text of the link suggests."
  - "For a second opinion, use the **VirusTotal**, **Google Transparency** or **Urlscan.io** buttons, which open those services with the link pre-filled."
faq:
  - q: "How can I tell if a link is safe before clicking?"
    a: "Look at the real domain, the part just before the first single `/`. In `https://paypal.com.secure-login.xyz/…` the domain is `secure-login.xyz`, not PayPal. Be wary of IP addresses instead of names, an `@` in the address, unusual extensions, lots of hyphens and anything that asks you to log in after arriving from an email or text message."
  - q: "Does LinkHazmat visit the link?"
    a: "No. The URL is only parsed as text with the browser's `URL` parser; nothing is fetched, so a malicious page cannot load or run anything. The only time a third party sees the link is if you press one of the external scanner buttons."
  - q: "Can a link marked LOW RISK still be dangerous?"
    a: "Yes. This is a structural check: it catches the tricks that make a link *look* legitimate, not whether the site behind a normal-looking domain is malicious. A freshly registered domain with a clean structure scores low. When in doubt, use the reputation scanners, or open the site by typing its address yourself."
  - q: "What is a punycode or homograph attack?"
    a: "Domains can contain non-Latin letters, which are stored in an ASCII form starting with `xn--`. Attackers register look-alikes such as `аpple.com` with a Cyrillic а, which displays almost like the real thing. LinkHazmat converts the host to its ASCII form, so any `xn--` label is exposed and flagged."
  - q: "Why is an @ in a URL suspicious?"
    a: "Everything before an `@` in the authority part of a URL is treated as a username, not a host. `https://www.bank.com@evil.example/` actually goes to `evil.example`. Legitimate links almost never use it, which is why the tool adds two points for it."
  - q: "Which TLDs are flagged?"
    a: "`.xyz`, `.top`, `.gq`, `.zip`, `.mov`, `.tk`, `.ml`, `.ga`, `.cf`, `.buzz`, `.icu` and `.cam`: extensions that are cheap or free to register and appear disproportionately in abuse reports. Plenty of honest sites use them, so this adds only one point."
---

## How it works

The input is parsed with the browser's standard `URL` constructor (with `http://` prepended if no scheme is given). That gives the protocol, the hostname in its ASCII form and the query string exactly as a browser would interpret them, which matters because phishing relies on the gap between what a URL *looks like* and where it *goes*.

Each check adds points to a risk score:

| Check | What it looks for | Points |
|---|---|---|
| Unencrypted | `http:` instead of `https:` | +1 |
| IP host | a hostname like `185.12.4.9` instead of a domain | +2 |
| Hidden login | an `@` anywhere in the input | +2 |
| Risky TLD | one of 12 frequently abused extensions | +1 |
| Long domain | hostname over 50 characters | +1 |
| Deep nesting | more than 4 labels, e.g. `a.b.c.d.com` | +1 |
| Punycode | a label starting with `xn--` (internationalised look-alike) | +2 |
| Hyphen-heavy | 3 or more hyphens in the hostname | +1 |
| Redirect parameter | `redirect=`, `url=`, `goto=`, `next=`, `redir=` or `link=` in the query | +1 |
| Brand in subdomain | paypal, apple, google, microsoft, amazon, netflix, bank, secure, login, verify or account to the *left* of the registrable domain | +2 |

A score of **0** is *LOW RISK*, **1–2** is *SUSPICIOUS*, **3 or more** is *HIGH RISK*. The brand check only looks at subdomain labels: `www.paypal.com` passes, while `paypal.com.account-check.xyz` (registrable domain `account-check.xyz`) is flagged. The registrable domain is approximated as the last two labels, so multi-part suffixes such as `.co.uk` are counted as one level too few.

The deep-scan buttons build links to VirusTotal's search, Google's Safe Browsing site status and urlscan.io's search with your domain or URL encoded in them. They open in a new tab only when you click them.

## Use cases

- **Checking a link from an email or SMS** that claims to be your bank, a courier or a streaming service, before deciding whether to touch it.
- **Help-desk and SOC triage.** Give a colleague a quick structural read of a reported link, then pivot to the reputation scanners.
- **Security awareness training.** Paste real-world phishing examples and show which tricks each one uses.
- **QR code links.** Decode a QR code with your phone's camera without opening it, then paste the URL here first.
- **Reviewing your own links.** Make sure marketing links with tracking or redirect parameters don't look like phishing to cautious users.
