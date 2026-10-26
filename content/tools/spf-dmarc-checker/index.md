---
title: "SPF, DKIM & DMARC Checker for Any Domain"
description: "Check a domain's SPF, DKIM and DMARC records, count SPF lookups against the limit of 10, check DKIM key sizes and BIMI, and get example fixes."
intro: "Enter a domain to grade its **email authentication**. The checker reads the **SPF** record and counts its DNS lookups **through every include** against the limit of 10, reads the **DMARC** policy, percentage, report addresses and alignment, measures **DKIM key sizes**, and checks **MX** and **BIMI**. Each problem comes with an **example record** to fix it. DNS lookups go to Cloudflare's DNS-over-HTTPS resolver, only when you press Check."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["spf checker", "dmarc checker", "dkim checker", "spf dkim dmarc check", "spf record check", "dmarc record check", "spf too many dns lookups", "check dkim key length", "dmarc policy checker", "bimi record check"]
tags: ["security", "email", "dns", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/spf-dmarc-checker/"
tool_title: "SPF, DKIM and DMARC checker"
tool_height: 1150
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Type a **domain** (or paste an email address; only the part after @ is used)."
  - "Optional: enter your **DKIM selectors**, separated by commas. Without them, the checker tries common selector names."
  - "Press **Check**. This is the only moment DNS queries are sent."
  - "Read the **grade** and each section: SPF with its lookup count and include tree, DMARC tags, DKIM keys, MX and BIMI."
  - "Under **Suggested fixes**, copy the example records, replace the parts in angle brackets and check with your mail provider before publishing them."
faq:
  - q: "What is sent, and to whom?"
    a: "When you press Check, your browser sends DNS queries for the domain (its TXT records for SPF, _dmarc, DKIM selectors and BIMI, and its MX records) to Cloudflare's public DNS-over-HTTPS resolver at cloudflare-dns.com. Like any web request, this reveals your IP address and browser user-agent to Cloudflare. Nothing is sent to this website, and nothing is sent before you press the button."
  - q: "Why does SPF have a limit of 10 lookups?"
    a: "The SPF standard (RFC 7208) caps the mechanisms that need a DNS query — include, a, mx, ptr, exists and the redirect modifier — at 10 per check, counted through every nested include. Receivers that hit the cap stop with a permanent error, so SPF fails for all of your mail, not just the extra senders. ip4, ip6 and all do not count."
  - q: "Why is no DKIM key found when my mail is signed?"
    a: "DKIM keys live under a selector name chosen by your provider (selector._domainkey.yourdomain), and DNS cannot list them. The checker only tries a few common names. Find your selector in the s= tag of a DKIM-Signature header (the Email Header Analyzer on this site shows it) and enter it."
  - q: "Is p=none good enough?"
    a: "It is the right first step: you receive reports without affecting delivery. But it does not stop anyone from spoofing your domain. Once the reports show your legitimate senders pass, move to p=quarantine and then p=reject."
  - q: "Should I use ~all or -all?"
    a: "Both mark unlisted servers as unauthorised. With DMARC at quarantine or reject, receivers act on the DMARC result anyway, so ~all is a common and safe choice; -all is stricter, and some receivers may reject on it before DMARC is evaluated."
  - q: "Are the example records ready to paste?"
    a: "They are starting points built from your current records. Parts in angle brackets must be replaced, and only you or your mail provider know every service that sends for your domain. Check with your provider, then re-run the checker after DNS has updated."
---

## How it works

### SPF: counting lookups the way receivers do

The checker fetches the TXT records of the domain and keeps the one starting with `v=spf1`. It then walks the record term by term. Every `include`, `a`, `mx`, `ptr`, `exists` and `redirect` adds one lookup, and every `include` is fetched and walked in turn, so nested providers are counted too. The total is compared with the limit of 10 from RFC 7208. The checker also flags includes that point to domains without SPF, more than two lookups that return nothing, include loops, the discouraged `ptr` mechanism, and the qualifier on `all`.

### DMARC: policy, coverage and reports

The record at `_dmarc.<domain>` is parsed tag by tag. A subdomain without its own record inherits the organisational domain's record and its `sp=` policy, as receivers do. The grade depends on the policy (`none`, `quarantine`, `reject`), on `pct`, on whether aggregate reports (`rua`) are enabled, and on whether report addresses on another domain have published the authorisation record they need (RFC 7489, section 7.1).

### DKIM: key size from the public key itself

For each selector found, the `p=` value is decoded and the size of the RSA modulus is read from the key. Keys below 1024 bits must not be accepted by receivers (RFC 8301); 2048 bits is the recommended size. Empty keys are reported as revoked, and Ed25519 keys are recognised.

### MX and BIMI

MX records show where the domain receives mail; a "null MX" (`0 .`) means it accepts none. BIMI (`default._bimi`) is optional and only works with an enforcing DMARC policy at 100%.

## Use cases

- **Before sending newsletters** — make sure SPF, DKIM and DMARC pass so mail reaches the inbox.
- **After adding a mail service** — check that the new `include:` did not push SPF over 10 lookups.
- **Securing a domain** — move DMARC from `p=none` to `p=reject` with confidence, and protect domains that never send mail.
- **Security reviews** — check a vendor's or your own organisation's domains for spoofing protection.
- **Investigating a suspicious email** — see what the sender's domain publishes, then read the message itself with the [Email Header Analyzer](../email-header-analyzer/).
