---
title: "Security Headers & CSP Analyzer"
description: "Paste HTTP response headers or a Content-Security-Policy to find missing headers, weak CSP rules and unsafe cookies, with a fix for each. Nothing is fetched."
intro: "Paste the **response headers** of a page — from `curl -sI` or your browser's DevTools — or a **Content-Security-Policy** on its own. The analyzer checks **HSTS**, **CSP**, **X-Content-Type-Options**, framing protection, **Referrer-Policy**, **Permissions-Policy**, **COOP**, **CORS** and every **Set-Cookie**, explains each problem and shows the fix. It makes **no network requests**: it only reads what you paste, so it also works for staging and intranet sites."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["security headers check", "csp evaluator", "content security policy checker", "http security headers", "csp analyzer", "hsts check", "check response headers", "x-frame-options check"]
tags: ["security", "csp", "http", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/security-headers/"
tool_title: "Security headers and CSP analyzer"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Copy the response headers of the page you want to check: run `curl -sI https://example.com` in a terminal, or open DevTools → **Network**, reload, select the page request and copy its **Response Headers**."
  - "Paste them into **Response headers or CSP**. You can also paste just a policy (`default-src 'self'; …`) or a `<meta http-equiv=\"Content-Security-Policy\">` tag."
  - "The result appears as you paste: a grade, then every finding sorted from **High** to **Pass**, each with the header it concerns and what to change."
  - "Under **Content-Security-Policy**, each directive is listed with its sources; risky sources are highlighted in red or amber, safe ones in green."
  - "Press **Copy report** to paste the findings into a ticket or pull request. Try **Weak example** and **Strong example** to see the difference."
faq:
  - q: "Does the tool connect to my website?"
    a: "No. It does not fetch any URL — it only analyses the text you paste, in your browser. That keeps your server out of third-party logs and lets you check sites that are not public, such as staging, intranet or localhost."
  - q: "Why paste the headers instead of entering a URL?"
    a: "Fetching a URL from a web page is blocked by the browser's CORS rules unless a server does it for you, and that server would see every site you test. Pasting the output of `curl -sI` is just as quick and keeps everything local."
  - q: "What makes a Content-Security-Policy weak?"
    a: "The usual problems are `'unsafe-inline'` in script-src (lets injected inline scripts run), scheme sources like `https:` or `data:` and the `*` wildcard (allow scripts from almost anywhere), allow-listed CDNs that host JSONP endpoints or old AngularJS, and a missing object-src or base-uri. Google research found most allow-list based policies could be bypassed; nonces with 'strict-dynamic' avoid that."
  - q: "What is a strict CSP?"
    a: "A policy that allows scripts by a random nonce (or a hash) instead of by host, plus `'strict-dynamic'` so the scripts you trust can load others. It is the approach recommended by Google and OWASP against XSS. The example under \"How it works\" is a good starting point; deploy it as Content-Security-Policy-Report-Only first and fix what it reports."
  - q: "How is the grade calculated?"
    a: "It starts at 100 and subtracts 20 points per high finding, 10 per medium and 4 per low; informational notes and passes cost nothing. A+ requires no high or medium findings. The grade is a quick summary, not a certification: read the findings, because their impact depends on your site."
  - q: "Do I still need X-Frame-Options and X-XSS-Protection?"
    a: "CSP's frame-ancestors replaces X-Frame-Options in current browsers, but sending both is harmless and covers old ones, so the tool accepts either. X-XSS-Protection is obsolete: browsers removed the filter it controlled, so the tool recommends removing it or sending 0."
  - q: "Which cookie attributes does it check?"
    a: "Secure (sent only over HTTPS), HttpOnly (hidden from JavaScript), SameSite (limits cross-site sending, a CSRF defence), plus the rules for the __Host- and __Secure- name prefixes. A cookie with SameSite=None but no Secure is rejected by browsers and is flagged as high."
---

## How it works

### Paste, parse, check

The text you paste is split into header lines. Status lines such as `HTTP/2 200`, HTTP/2 pseudo-headers and folded lines are handled; when a redirect chain is pasted, only the last response is analysed. Repeated headers such as `Set-Cookie` are each checked. If the text starts with a CSP directive, or is a CSP `<meta>` tag, only the policy is analysed.

Each header is then compared with current browser behaviour and the recommendations of OWASP, MDN and the CSP specification. Every finding has a severity, the header it concerns and a concrete fix.

### The CSP checks

The policy is parsed into directives and sources. The analyzer works out which directive actually governs scripts (`script-src`, or `default-src` when it is missing) and plugins (`object-src` falls back to `default-src`; `base-uri` and `form-action` do not fall back at all). It flags `'unsafe-inline'` and `'unsafe-eval'`, wildcards, scheme sources, plain-HTTP hosts, allow-listed hosts known to serve JSONP or arbitrary library versions, short nonces, `'strict-dynamic'` without a nonce, and syntax mistakes browsers silently ignore: unquoted keywords (`self` instead of `'self'`), missing semicolons, duplicate, unknown and deprecated directives.

### A strict policy to start from

```text
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'self'
```

Generate a new random nonce (at least 128 bits) for every response, and add `nonce="{RANDOM}"` to each `<script>` tag. Send it as `Content-Security-Policy-Report-Only` first, fix what breaks, then enforce it.

## Use cases

- **Before a launch.** Check the headers of a staging site, which online scanners cannot reach.
- **Pull requests and audits.** Paste the headers before and after a change and copy the report into the review.
- **Learning CSP.** See why each source in a policy is or is not a risk, directive by directive.
- **Pentest and bug bounty notes.** Turn a captured response into a list of header findings with fixes.
- **Cookie review.** Check that session cookies are Secure, HttpOnly and SameSite after a framework upgrade.
