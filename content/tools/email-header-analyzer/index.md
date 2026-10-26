---
title: "Email Header Analyzer: Trace & Check Sender"
description: "Paste raw email headers to trace every server hop, check SPF, DKIM and DMARC and spot spoofed senders. Free, private, runs fully in your browser."
intro: "Paste the **raw headers** of a suspicious email to see where it really came from. The analyzer rebuilds the **route server by server** with the delay at each hop, reads the **SPF, DKIM, DMARC and ARC** verdicts recorded by your mail provider, and flags **mismatches** between From, Reply-To and Return-Path. Everything is parsed in your browser: the headers are never sent anywhere."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["email header analyzer", "analyze email headers", "check email headers", "email header checker", "trace email sender", "is this email spoofed", "spf dkim dmarc check email", "read email headers", "show original gmail headers"]
tags: ["security", "email", "phishing", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/email-header-analyzer/"
tool_title: "Email header analyzer"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Copy the raw headers from your mail app (see **How to get the headers** below) — or the whole message source, the body is ignored."
  - "Paste them into the box. The analysis runs as you paste; press **Analyze** to run it again."
  - "Read the **verdict** and the **signals**, most serious first. Each one explains what it means and when it is harmless."
  - "Check the **sender identity** table: the From, Reply-To and Return-Path domains should normally belong to the same organisation."
  - "Follow the **route** from the first server to your inbox. Long delays and unexpected servers are worth a second look."
faq:
  - q: "Are my headers uploaded?"
    a: "No. The headers are parsed by JavaScript in this page and the tool makes no network requests. You can load the page, disconnect from the internet and it still works."
  - q: "Can the analyzer tell me for certain that an email is phishing?"
    a: "No tool can. Headers show how a message travelled and whether the sender's domain vouched for it. A message can pass every check and still be a scam sent from a look-alike domain the scammer owns, so also look at the From domain itself and at the links (the Link Hazmat tool on this site checks those)."
  - q: "Why are some headers not trusted?"
    a: "Everything below the Received lines added by your own provider can be written by anyone along the way, including the sender. The analyzer trusts the Authentication-Results header added by your provider and treats the rest as claims. If you paste a message that was forwarded as an attachment, analyze the attached original, not the forwarding message."
  - q: "What do SPF, DKIM and DMARC mean?"
    a: "SPF lists which servers may send mail for a domain. DKIM is a cryptographic signature added by the sending domain. DMARC passes when SPF or DKIM passes for the same domain shown in From, and tells receivers what to do when neither does. ARC records the original results when a list or forwarder changes the message."
  - q: "Why does a genuine newsletter show a different Return-Path?"
    a: "Mailing services send on behalf of companies and collect bounces on their own domain or a subdomain. That is why a Return-Path or Message-ID on another domain is reported only as low severity: it matters when it comes together with a failed DMARC check or a Reply-To on an unrelated domain."
  - q: "Why do some times go backwards?"
    a: "Each server stamps the time from its own clock, and some clocks are wrong. The analyzer reports this as clock skew and still shows the route in order."
---

## How to get the headers

Most mail apps hide the headers. Open the message first, then:

- **Gmail (web)** — open the message, click the **⋮ More** button next to Reply and choose **Show original**. Press **Copy to clipboard**. The Gmail phone app cannot show headers; use a browser.
- **Outlook for Windows (classic)** — double-click the message to open it in its own window, then **File → Properties**. The headers are in the **Internet headers** box at the bottom: click inside it, press Ctrl+A and Ctrl+C.
- **New Outlook and Outlook on the web** — open the message, click **… More actions → View → View message details**, then copy the text.
- **Apple Mail (Mac)** — select the message and choose **View → Message → All Headers** (⇧⌘H), or **View → Message → Raw Source** (⌥⌘U) for the whole message. The Mail app on iPhone and iPad cannot show headers.
- **Thunderbird** — select the message and choose **View → Message Source** (Ctrl+U, ⌘U on a Mac). Copy everything above the first empty line, or simply all of it.

Menu names can differ slightly between versions. Do not forward the suspicious email to yourself to get its headers: forwarding creates a new message with new headers.

## How it works

### The route: reading Received headers from the bottom

Every mail server that handles a message adds a **Received** line at the top, so the oldest one is at the bottom. The analyzer reverses them into a timeline from the first server to your inbox and shows the time spent between hops. Only the lines added by your own provider are trustworthy: a sender can write fake Received lines below them, which is why the analyzer relies on authentication results rather than the claimed origin.

### Authentication: what your provider already checked

When a message arrives, your provider checks **SPF**, **DKIM** and **DMARC** and records the results in an **Authentication-Results** header. The analyzer reads that header and also checks **alignment**: a DKIM signature or an SPF pass only protects you when it is for the same organisation as the From address. It does not query DNS or verify signatures itself, because the provider has already done that at delivery time, with the keys that were valid then.

### Identity mismatches

The display name is free text, so phishers often put a trusted address in it (`"help@yourbank.example" <x@random.test>`). The analyzer compares the organisational domains of **From**, **Reply-To**, **Return-Path** and the **Message-ID**, and explains which differences are normal for mailing services and which point to an impostor.

## Use cases

- **A suspicious email** — check whether the "bank" or "delivery" message really came from that domain before you click anything.
- **Help desks and security teams** — triage reported phishing quickly and paste the timeline into a ticket.
- **Email deliverability** — see why your own newsletters fail DMARC or land in spam, and which hop delays delivery.
- **Learning** — understand SPF, DKIM and DMARC with real-shaped examples, then test yourself with the [Phishing Quiz](../phishing-quiz/).
