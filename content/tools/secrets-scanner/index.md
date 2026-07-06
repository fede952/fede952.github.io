---
title: "SafeEnv: Secrets & API Key Scanner for .env Files"
description: "Scan your .env files and config snippets for exposed secrets before you commit — AWS keys, GitHub and Stripe tokens, private keys, passwords in URLs and high-entropy values. 100% in your browser: nothing is ever uploaded."
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["env file scanner", "secret scanner", "api key checker", "detect leaked secrets", "scan env file for secrets", "aws key leak check", "git secrets scanner", "pre-commit secret scan", "client-side secret scanner", "check exposed api keys", "dotenv security"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv — Secrets & API Key Scanner", "description": "Free client-side scanner that finds exposed API keys, tokens, private keys and passwords in .env files and configs before you commit them.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Why scan before you commit

One pasted `.env` in a public repo is all it takes: bots scrape GitHub for fresh AWS keys in **under a minute**. SafeEnv catches the leak before the commit. Paste any configuration — `.env`, `docker-compose.yml`, CI config, source snippets — and it flags exposed credentials with the line number, a masked preview and concrete remediation steps.

The scan runs entirely in this page's memory. No upload, no logging, no network request — which is the only acceptable design for a tool you paste real secrets into. Reload the page and everything is gone.

## What it detects

- **Cloud & API tokens** — AWS access/secret keys, GitHub, GitLab, Stripe, Google, OpenAI, Anthropic, Slack, SendGrid, npm, PyPI, Telegram, Twilio
- **Private keys** — RSA/EC/OpenSSH/PGP PEM blocks
- **Credentials in URLs** — database connection strings and basic-auth URLs with embedded passwords
- **Generic leaks** — hardcoded passwords and high-entropy values, with placeholder detection to keep false positives down

Paste a config to scan it, or load the sample to see every detector fire on fake keys.
