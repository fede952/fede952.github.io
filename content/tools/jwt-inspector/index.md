---
title: "TokenLens: JWT Decoder, Debugger & Signature Verifier"
description: "Decode and debug any JSON Web Token in your browser, then cryptographically verify its signature (HS/RS/ES/PS) with the Web Crypto API. 100% client-side — no token ever leaves your device."
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["jwt decoder", "jwt debugger", "jwt verify signature", "json web token", "jwt validator", "decode jwt online", "jwt signature verification", "rs256 verify", "es256", "hs256", "client-side jwt", "private jwt decoder"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — JWT Decoder & Signature Verifier", "description": "Free client-side JWT decoder, claims debugger and Web Crypto signature verifier supporting HS, RS, ES and PS algorithms.", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## What TokenLens does

TokenLens decodes any JSON Web Token directly in your browser and lays out the header, payload and every registered claim in plain language — issuer, subject, audience, and the exact local time a token was issued, becomes valid, or expires. It then lets you **cryptographically verify the signature** with the Web Crypto API against your own secret or public key.

Unlike server-based decoders, the token never leaves this page: no upload, no logging, no network request. That is exactly what you need when a token carries production claims or personal data and pasting it into someone else's server is not an option.

## Supported algorithms

- **HMAC** — HS256, HS384, HS512 (verify with a shared secret)
- **RSA** — RS256/384/512 and PS256/384/512 (verify with a PEM public key or JWK)
- **ECDSA** — ES256, ES384, ES512 (verify with an EC public key or JWK)

Paste a token to begin, or load the sample to see a verified HS256 signature.
