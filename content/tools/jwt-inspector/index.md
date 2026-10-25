---
title: "JWT Decoder & Signature Verifier Online"
description: "Decode any JSON Web Token, read its claims and expiry, and verify HS256, RS256, PS256 or ES256 signatures with the Web Crypto API, all in your browser."
intro: "Paste a **JSON Web Token** to see its header and payload, check `exp`, `nbf` and `iat` in human time, and verify the signature with a secret or public key. Decoding and verification run in your browser; the token is never sent anywhere."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["jwt decoder", "jwt verify", "decode jwt online", "jwt signature verification", "jwt parser", "verify rs256 jwt", "jwt expiration check", "jwt debugger"]
tags: ["security", "developer-tools", "jwt", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/jwt-inspector/"
tool_title: "TokenLens JWT decoder and signature verifier"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-read; clipboard-write"
howto:
  - "Paste a token into the input box, or press **Paste** to read it from the clipboard. **Load sample** fills in a demo HS256 token."
  - "The token is split into its three coloured parts and decoded instantly: header and payload appear as highlighted JSON."
  - "Check the status chips: algorithm, `typ`, `kid`, and whether the token is expired or not yet valid. The claims table translates `exp`, `nbf` and `iat` into local dates."
  - "To verify, paste the **HMAC secret** for HS256/384/512 (tick *Secret is Base64URL-encoded* if it is), or the signer's **public key** as PEM or JWK for RS, PS and ES algorithms."
  - "Press **Verify signature**. Green means the signature matches that key and the token was not modified; red means wrong key or tampered token."
faq:
  - q: "Is it safe to paste a production JWT here?"
    a: "The tool runs entirely in your browser and makes no network requests with the token, so nothing is logged on our side. Still, a valid access token is a password with an expiry date: anyone who sees it can use it until it expires. Prefer expired or test tokens, and never paste one into a tool you cannot inspect."
  - q: "What is the difference between decoding and verifying a JWT?"
    a: "Decoding only reverses the Base64URL encoding of the header and payload. Anyone can do it: a JWT is signed, not encrypted. Verifying recomputes the signature over `header.payload` with the key and checks that it matches the third segment. Only verification tells you the token was issued by the key holder and not modified."
  - q: "Which algorithms can it verify?"
    a: "HS256, HS384 and HS512 (HMAC with a shared secret); RS256, RS384 and RS512 (RSA PKCS#1 v1.5); PS256, PS384 and PS512 (RSA-PSS); and ES256, ES384 and ES512 (ECDSA on P-256, P-384 and P-521). Tokens with `alg: none` or other algorithms are decoded but not verified."
  - q: "Where do I find the public key for an RS256 token?"
    a: "Most identity providers publish their keys as a JWKS at a URL such as `https://issuer/.well-known/jwks.json`. Find the entry whose `kid` matches the token header and paste that single JWK object. A PEM public key (`-----BEGIN PUBLIC KEY-----`) works too."
  - q: "Why does a token with \"alg\": \"none\" not verify?"
    a: "Because there is nothing to verify: the token claims to be unsigned. Accepting such tokens is a classic vulnerability; a server must decide which algorithms it accepts instead of trusting the header. The inspector shows the algorithm prominently so this stands out."
  - q: "My signature is valid but the API still rejects the token. Why?"
    a: "A valid signature is only one check. Servers also validate `exp`, `nbf`, the issuer (`iss`), the audience (`aud`) and often scopes. Look at the status chips and the claims table: an expired token or a wrong audience is the most common cause."
  - q: "Does the tool store the secret or key I paste?"
    a: "No. Keys are imported with `crypto.subtle.importKey` as non-extractable, used once for verification and discarded with the page. Nothing is written to storage."
---

## How it works

### Decoding

A JWT is three Base64URL segments joined by dots: `header.payload.signature`. The inspector splits the string, checks that there are exactly three segments, converts Base64URL to standard Base64 (replacing `-` with `+` and `_` with `/` and restoring the `=` padding), decodes the bytes as UTF-8 and parses the header and payload with `JSON.parse`. Malformed input produces a specific error instead of a blank screen.

The payload's registered claims are explained in a table. The time claims `exp` (expiration), `nbf` (not before) and `iat` (issued at) are **NumericDate** values, seconds since 1970-01-01 UTC, so they are converted to your local time and to a relative description such as "in 23 min" or "3 days ago". The status strip flags an expired token, a token that is not yet valid and a token with no `exp` at all.

### Verifying

Verification uses the browser's built-in **Web Crypto API** (`crypto.subtle`), not a JavaScript crypto library:

- The signing input is the ASCII string `header.payload`, exactly as it appears in the token. It is not re-encoded, which is why a token edited by hand fails verification.
- **HS256/384/512**: the secret is imported as a raw HMAC key with SHA-256, SHA-384 or SHA-512, and `crypto.subtle.verify('HMAC', …)` checks the MAC.
- **RS256/384/512**: the public key is imported as `RSASSA-PKCS1-v1_5` with the matching hash.
- **PS256/384/512**: imported as `RSA-PSS`, verified with a salt length equal to the hash length (32, 48 or 64 bytes), as RFC 7518 requires.
- **ES256/384/512**: imported as `ECDSA` on P-256, P-384 or P-521. JWS ECDSA signatures are the raw `r‖s` concatenation, the format Web Crypto expects, so no DER conversion is needed.

Public keys can be given as **PEM/SPKI** (the Base64 between the `BEGIN/END PUBLIC KEY` lines is decoded to DER) or as a **JWK** JSON object. Imported keys are non-extractable and live only for the verification call.

### A common pitfall

HMAC secrets are often configured as Base64 strings. If your backend decodes the secret before signing, tick *Secret is Base64URL-encoded*; otherwise the same visible string produces a different key and the signature will not match.

## Use cases

- **Debugging authentication.** See why a request returns 401: expired `exp`, wrong `aud`, a missing scope or a token signed by a different key.
- **Checking an identity provider integration.** Decode the ID token from an OAuth/OIDC login and verify it against the provider's JWKS before writing any backend code.
- **Security reviews and pentests.** Spot tokens with `alg: none`, overly long lifetimes, sensitive data in the payload or a `kid` that points somewhere unexpected.
- **Rotating keys.** Confirm that tokens issued after a rotation verify with the new public key and old ones with the previous key.
- **Teaching.** Show how a token is put together and why Base64URL is encoding, not encryption.
