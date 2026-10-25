---
title: "Base64 Encode & Decode Online (UTF-8)"
description: "Encode text to Base64 or decode Base64 and Base64URL back to text, with full UTF-8 support for accents and emoji. Free, instant, runs in your browser."
intro: "Convert text to **Base64** and back. Encoding is UTF-8 safe, and decoding also accepts the URL-safe **Base64URL** variant used in JWTs and web APIs, with or without `=` padding. Nothing you paste leaves this page."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["base64 encode", "base64 decode", "base64 decoder", "base64 encoder online", "base64url decode", "decode base64 to text", "utf-8 base64", "base64 converter"]
tags: ["encoding", "developer-tools", "base64", "tool"]
app_category: "DeveloperApplication"
tool_partial: "base64-converter"
howto:
  - "Type or paste into **Input text**: plain text to encode, or a Base64 string to decode."
  - "Press **Encode to Base64** to turn the text into Base64. Accents, non-Latin scripts and emoji are encoded as UTF-8."
  - "Press **Decode from Base64** to turn Base64 back into text. Standard Base64, Base64URL (`-` and `_`), missing padding and line breaks are all accepted."
  - "Read the result in **Output** and press **Copy** to put it on the clipboard."
  - "If the decoded bytes are not valid UTF-8, the tool says so: the data is probably binary (an image, a compressed blob or a key) rather than text."
faq:
  - q: "What is Base64 used for?"
    a: "Base64 represents binary data with 64 printable ASCII characters, so it can travel through systems that only handle text: email attachments (MIME), data URLs in HTML and CSS, JSON payloads, HTTP Basic authentication headers, Kubernetes Secrets and the three parts of a JSON Web Token."
  - q: "Is Base64 encryption?"
    a: "No. It is an encoding with no key: anyone can decode it instantly, as this page shows. Never use Base64 to hide passwords or secrets; Kubernetes Secrets, for example, are only Base64-encoded, not encrypted, unless you enable encryption at rest."
  - q: "What is the difference between Base64 and Base64URL?"
    a: "Base64URL (RFC 4648, section 5) replaces `+` with `-` and `/` with `_` so the result is safe in URLs and file names, and usually drops the `=` padding. JWTs and many APIs use it. This tool decodes both; when encoding it produces standard Base64."
  - q: "Why does my decoded text look garbled?"
    a: "Either the input was not text to begin with (for example an image or a gzip stream), or the original text was encoded with a different character set such as Latin-1 instead of UTF-8. The tool decodes as UTF-8 and warns you when the bytes are not valid UTF-8."
  - q: "Why is Base64 about a third larger than the original?"
    a: "Every 3 bytes of input become 4 Base64 characters, because each character carries 6 bits (2⁶ = 64). That is a 33% overhead, plus up to two `=` padding characters at the end. A 30 KB image becomes a 40 KB data URL."
  - q: "Is the text I paste sent anywhere?"
    a: "No. Encoding and decoding use the browser's built-in `btoa`, `atob`, `TextEncoder` and `TextDecoder` functions inside this page. Nothing is uploaded or stored."
---

## How it works

### Encoding

JavaScript's built-in `btoa()` only understands characters in the Latin-1 range, so calling it directly on `"Città €"` throws an error. The tool avoids that by encoding properly:

1. `TextEncoder` converts the text to **UTF-8 bytes**: `à` becomes `C3 A0`, `€` becomes `E2 82 AC`.
2. Each byte is mapped to a one-byte character, and `btoa()` turns that byte string into Base64.

Base64 works on groups of **3 bytes = 24 bits**, split into four 6-bit values, each mapped to one character of the alphabet `A–Z a–z 0–9 + /`. When the input length is not a multiple of 3, the last group is padded with `=`:

| Text | UTF-8 bytes | Base64 |
|---|---|---|
| `Man` | `4D 61 6E` | `TWFu` |
| `Ma` | `4D 61` | `TWE=` |
| `M` | `4D` | `TQ==` |
| `é` | `C3 A9` | `w6k=` |

### Decoding

Decoding reverses the process with some tolerance for real-world input:

- All whitespace and line breaks are removed (MIME wraps Base64 at 76 characters per line).
- The **Base64URL** characters `-` and `_` are mapped back to `+` and `/`, and missing `=` padding is restored, so a JWT segment can be pasted as is.
- `atob()` turns the Base64 into bytes, and `TextDecoder` with `fatal: true` interprets them as UTF-8. If the bytes are not valid UTF-8, the tool still shows a best-effort decoding but warns that the data is probably binary.
- A string whose length leaves a remainder of 1 when divided by 4 can never be valid Base64, and it is rejected with a clear message.

## Use cases

- **Reading a JWT by hand.** Paste the middle segment of a token to see its JSON claims (for signature checks, use the JWT Inspector).
- **Kubernetes and Docker.** Decode the values in a Secret manifest, or encode a value before putting it into `data:`.
- **HTTP Basic auth.** Decode an `Authorization: Basic …` header to see the `user:password` it carries, or build one for a test request.
- **Data URLs and email.** Inspect `data:` URIs and MIME parts in raw email sources.
- **Debugging APIs.** Many APIs Base64-encode binary fields or nested JSON; decode them to see what was actually sent.
