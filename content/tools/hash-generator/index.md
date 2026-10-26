---
title: "Hash Generator & File Checksum Verifier"
description: "Generate MD5, SHA-1, SHA-256 and SHA-512 hashes of text, or verify a downloaded file against its published checksum. Runs in your browser, nothing uploaded."
intro: "Type or paste text to get its **MD5, SHA-1, SHA-256 and SHA-512** hashes as you type, or **verify a file**: pick a download, paste the checksum from the publisher's page and get a clear **match or mismatch**. Files of any size are hashed in a background worker, piece by piece, and never leave your device."
date: 2026-02-03
lastmod: 2026-10-26
reviewed: false
keywords: ["hash generator", "sha256 generator", "md5 generator", "sha512 hash online", "sha1 hash", "text to sha256", "checksum generator", "online hash calculator"]
tags: ["cryptography", "hash", "developer-tools", "tool"]
app_category: "DeveloperApplication"
tool_partial: "hash-generator"
howto:
  - "Type or paste your text into **Input text**. All four hashes are recalculated on every keystroke."
  - "Read the result you need: **MD5** (32 hex characters), **SHA-1** (40), **SHA-256** (64) or **SHA-512** (128)."
  - "Press **Copy** next to a hash to put it on the clipboard."
  - "To compare with a hash you were given, paste both into a text editor or compare them character by character: one different character means different input."
  - "Press **Clear all** to empty the input and the results."
  - "To check a download, scroll to **Verify a file checksum**, choose the file and paste the checksum the publisher gives (a bare hash or the line from a SHA256SUMS file). The algorithm is picked from its length."
faq:
  - q: "Which hash algorithm should I use?"
    a: "For integrity checks, fingerprints and new designs, use SHA-256 (or SHA-512). MD5 and SHA-1 are broken for security: practical collision attacks exist, so they must not be used for signatures or certificates. They are still fine for non-security uses such as cache keys or matching a legacy checksum."
  - q: "Can I hash a password with this tool?"
    a: "You can compute the SHA-256 of any string, but a plain SHA hash is the wrong way to store passwords: it is designed to be fast, so attackers can test billions of guesses per second. Real systems use a slow, salted password-hashing function such as Argon2id, bcrypt, scrypt or PBKDF2."
  - q: "Why is my hash different from another tool's?"
    a: "Almost always the input differs. Check for a trailing newline (`echo` adds one; use `echo -n`), spaces, Windows `\\r\\n` line endings or a different text encoding. This tool hashes the exact characters in the box, encoded as UTF-8."
  - q: "Can I hash a file?"
    a: "Yes. Use **Verify a file checksum** below the text hashes. The file is read in your browser in chunks by a background worker (with the hash-wasm library, served from this site), so even multi-gigabyte files work without filling the memory, and nothing is uploaded. The command-line equivalents are `sha256sum file` on Linux, `shasum -a 256 file` on macOS and `Get-FileHash file -Algorithm SHA256` in Windows PowerShell."
  - q: "Can a hash be reversed or decrypted?"
    a: "No. A hash is a one-way function: there is no key and no way to compute the input from the output. \"MD5 decrypt\" websites simply look up precomputed hashes of common words, which is exactly why short or common inputs are not protected by hashing."
  - q: "Is anything I type sent to a server?"
    a: "No. SHA-1, SHA-256 and SHA-512 are computed with `crypto.subtle.digest()` and MD5 with a JavaScript implementation, all inside this page. There are no network requests with your input."
---

## How it works

On every input event the tool reads the text box, converts it to bytes with `TextEncoder` (UTF-8, so `é` becomes two bytes and an emoji four) and runs four hash functions in parallel with `Promise.all`:

- **SHA-1, SHA-256 and SHA-512** go through the browser's native **Web Crypto API**: `crypto.subtle.digest('SHA-256', bytes)` returns an `ArrayBuffer`, which is converted to lowercase hexadecimal.
- **MD5** is not part of Web Crypto, because it is considered broken, so it is computed by a compact JavaScript implementation of RFC 1321 working on the same UTF-8 bytes.

The results are hexadecimal strings whose length is fixed by the algorithm, whatever the size of the input:

| Algorithm | Output size | Hex characters | Status |
|---|---|---|---|
| MD5 | 128 bits | 32 | Broken (collisions since 2004) |
| SHA-1 | 160 bits | 40 | Broken (practical collision, 2017) |
| SHA-256 | 256 bits | 64 | Secure, the common default |
| SHA-512 | 512 bits | 128 | Secure, faster on 64-bit CPUs |

Two properties make these functions useful. They are **deterministic**: the same input always gives the same hash, on any machine. And they have an **avalanche effect**: change one character and about half of the output bits flip, so `Hello` and `hello` have completely unrelated SHA-256 values. The `Copy` buttons use the Clipboard API, with a fallback for older browsers.

### Text, not files

The input is text from the box, so the hashes match command-line tools only when the bytes match exactly. `printf 'Hello, World!' | sha256sum` and this tool agree; `echo 'Hello, World!' | sha256sum` does not, because `echo` appends a newline.

## How to verify a download

A checksum proves that the file you have is bit-for-bit the file the publisher hashed. It catches broken and truncated downloads, and a tampered file on a mirror.

1. **Get the checksum from the official source** — the project's own download page or release notes, ideally over HTTPS. A checksum hosted next to the file on the same mirror proves little: whoever can replace the file can replace the checksum too.
2. **Download the file**, then open **Verify a file checksum** on this page and choose it.
3. **Paste the expected checksum.** You can paste the whole line from a `SHA256SUMS` file, a `SHA256 (file) = …` line or PowerShell output; the tool finds the hash and the algorithm.
4. **Read the verdict.** *Match* means the file is identical. *Mismatch* means it is not: delete it and download it again from the official site. One different character is a mismatch; there is no "almost the same".
5. **Prefer SHA-256 or SHA-512.** MD5 and SHA-1 still detect accidental corruption, but collisions can be crafted on purpose, so they do not prove a file was not swapped.

For the strongest check, some projects also sign their checksum files with GPG or Sigstore. Verifying that signature proves who published the checksum; this tool checks that your file matches it.

## Use cases

- **Verifying a download checksum.** Many projects publish the SHA-256 of a release string or small config; paste the text and compare.
- **Debugging signatures and APIs.** Check the hash an API expects for a payload, or the SHA-256 that goes into an AWS Signature V4 or webhook verification.
- **Cache keys and deduplication.** Derive a stable identifier from a URL, a query or a document's text.
- **Learning cryptography.** Watch the avalanche effect live, compare digest lengths and see why MD5 and SHA-1 are retired for security.
- **Matching legacy data.** Recreate an MD5 or SHA-1 value an old system stored, to migrate it to something stronger.
