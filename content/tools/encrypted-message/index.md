---
title: "Encrypted Message Link: Send a Secret Note"
description: "Encrypt a message in your browser with AES-256 and a passphrase, and share it as a link. The text is never uploaded: it lives only inside the link."
intro: "Write a message, choose a passphrase and get a **link** that contains the message **encrypted with AES-256-GCM**. Send the link and the passphrase **over different channels**; the recipient opens the link and decrypts it in their browser. Nothing is uploaded or stored: the encrypted text travels inside the link itself, in the part after `#` that browsers never send to a server."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["encrypted message link", "send encrypted message", "encrypt text online", "password protected message", "share password securely", "send a secret note", "encrypt message with password", "private message link"]
tags: ["security", "privacy", "encryption", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/encrypted-message/"
tool_title: "Encrypted message link"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Type the **message** — a Wi-Fi password, a door code, a short private note."
  - "Enter a **passphrase** of at least 8 characters, or press **Generate** for a random one."
  - "Press **Create encrypted link** and **Copy link**."
  - "Send the link over one channel (for example email) and the **passphrase over another** (a phone call, a different messenger). Never put both in the same message."
  - "The recipient opens the link, enters the passphrase and reads the message in their own browser."
faq:
  - q: "Is my message uploaded anywhere?"
    a: "No. Encryption runs in your browser with the Web Crypto API. The encrypted message is placed in the link after the # sign, and browsers do not send that part to the server when the link is opened. This site never receives the message, the passphrase or the link's fragment, so there is nothing stored that could leak or be deleted."
  - q: "Does the link self-destruct after reading?"
    a: "No, and no tool without a server can promise that. The link is the encrypted message, so it keeps working for as long as someone has a copy of it — in an inbox, a chat history or a backup. Treat it like the secret itself: anyone who gets both the link and the passphrase can read it. If you need a message that disappears, use a service that stores it on a server and deletes it after reading, and accept that you trust that server."
  - q: "How strong is the encryption?"
    a: "The message is encrypted with AES-256 in GCM mode, which also detects any change to the link. The key is derived from your passphrase with PBKDF2-HMAC-SHA-256 and 600,000 iterations, with a random salt and a random IV for every message. The weak point is the passphrase: a short or guessable one can be brute-forced by anyone who has the link, so use a long one or the Generate button."
  - q: "What if the passphrase is wrong or the link is cut off?"
    a: "Decryption fails with a clear message. Authenticated encryption cannot tell a wrong passphrase from a modified link, so check both. Some apps cut very long links: the tool warns you above about 2,000 characters."
  - q: "Why send the passphrase separately?"
    a: "Because the link alone is useless without it. If both travel in the same email or chat, anyone who can read that conversation — now or later, for example after an account is compromised — can read the message too."
  - q: "Can I see what the tool does?"
    a: "Yes. The code runs in your browser and can be read with the developer tools. You can also check in the Network tab that creating and opening a link sends no request containing your message."
---

## How it works

### Encryption in your browser

When you press **Create encrypted link**, the page generates a random 16-byte salt and a random 12-byte IV, derives a 256-bit key from your passphrase with **PBKDF2-HMAC-SHA-256** (600,000 iterations), and encrypts the message with **AES-256-GCM**. The salt, IV and ciphertext with its authentication tag are joined, encoded in Base64url and placed after `#v1.` in the link.

### Why the message never reaches a server

The part of a URL after `#` is the **fragment**. Browsers keep it on the device: it is not sent in the request for the page, and it is not included in the `Referer` header. The link opens a minimal page of this site, without ads or analytics, which reads the fragment, removes it from the address bar and asks for the passphrase. Decryption happens on the recipient's device.

### What it does not protect against

- **Someone with both the link and the passphrase** — that is how the recipient reads it, and how anyone else could.
- **A weak passphrase** — whoever has the link can try passphrases offline as fast as their hardware allows; the 600,000 iterations make each guess slow, not impossible.
- **A compromised device** — malware on the sender's or recipient's device can read the message before encryption or after decryption.
- **Copies of the link** — inboxes, chat histories and backups keep it. There is no way to revoke it.

## Use cases

- **Share a password or Wi-Fi key** with a colleague or a guest without leaving it readable in chat history.
- **Send a door code or alarm PIN** to a delivery person or a house sitter.
- **Pass a recovery code or API key** to a teammate over email, with the passphrase sent by phone.
- **Leave a private note** in a public place — a ticket, a forum, a shared document — that only people with the passphrase can read.
- **Before sending**, check how hard your passphrase is to guess with [PassFort](../pass-fort/).
