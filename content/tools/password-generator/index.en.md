---
title: "Random Password Generator: Secure & Free"
description: "Generate strong random passwords up to 64 characters with your browser's crypto RNG. Live entropy readout, one-click copy, nothing sent to any server."
intro: "A one-click **secure password generator**: pick a length and character sets, and get a random password drawn from your browser's cryptographic random number generator, with its strength shown in bits."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["random password generator", "secure password generator", "strong password generator", "generate password online", "password maker", "crypto random password", "16 character password generator"]
tags: ["security", "passwords", "tool"]
app_category: "SecurityApplication"
tool_partial: "password-generator"
howto:
  - "Drag the **Length** slider (8 to 64 characters). A new password is generated instantly every time you move it."
  - "Untick any character set the target site does not accept: uppercase **A–Z**, lowercase **a–z**, digits **0–9** or symbols **!@#**."
  - "Check the strength line under the password: it shows the entropy in bits and a label (Weak, Good, Strong)."
  - "Press **Generate password** for a fresh one, then the copy button next to the field puts it on your clipboard."
  - "Paste it into your password manager *before* closing the page. The generator keeps no history."
faq:
  - q: "Is this password generator really random?"
    a: "Yes. Each character is chosen with `crypto.getRandomValues()`, the browser's cryptographically secure random number generator, using rejection sampling so that every character in the set is exactly equally likely. It does not use `Math.random()`, which is predictable and not meant for secrets."
  - q: "Can the website see the passwords I generate?"
    a: "No. The generator is a few lines of JavaScript that run in your browser. There is no request to a server, no logging and no storage. Disconnect from the internet after the page has loaded and it keeps working, which is the simplest proof."
  - q: "What length should I choose?"
    a: "With all four character sets, 16 characters give about 104 bits of entropy, far beyond what any brute-force attack can reach. Use 20 or more for very sensitive accounts if the site allows it. Only go below 12 when a legacy system forces you to."
  - q: "Why does my password not contain a symbol even though symbols are enabled?"
    a: "Every character is drawn independently from the whole pool, so a password is not forced to include one character of each type. With 16 characters it almost always will. If a site rejects a password for missing a symbol or digit, press Generate again."
  - q: "What do Weak, Good and Strong mean here?"
    a: "They are bands of the password's entropy: below 60 bits is Weak, 60 to 90 bits is Good and 90 bits or more is Strong. Because the password is generated at random, this number is exact, unlike strength meters that guess the entropy of a password you typed yourself."
  - q: "Should I remember these passwords?"
    a: "No, store them in a password manager and let it fill them in. For the one or two passwords you must memorise, such as the manager's master password, a long random passphrase is easier to type. The PassFort tool on this site can generate one."
---

## How it works

The generator builds a pool from the sets you ticked: 26 uppercase letters, 26 lowercase letters, 10 digits and 29 symbols (`` !@#$%^&*()_+~`|}{[]:;?><,./-= ``), up to **91 characters**. For each position it asks the Web Crypto API for a random 32-bit number with `crypto.getRandomValues()` and maps it to a character.

That mapping uses **rejection sampling**. 2³² is not a multiple of 91, so the plain `random % 91` would make a few characters very slightly more likely than the others. Instead, any value in the incomplete top slice of the 32-bit range is discarded and drawn again, and every character ends up with exactly the same probability.

The strength line is not a guess. Since every character is uniformly random, the entropy is exactly **length × log₂(pool size)**:

| Settings | Bits per character | 12 chars | 16 chars | 24 chars |
|---|---|---|---|---|
| All four sets (91) | 6.51 | 78 | 104 | 156 |
| Letters + digits (62) | 5.95 | 71 | 95 | 143 |
| Lowercase + digits (36) | 5.17 | 62 | 83 | 124 |
| Digits only (10) | 3.32 | 40 | 53 | 80 |

The label is **Weak** below 60 bits, **Good** from 60 to 90 bits and **Strong** at 90 bits and above. The bar is full at 128 bits. Changing the length or a checkbox regenerates the password immediately, so what you see always matches the settings.

Copying uses the asynchronous Clipboard API where the page is served over HTTPS, with a fallback for older browsers. The password lives only in the input field: reload the page and it is gone.

### Why entropy is the right measure

An attacker who knows exactly how this generator works, pool and length included, still has to try on average half of all 2^bits combinations. At 104 bits that is about 10³¹ guesses: even at 10 billion guesses per second it would take far longer than the age of the universe. That is why a password from a good generator is strong *by construction*, while a password you invent is only as strong as the attacker's dictionary is small.

## Use cases

- **Signing up for a new service.** Generate 16+ characters, save them in your password manager, done.
- **Rotating a password after a breach notice.** Replace a reused or leaked password with a unique random one, starting with your email account, because it can reset all the others.
- **API keys, database users and service accounts.** Untick symbols if a connection string or shell script chokes on them, and raise the length to keep the entropy above 100 bits.
- **Wi-Fi networks.** Generate a 20–30 character key for your router; you only type it once per device.
- **Temporary credentials.** Create a one-off password for a guest account or a shared document, then delete the account when you are done.

To check the strength of a password you already use, and whether it appears in a known data breach, try [PassFort](/en/tools/pass-fort/).
