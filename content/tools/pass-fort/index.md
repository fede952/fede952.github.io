---
title: "Password Strength Checker & Generator"
description: "Test how strong a password is (entropy in bits, brute-force crack time) and generate random passwords or passphrases. Runs entirely in your browser."
intro: "**PassFort** generates random passwords and passphrases with your browser's cryptographic random number generator, and audits any password's entropy and brute-force crack time. Nothing you type ever leaves this page. The optional breach check sends only 5 characters of the password's hash, and only when you ask for it."
date: 2026-02-03
lastmod: 2026-10-25
reviewed: false
keywords: ["password strength checker", "password generator", "passphrase generator", "password entropy calculator", "how long to crack my password", "strong password generator", "random password", "password tester"]
tags: ["security", "passwords", "privacy", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/pass-fort/"
tool_title: "PassFort password generator and strength checker"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Open the **Generator** tab. Pick a length (8–128 characters) and the character sets you want: uppercase, lowercase, digits, symbols."
  - "For something you can type and remember, tick **Passphrase Mode** and choose 3–8 words. For a master password, use at least 6."
  - "Press **Generate Password** until you like the result, then the clipboard button copies it. Paste it straight into your password manager."
  - "To check a password you already use, switch to the **Auditor** tab and type or paste it. The eye button toggles visibility."
  - "Read the entropy meter, the estimated crack time and the checklist. Anything red is worth fixing before you reuse that password."
  - "Optionally, press **Check against known breaches** to see whether that exact password has appeared in a data breach. Nothing is sent until you press it."
faq:
  - q: "Is it safe to type my real password into this checker?"
    a: "Yes. The auditor is plain JavaScript running inside this page. It never makes a network request with what you type, and the value is gone as soon as you clear the field or close the tab. You can confirm it in your browser's developer tools (Network tab) while you type. If you prefer, test a password that *follows the same pattern* as your real one. The only exception is the optional breach check, and only when you press its button: it sends 5 characters of the password's SHA-1 hash, never the password (see the next question)."
  - q: "How does the breach check work without revealing my password?"
    a: "It uses the k-anonymity model of Have I Been Pwned's Pwned Passwords service. PassFort computes the SHA-1 hash of the password in your browser and sends only its first 5 hexadecimal characters to `api.pwnedpasswords.com`. The service replies with the roughly 1,000 hash endings that share that prefix, with their breach counts, and PassFort looks for a match locally. The request also asks for padding (`Add-Padding: true`), so every reply has a similar size whatever the result. The service never sees the password or its full hash; it does see your IP address, as with any web request. The check runs only when you press the button."
  - q: "How many bits of entropy does a strong password need?"
    a: "For accounts protected by a slow, salted hash, 60–70 bits of *random* entropy resists offline brute force for a very long time. For a password manager's master password or disk encryption, aim for 80–100 bits. A 16-character random password from all four character sets gives about 103 bits; a 7-word PassFort passphrase about 72 bits."
  - q: "Passphrase or random password: which is better?"
    a: "Both are strong when the words or characters are chosen randomly by a machine. Random character passwords pack more entropy per character and are ideal when a password manager types them for you. Passphrases are easier to type and remember, which makes them the better choice for the few passwords you must enter by hand, as long as you use enough words."
  - q: "Why does the checker say \"centuries\" for a password that I know is weak?"
    a: "The crack-time estimate assumes every character was chosen at random. Real attackers start with dictionaries, leaked-password lists and rules such as \"capital first letter, year at the end\", so `Summer2024!` falls in seconds even though its raw entropy looks decent. PassFort only flags a few obvious patterns (starting with 123, abc, password, qwerty, 111 or aaa), so treat a high score on a human-made password as an upper bound."
  - q: "What does \"10 billion guesses per second\" mean?"
    a: "It is the attack speed the estimate assumes: roughly a single modern GPU against a fast, unsalted hash such as MD5 or NTLM. Against bcrypt, scrypt or Argon2 an attacker is thousands of times slower, so real crack times are usually longer. Against an online login form with rate limiting they are far longer still."
  - q: "Does PassFort store or log the passwords it generates?"
    a: "No. Generated passwords exist only in the page's memory until you copy them. There is no account, no storage and no server behind the tool. Save the password in a password manager, because once you close the tab it cannot be recovered."
  - q: "How long should a password be in 2026?"
    a: "If a password manager generates and stores it, use at least 16 random characters; it costs you nothing. If you have to memorise it, use a passphrase of 6 or more random words. Length beats complexity rules: a long random password with only lowercase letters is stronger than a short one full of symbols."
---

## How it works

### The generator

Every character comes from `crypto.getRandomValues()`, the Web Crypto API's cryptographically secure random number generator, which the browser seeds from the operating system's entropy source. `Math.random()` is never used.

To turn a random 32-bit number into a position in the character set, PassFort uses **rejection sampling**: values that fall into the incomplete top "bucket" of the 32-bit range are thrown away and redrawn. The simpler `random % setSize` would make the first few characters of the set slightly more likely. That bias is tiny, but there is no reason to accept it.

The four character sets are 26 uppercase letters, 26 lowercase letters, 10 digits and 26 symbols (`!@#$%^&*()_+-=[]{}|;:,.<>?`), 88 characters in total. Each character therefore adds log₂(88) ≈ **6.46 bits** of entropy:

| Length | All four sets | Lowercase only |
|---|---|---|
| 12 | ≈ 77 bits | ≈ 56 bits |
| 16 | ≈ 103 bits | ≈ 75 bits |
| 20 (default) | ≈ 129 bits | ≈ 94 bits |

Characters are drawn independently, so a short password is not *guaranteed* to contain every selected set. Regenerate if a site insists on, say, one digit.

### The passphrase mode

Passphrase mode picks words from a built-in list of **1,207 English words** with the same unbiased random index, capitalises each one and joins them with hyphens (for example `Harbor-Canyon-Crisp-Velvet`). Each word adds log₂(1207) ≈ **10.24 bits**, so 4 words give about 41 bits, 6 words about 61 bits and the maximum of 8 words about 82 bits.

That is less per word than a full 7,776-word Diceware list (12.9 bits), which is why the guidance on this page is to use at least 6 words for anything important. The capitalisation and hyphens are fixed, so they add no entropy.

### The auditor

The auditor estimates the size of the "alphabet" your password draws from: 26 if it contains a lowercase letter, +26 for uppercase, +10 for digits and +33 for any other character. Entropy is then `length × log₂(pool)`.

Crack time is the time needed to try all 2^entropy combinations at **10¹⁰ guesses per second**, shown in human units up to "centuries". The meter fills at 100 bits and turns from red to orange, yellow and green at 25, 50 and 75 bits. Below it, eight checks are listed: at least 8 and 12 characters, each character class, no common starting pattern, and at least 60 bits.

This is the standard "brute-force" model. It is accurate for random passwords like the ones the generator makes, and **optimistic for passwords people invent**, because it cannot see dictionary words, names or dates.

### The optional breach check

A password can have high entropy and still be useless because it was leaked: attackers try breached passwords first. **Check against known breaches** asks Have I Been Pwned whether the exact password is in its list of passwords from real breaches, using k-anonymity: only the first 5 of the 40 hexadecimal characters of its SHA-1 hash leave the page (`5BAA6` for `password`), the comparison with the returned suffixes happens in your browser, and responses are padded so their size gives nothing away. It is off until you press the button, and typing a new password clears the previous result.

## Use cases

- **New accounts.** Generate a 16–20 character password and store it in your password manager. You never need to see it again.
- **The passwords you have to remember.** Your password-manager master password, your computer login, full-disk encryption: use a 6–8 word passphrase that you can type reliably.
- **Auditing old habits.** Paste a password you have used for years and see how it scores, then rotate the weak ones, starting with email and banking.
- **Wi-Fi keys and shared secrets.** WPA2/WPA3 passphrases can be up to 63 characters; a long random one costs nothing and stops offline cracking of a captured handshake.
- **Teaching and policy writing.** The table above and the live meter make entropy tangible when you explain to colleagues why "8 characters with a symbol" is no longer a good policy.
