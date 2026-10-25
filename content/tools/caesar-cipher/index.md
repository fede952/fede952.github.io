---
title: "Caesar Cipher Encoder & Decoder (ROT13)"
description: "Encrypt and decrypt text with the Caesar shift cipher, any shift from 1 to 25 including ROT13. Learn how it works and how it is broken. Free and private."
intro: "Shift every letter of your text by a fixed number of places in the alphabet, the cipher Julius Caesar used. Pick a shift from 1 to 25 (13 gives **ROT13**), then encrypt or decrypt. A classic for puzzles, CTFs and learning why simple ciphers fail."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["caesar cipher", "caesar cipher decoder", "caesar shift", "rot13", "shift cipher", "caesar cipher encoder", "decode caesar cipher", "classical cipher"]
tags: ["cryptography", "cipher", "ctf", "tool"]
app_category: "EducationalApplication"
tool_partial: "caesar-cipher"
howto:
  - "Type or paste your message into **Input text**."
  - "Set the **Shift key** with the slider (1–25). Caesar's own choice was 3; 13 is ROT13."
  - "Press **Encrypt** to shift letters forward, or **Decrypt** to shift them back by the same amount."
  - "Read the result in **Output** and press **Copy** to put it on the clipboard."
  - "To crack an unknown message, decrypt with each shift in turn until readable words appear; there are only 25 to try."
faq:
  - q: "How does the Caesar cipher work?"
    a: "Each letter is replaced by the letter a fixed number of positions later in the alphabet, wrapping around from Z back to A. With a shift of 3, A becomes D, B becomes E and Z becomes C. Decryption shifts back by the same number."
  - q: "What is ROT13?"
    a: "ROT13 is the Caesar cipher with a shift of 13. Because the alphabet has 26 letters, applying it twice returns the original text, so the same operation encrypts and decrypts. It was used on forums to hide spoilers and punchlines, never for security."
  - q: "Is the Caesar cipher secure?"
    a: "No. There are only 25 useful keys, so anyone can try them all in seconds by hand. Letter-frequency analysis breaks it even faster: in English the most common letter in the ciphertext is very likely an encrypted E. Use it for puzzles and teaching only."
  - q: "What happens to numbers, spaces and accented letters?"
    a: "They are kept unchanged. The tool shifts only the 26 basic Latin letters A–Z and a–z and preserves upper and lower case. Digits, punctuation, spaces and letters such as é or ñ pass through as they are."
  - q: "How do I decode a Caesar cipher without the key?"
    a: "Brute force: decrypt with shifts 1 to 25 and look for the one that produces readable text. For longer messages, count the letters: the most frequent one usually stands for E (or A in Italian, Spanish and Portuguese), and the distance between them is the shift."
  - q: "Is my text sent anywhere?"
    a: "No. The shift is computed by a few lines of JavaScript in this page and nothing is uploaded."
---

## How it works

The tool walks through your text one character at a time. For each character it looks at the character code:

- uppercase letters `A–Z` (codes 65–90) are shifted within the uppercase alphabet;
- lowercase letters `a–z` (codes 97–122) are shifted within the lowercase alphabet;
- everything else (digits, spaces, punctuation, accented and non-Latin letters) is copied unchanged.

The shift is modular arithmetic on the letter's position *p* (0 for A, 25 for Z) and the key *k*:

**encrypted = (p + k) mod 26**, and decryption uses −k.

Because JavaScript's `%` can return negative numbers, the code computes `((p + k) % 26 + 26) % 26`, which keeps the result between 0 and 25 for both directions. The position is then turned back into a character with the original case.

| Plain | Shift 3 | Shift 13 (ROT13) |
|---|---|---|
| `HELLO` | `KHOOR` | `URYYB` |
| `Attack at dawn` | `Dwwdfn dw gdzq` | `Nggnpx ng qnja` |
| `Zebra` | `Cheud` | `Mroen` |

### Why it is so easy to break

A Caesar cipher has a key space of 25. A computer, or a patient person, tries every key in moments. And because each letter always maps to the same letter, the ciphertext keeps the statistical fingerprint of the language: the most common symbol in an English ciphertext is almost always E shifted by the key. These two weaknesses, tiny key space and preserved frequencies, are exactly what modern ciphers such as AES are designed to avoid.

## Use cases

- **CTF challenges and puzzles.** Caesar and ROT13 appear constantly in beginner capture-the-flag tasks, escape rooms and geocaching.
- **Teaching cryptography.** Show students encryption, keys and brute force with something they can do on paper, then explain why it fails.
- **Hiding spoilers.** ROT13 still hides a punchline or a solution from accidental reading.
- **Programming exercises.** Compare your own implementation with this one; the modular arithmetic and case handling are the usual stumbling blocks.
- **Historical curiosity.** Encode a message the way Roman generals did, with a shift of 3.
