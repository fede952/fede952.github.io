---
title: "Free QR Code Generator (No Sign-up, PNG)"
description: "Create QR codes for links or text, pick colours and error correction, download a print-ready PNG. Static codes that never expire, made in your browser."
intro: "Type a link or any text and get a **static QR code** you can download as a sharp, print-ready PNG. The code is generated in your browser, contains your data directly and never expires. The **Wi-Fi** and **Contact** modes build codes that join a network or save a contact card in one scan."
date: 2026-02-03
lastmod: 2026-10-25
reviewed: false
keywords: ["qr code generator", "free qr code generator", "create qr code", "qr code for link", "qr code png", "qr code generator no sign up", "static qr code", "qr code that never expires"]
tags: ["qr-code", "utilities", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/qr-generator/"
tool_title: "QuickLinker QR code generator"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Paste a URL (including `https://`) or type any text into the input box. Accented letters, emoji and non-Latin scripts work too."
  - "For a network, open **Wi-Fi** and enter the network name, password and security; for a business card, open **Contact** and fill in the fields you want. The exact text that will be encoded appears under **Encoded text**."
  - "Optionally pick a **Foreground** and **Background** colour. Keep the foreground clearly darker than the background, or many phone cameras will not read it."
  - "Choose the **Error Correction** level: **M (15%)** is the default; use **Q** or **H** if the code will be printed small, outdoors, or with a logo on top."
  - "Press **Generate QR** and check the preview by pointing your phone's camera at the screen."
  - "Press **Download .PNG** to save a ~1200 px image with the required white margin, ready for print or slides."
faq:
  - q: "Do these QR codes expire?"
    a: "No. They are static QR codes: your link or text is encoded in the pattern itself. Nothing points to a server of ours, so there is nothing to switch off, no subscription and no scan limit. The flip side is that you cannot change the destination later; if the URL changes, generate a new code."
  - q: "Is this QR code generator really free?"
    a: "Yes, with no account, watermark or limit on the number of codes. The page is funded by ads shown around the tool, not by locking features."
  - q: "What is the difference between a static and a dynamic QR code?"
    a: "A dynamic QR code contains a short link to the provider's server, which redirects to your real URL. That lets them count scans and change the destination, but the code stops working if you stop paying or the service shuts down, and every scan passes through their servers. A static code, like the ones made here, goes straight to your URL."
  - q: "Which error correction level should I choose?"
    a: "L recovers about 7% of damaged modules, M 15%, Q 25% and H 30%. Higher levels make the code denser for the same content. M is right for screens and clean prints; choose Q or H for small stickers, rough surfaces, or if you plan to place a logo in the middle."
  - q: "How much text fits in a QR code?"
    a: "The generator automatically picks the smallest of the 40 QR versions that fits. At level M a version 40 code holds about 2,300 bytes of text, but codes that large are hard to scan with a phone. For links, shorter is better: a 30–60 character URL gives a clean, easily readable code."
  - q: "Why won't my coloured QR code scan?"
    a: "Scanners look for dark modules on a light background with enough contrast. Light-on-dark (inverted) colours, low-contrast pairs such as yellow on white, or a background image behind the code are the usual causes. Black or a dark colour on white is the safest choice."
  - q: "Is the data I type sent anywhere?"
    a: "No. The QR code is computed by a JavaScript library running in this page and drawn onto a canvas. Nothing is uploaded, which matters if you are encoding a Wi-Fi password, an internal URL or a private note."
  - q: "How does a Wi-Fi QR code work?"
    a: "It contains a short text in the `WIFI:` format that Android and iPhone cameras understand, for example `WIFI:T:WPA;S:Home;P:secret;;`. Scanning it offers to join the network without typing the password. Special characters in the name or password (`\\ ; , : \"`) are escaped with a backslash, as the format requires, so a password such as `p;ss:word` still works. The password is readable by anyone who scans the code, so only print it where guests are welcome."
  - q: "Which contact format is used, and what can it hold?"
    a: "A vCard 3.0, the version phone cameras import most reliably: name, organisation, job title, mobile phone, email, website, address and a note. Empty fields are left out to keep the code small. Commas, semicolons and line breaks are escaped as the vCard standard requires. A full card makes a dense code, so leave out what you do not need and keep the error correction at L or M."
---

## How it works

The tool uses the open-source **qrcode-generator** library by Kazuhiko Arase (v1.4.4, self-hosted here) and draws the result on an HTML canvas.

1. **Encoding.** Your text is converted to bytes as **UTF-8** and stored in QR *byte mode*, so `é`, `ß`, `ç`, `€` and emoji come out exactly as typed when a phone reads them. (The library's default would keep only one byte per character and garble anything outside basic Latin, so the page switches it to UTF-8 explicitly.)
2. **Version selection.** The library chooses the smallest **QR version**, from version 1 (21 × 21 modules) up to version 40 (177 × 177), that can hold your data at the chosen error-correction level.
3. **Error correction.** QR codes add **Reed–Solomon** error-correction codewords so a reader can rebuild missing or dirty parts: level **L** restores ~7%, **M** ~15%, **Q** ~25% and **H** ~30% of the codewords.
4. **Rendering.** Every dark module is drawn as a square in your foreground colour. Around the symbol the tool leaves a **4-module quiet zone** in the background colour, the margin the QR standard (ISO/IEC 18004) requires. Without it, scanners struggle as soon as the code sits on a coloured page.
5. **Export.** The on-screen preview is about 300 px wide. When you download, the code is drawn again at roughly **1200 px**, with each module a whole number of pixels so the edges stay crisp, and saved as `qrcode.png`.

| Content | Typical length | Version at level M | Modules |
|---|---|---|---|
| Short URL | 25 characters | 2 | 25 × 25 |
| Normal URL with path | 60 characters | 4 | 33 × 33 |
| Long URL with tracking parameters | 150 characters | 8 | 49 × 49 |
| A paragraph of text | 500 characters | 17 | 85 × 85 |

The fewer modules, the larger each one is when printed and the easier the code is to scan from a distance, which is why removing tracking parameters from a URL often matters more than the error-correction level.

### Wi-Fi and contact codes

In **Wi-Fi** mode the tool writes `WIFI:T:<WPA|WEP|nopass>;S:<network>;P:<password>;H:true;;` (the `H` field only for hidden networks); `WPA` covers WPA, WPA2 and WPA3 Personal, because the phone negotiates the exact version. In **Contact** mode it writes a vCard 3.0 with CRLF line endings. Both payloads are tested by decoding the downloaded PNG and comparing the result character by character, including names and passwords full of `; , : " \`.

## Use cases

- **Print and packaging.** Put a QR code on flyers, business cards, menus or product labels that opens your site, a review page or a manual. A static code keeps working as long as the URL does.
- **Presentations and posters.** Let the audience open your slides, a survey or a repository without typing a long address.
- **Sharing text offline.** Encode a short note, a serial number or contact details that a phone can read without any network.
- **Testing your own apps.** Generate codes for deep links, staging URLs or OAuth callback testing without pasting internal addresses into a third-party service.
- **Security awareness.** "Quishing" (QR phishing) hides malicious links behind codes. Generating your own lets you show colleagues how easily a code can point anywhere, and why the URL preview on the phone deserves a look before tapping.
