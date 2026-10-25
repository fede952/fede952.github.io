---
title: "Redact a Screenshot: Black Out Text Online"
description: "Black out emails, names, IBANs and other sensitive parts of a screenshot. Solid boxes burned into the pixels, metadata removed, all in your browser."
intro: "Paste a screenshot (Ctrl+V), drop an image or pick one, then **drag to cover** anything sensitive: email addresses, names, account numbers, faces, URLs. Redactions are **solid boxes burned into the pixels** — no layers to remove — and the exported PNG or JPEG carries **no metadata**. An optional helper can **suggest boxes** over emails, IBANs, card and phone numbers and IP addresses. Nothing is uploaded."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["redact screenshot", "black out text in image", "redact image online", "hide sensitive information in screenshot", "censor screenshot", "blur screenshot", "pixelate image online", "remove personal data from screenshot"]
tags: ["privacy", "images", "security", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/screenshot-redactor/"
tool_title: "Screenshot redactor"
tool_height: 1050
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write; clipboard-read"
howto:
  - "Paste a screenshot with **Ctrl+V** (⌘V on a Mac), drop an image on the box, or press **Choose an image**."
  - "Keep **Solid box** selected (black by default; pick another **Colour** if you like) and drag over each area to hide. On a phone, drag with one finger and use **Move** to scroll a zoomed image."
  - "Optional: press **Suggest areas** to find emails, IBANs, card numbers, phone numbers and IP addresses with on-device text recognition. Untick any suggestion you want to keep, then **Cover** the rest."
  - "Use **Undo** / **Redo** (Ctrl+Z / Ctrl+Y) and the zoom buttons to check the edges of each box."
  - "Choose **PNG** (sharp text) or **JPEG** (smaller photos) and press **Download redacted image**, or **Copy image** to paste it straight into a chat or ticket."
faq:
  - q: "Is my image uploaded anywhere?"
    a: "No. The image is decoded, edited and exported inside your browser. The optional text recognition also runs on your device; the first time, it downloads its recognition files (about 10 MB) from this website, never from a third party, and the image itself is not sent anywhere."
  - q: "Why is a solid box safer than blur or pixelation?"
    a: "A solid box replaces the pixels with one colour, so nothing of the original survives. Blur and pixelation keep a reduced version of the original pixels. For short or predictable text — numbers, card digits, names in a known font — that is sometimes enough to reconstruct or guess it, for example by blurring or pixelating candidate texts the same way and comparing the results. Use them only for things that merely need to look less prominent."
  - q: "Can the redaction be removed from the downloaded file?"
    a: "No. The export is a new image drawn from the edited pixels: there are no layers, no hidden original and no editing history in the file. That is the difference from covering text with a shape in a document or a PDF, where the text underneath can often still be selected."
  - q: "Does it remove EXIF and GPS data?"
    a: "Yes. The exported PNG or JPEG is encoded fresh by the browser and contains no metadata: no camera model, no date, no GPS position. Photo orientation is applied to the pixels first, so the image still looks the right way round."
  - q: "What does the automatic suggestion find?"
    a: "Email addresses, IBANs (checked with their mod-97 checksum), payment card numbers (checked with the Luhn algorithm), phone numbers, and IPv4 and IPv6 addresses. It works on printed screen text in Latin script. It does not detect names, faces, addresses or handwriting, so always look over the image yourself before sharing it."
  - q: "Which image formats can I open?"
    a: "Anything your browser can display: PNG, JPEG, WebP, GIF (first frame), and usually AVIF and BMP. HEIC photos from an iPhone need converting first, for example with the HEIC converter on this site."
---

## How it works

### Redactions are pixels, not layers

The image is decoded into a canvas at full resolution, with the photo's EXIF orientation applied. Every box you draw is kept as a rectangle, and a composite of the image plus all boxes is rebuilt from the original pixels each time you draw, undo or redo. When you export, that composite is encoded into a brand-new PNG or JPEG. The file contains only the final pixels: what is under a box no longer exists in it.

This is why redaction tools in document editors so often fail: a black rectangle drawn over text in a document or a PDF is a separate object, and the text underneath can still be selected or extracted. Here there is nothing underneath.

### Why blur and pixelation are offered with a warning

Pixelation replaces each block of pixels with its average colour; blur spreads every pixel over its neighbours. Both throw information away, but not all of it. With text, the shape of each letter still influences the result, and the number of possible originals is often small: a card number has only ten possible digits per position, and screenshots use a handful of known fonts. Someone can render candidate texts in the same font, pixelate or blur them the same way and keep the one that matches. Published tools and research have shown this working on pixelated passwords and numbers. A solid box leaves nothing to compare, so it is the default and the only mode recommended for anything secret.

### The optional suggestions

Text detection uses Tesseract, an open-source OCR engine, compiled to WebAssembly and served from this site. It loads only when you press **Suggest areas**. The recognised words are checked against patterns for emails, IBANs, card numbers, phone numbers and IP addresses; IBANs and card numbers must also pass their checksums, which keeps false alarms down. Each match becomes a dashed suggestion box that you can accept or reject.

## Use cases

- **Bug reports and support tickets** — share a screenshot of an error without your email address, account ID or API key.
- **Social media and forums** — post a conversation or receipt with names, phone numbers and order numbers covered.
- **Documentation and tutorials** — hide internal URLs, IP addresses and customer data in screenshots of admin panels.
- **Expense reports** — send a photo of a receipt or bank transfer with the account number blacked out.
- **Security work** — include evidence in a report without leaking the credentials or personal data it contains.
