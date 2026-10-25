---
title: "Hide Text in an Image: LSB Steganography"
description: "Hide a secret message inside an image with LSB steganography and reveal it again. Exports a lossless PNG; runs entirely in your browser, nothing uploaded."
intro: "**Steganography Lab** hides a text message inside the pixels of an image and reads it back later. The picture looks unchanged, because each colour value moves by at most 1 out of 255. Everything happens in your browser: the image and the message never leave your device."
date: 2026-02-05
lastmod: 2026-10-24
reviewed: false
keywords: ["steganography tool", "hide text in image", "lsb steganography", "hide message in picture", "decode hidden message image", "steganography online", "png steganography", "secret message in image"]
tags: ["privacy", "security", "images", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/steganography/"
tool_title: "Steganography Lab"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "On the **Hide Message** tab, drop an image or click to choose one (JPG, PNG, WebP or GIF). The tool shows its size and how many bytes it can hold."
  - "Type or paste your message. The capacity bar fills as you type and turns orange, then red, as you approach the limit."
  - "Click **Encode & Download PNG**. A file named `stego_<timestamp>.png` is saved. It looks identical to the original."
  - "Send that PNG **as a file** (email attachment, cloud link, \"send as document\"), not as a photo that a chat app will recompress."
  - "To read it, open the **Reveal Message** tab, load the PNG and click **Decode Hidden Message**. Use **Copy Text** to grab the result."
faq:
  - q: "Is the hidden message encrypted?"
    a: "No. Steganography hides that a message exists; it does not protect its content. Anyone who loads the PNG into this tool, or knows the scheme, can read it. For anything sensitive, encrypt the text first (for example with a password manager's secure note or a tool like age or GPG) and hide the ciphertext."
  - q: "Why does the output have to be PNG?"
    a: "PNG is lossless, so every pixel value is stored exactly as written. JPEG and lossy WebP re-quantise colours on save, which scrambles the lowest bits where the message lives. That is also why the Reveal tab only accepts PNG files."
  - q: "My message disappeared after sending the image. Why?"
    a: "Most chat apps and social networks resize and recompress photos, and screenshots re-render the pixels. Any of these destroys the hidden bits. Send the PNG as a file or document so it arrives byte-for-byte intact."
  - q: "How much text can an image hold?"
    a: "Three bits per fully opaque pixel, minus a 19-byte header and terminator. A 1920×1080 photo holds about 777,000 bytes. The counter is in UTF-8 bytes: plain English uses one byte per character, accented letters two, many emoji four."
  - q: "Can steganalysis tools detect it?"
    a: "Yes. Sequential LSB embedding is the textbook case that statistical tests such as chi-square and RS analysis are built to spot, especially when a large share of the capacity is used. Treat this as a learning and casual-privacy tool, not covert communication against a capable adversary."
  - q: "Does it work with transparent PNGs?"
    a: "Yes. Only fully opaque pixels carry data, because browsers store semi-transparent pixels in premultiplied form and their low bits would not survive. Transparent areas are left untouched and simply reduce the capacity."
  - q: "Is my image uploaded anywhere?"
    a: "No. The file is read with the FileReader API and processed on a canvas in your browser tab. There is no server component; you can load the page, go offline and it still works."
---

## How it works

The technique is **least-significant-bit (LSB) substitution**, the classic form of image steganography (there is a longer explanation in the [Steganography 101 guide](/learn/guides/steganography-101-hidden-messages/)).

**1. Build the payload.** Your text is encoded as UTF-8 and wrapped like this:

```
STEGO_V1::<your message>\0\0\0END\0\0\0
```

The `STEGO_V1::` prefix lets the decoder tell straight away whether an image carries a message. The null-padded `END` marker tells it where the message stops.

**2. Read the pixels.** The image is drawn onto an HTML canvas at its natural size, with smoothing disabled, and `getImageData()` returns every pixel as red, green, blue and alpha bytes.

**3. Write one bit per colour channel.** The payload bits, most significant first, go one by one into the lowest bit of the R, G and B bytes of each fully opaque pixel, in reading order from the top-left. Each byte becomes `(value & 0xFE) | bit`, so a channel changes by 0 or 1 and the difference is invisible. Alpha is never touched, and pixels that are not fully opaque are skipped, because the canvas premultiplies their colours and the low bits would be lost.

**4. Export losslessly.** The modified canvas is saved with `toBlob('image/png')`. A side effect is that the output carries **no EXIF metadata** (camera, GPS, date), since the canvas only knows about pixels.

**5. Decode.** The Reveal tab does the reverse: it collects the low bits of the same channels, rebuilds bytes and checks the first ten against `STEGO_V1::`. It stops early if they don't match, so a large clean photo is rejected almost instantly. Otherwise it reads until the end marker and decodes the bytes back to text.

| Image | Opaque pixels | Capacity |
|---|---|---|
| 800×600 | 480,000 | ≈ 179,981 bytes |
| 1920×1080 | 2,073,600 | ≈ 777,581 bytes |
| 4000×3000 | 12,000,000 | ≈ 4.5 MB |

The more of the capacity you fill, the easier the image is to flag with statistical steganalysis. A short message in a big, noisy photo is much harder to spot than a full one in a flat graphic.

## Use cases

- **Learning and teaching.** See exactly what LSB embedding does, then try to break it: recompress the PNG as JPEG and watch the message vanish.
- **CTF practice.** Steganography challenges often hide flags in LSBs. Encoding your own samples makes the pattern easy to recognise in tools like `zsteg` or StegSolve.
- **Watermarking your own images.** Embed a note such as an owner name and date in a PNG you share as a file. It won't survive editing, but it does prove a copy is untouched.
- **A playful secret.** Hide a message in a holiday photo for a friend who knows to look.
- **Carrying already-encrypted text.** Paste ciphertext (for example ASCII-armoured GPG output) to get both confidentiality and a low profile.

For the opposite job, removing data hidden in a photo's metadata rather than its pixels, use the [EXIF Cleaner](/tools/exif-cleaner/).
