---
title: "HEIC to JPG Converter: Batch, Private, Free"
description: "Convert iPhone HEIC photos to JPG or PNG in your browser: batch, quality control, optional EXIF/GPS removal, ZIP download. No upload, no account."
intro: "Turn iPhone **HEIC photos into JPG or PNG** without uploading them anywhere: drop one or a hundred files, pick the format and quality, choose whether to remove the EXIF metadata and GPS location, and download each file or a single ZIP. The decoder runs inside this browser tab."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["heic to jpg", "heic to jpg converter", "convert heic to jpg", "heic to png", "iphone photo to jpg", "heic converter online", "batch heic to jpg", "open heic file"]
tags: ["images", "privacy", "converter", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/heic-converter/"
tool_title: "HEIC to JPG and PNG converter"
tool_height: 720
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Drop your `.heic` or `.heif` photos onto the box, or click it to choose them. You can add several at once, and add more later."
  - "The first time, the page loads its HEIC decoder (about 1.5 MB, once per visit). Each photo is then decoded and converted in turn; a thumbnail and the new size appear next to its name."
  - "Pick **JPG** (smaller files, adjustable **JPG quality**) or **PNG** (lossless, larger). Changing an option re-converts the photos already in the list."
  - "Leave **Remove metadata (EXIF, GPS location)** ticked to produce clean files, or untick it to keep the camera data and location in the JPG."
  - "Press **Download** on a photo, or **Download all (.zip)** to save every converted file in one archive."
faq:
  - q: "Are my photos uploaded to a server?"
    a: "No. The files are read with the browser's File API and decoded by a WebAssembly build of libheif that runs in this tab. The only network requests are for the decoder itself; your photos never leave the device. You can check it in the browser's Network panel while converting."
  - q: "Why do iPhones save photos as HEIC?"
    a: "HEIC stores an image compressed with HEVC (H.265) inside a HEIF container. At similar quality the files are roughly half the size of JPEG, which is why iOS uses it by default. Many Windows apps, websites and older devices still cannot open it, hence the need to convert."
  - q: "Will I lose quality?"
    a: "Converting to JPEG re-compresses the image. At the default quality of 85 the difference is very hard to see while the file stays small; set 95–100 if you plan to edit the photo. PNG is lossless but often three to five times larger than the original HEIC."
  - q: "What does \"Remove metadata\" remove?"
    a: "Everything except the pixels: EXIF camera data, the date and time, and above all the GPS position, which can reveal where you live or work. With the option off, the converter copies the original EXIF block into the JPEG and resets its orientation tag, because the decoder has already rotated the image."
  - q: "My HEIC has several images (Live Photo, burst). Which one is converted?"
    a: "The primary image, the one the Photos app shows. The motion part of a Live Photo is a separate video file and is not included."
  - q: "Is there a size or number limit?"
    a: "Only your device's memory. Each photo is decoded into raw pixels (a 12-megapixel photo needs about 48 MB while it is being converted), so very large batches are faster on a computer than on an older phone."
  - q: "Can I convert HEIC to PNG with transparency?"
    a: "Photos from phone cameras have no transparency. If a HEIF image does carry an alpha channel, PNG keeps it; JPEG has no transparency and fills it with black."
---

## How it works

### Decoding without a server

Browsers other than Safari cannot open HEIC on their own, because the format wraps **HEVC**-compressed images in a **HEIF** container (ISO/IEC 23008-12). This page bundles **libheif** — the reference open-source HEIF library, compiled to WebAssembly by the libheif-js project — and loads it only when you drop the first file, so the page itself stays light.

For each file the converter:

1. Reads the bytes with the File API and checks the `ftyp` box for a HEIF brand (`heic`, `heix`, `mif1`…), so a renamed JPEG is reported instead of crashing the decoder.
2. Decodes the primary image with libheif into an RGBA bitmap. Rotation and mirroring stored in the file (`irot`, `imir`) are applied at this step.
3. Draws the bitmap on a `<canvas>` and encodes it with `canvas.toBlob()` as JPEG at the chosen quality, or as PNG.

### Metadata

A canvas never carries metadata, so a converted file is clean by default. When you choose to keep it, the converter parses the HEIF container itself — the `meta` box, the item list (`iinf`) and the item locations (`iloc`) — to find the item of type `Exif`, and inserts that block into the JPEG as a standard **APP1** segment. The `Orientation` tag is set to 1 (normal) in the copy, otherwise viewers would rotate a photo that is already upright. PNG output is always written without metadata.

### ZIP download

For more than one file, **Download all** loads a small ZIP library (JSZip), adds every converted file and saves a single archive. Duplicate names get a numeric suffix (`IMG_0001-2.jpg`).

## Use cases

- **Sending iPhone photos to Windows users or to forms** that only accept JPG or PNG: job applications, insurance claims, government portals.
- **Posting on the web without leaking your location.** Convert and strip EXIF in one step before uploading to a marketplace or forum.
- **Archiving.** Convert a folder of holiday photos to JPG for a family member's old laptop or a digital photo frame.
- **Designers and developers** who receive HEIC screenshots or mock-ups and need PNG for documentation.
- **Privacy-sensitive images** — documents, ID cards, medical photos — that should not pass through an online converter you cannot inspect.
