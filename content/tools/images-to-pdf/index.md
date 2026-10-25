---
title: "JPG to PDF: Convert Images to PDF Free"
description: "Combine JPG, PNG and WebP images into one PDF in your browser: reorder, rotate, choose A4, Letter or image size and margins. No upload, EXIF removed."
intro: "Turn photos, scans and screenshots into a single **PDF**: drop **JPG, PNG, WebP or GIF** images, put them in order, rotate any that are sideways, pick **A4, US Letter or the image's own size** and a margin, and download. The images are processed in this tab and their EXIF and GPS data never end up in the PDF."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["jpg to pdf", "image to pdf", "png to pdf", "convert images to pdf", "photos to pdf", "combine images into pdf", "jpg to pdf without upload", "webp to pdf"]
tags: ["pdf", "images", "privacy", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/images-to-pdf/"
tool_title: "Images to PDF converter"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Drop your images onto the box, or click it to choose them. Each image becomes one page; add more at any time."
  - "Put the pages in order by dragging the thumbnails or with **←** and **→**. **⟳** rotates an image by 90°, **✕** removes it."
  - "Choose the **Page size**: **A4**, **US Letter**, or **Same as the image** for pages that match each picture exactly."
  - "With A4 or Letter, **Automatic (per image)** orientation puts wide images on landscape pages and tall ones on portrait pages; you can force **Portrait** or **Landscape**. Pick a **Margin** (none, 1 cm or 2 cm)."
  - "Set the **File name** and press **Create PDF & download**."
faq:
  - q: "Are my images uploaded?"
    a: "No. The images are decoded by the browser, drawn on a canvas and placed into a PDF by pdf-lib, all inside this tab. Nothing is sent to a server, which matters for ID cards, receipts and medical documents."
  - q: "Does the PDF keep the location or camera data of my photos?"
    a: "No. Every image is redrawn on a canvas before it is embedded, and a canvas carries no metadata, so EXIF fields such as GPS position, date and camera model are not in the PDF. The PDF itself only gets basic technical metadata from the library."
  - q: "Why are my phone photos the right way up?"
    a: "Phones often save photos sideways and record the correct rotation in an EXIF tag. The tool reads the image with that orientation applied before drawing it, so the page looks like the photo in your gallery. Use ⟳ if a scan is still rotated."
  - q: "Will the images lose quality?"
    a: "Photos are re-encoded as high-quality JPEG (92%), which is visually identical for prints and documents. PNG, WebP and GIF images are stored losslessly as PNG, keeping sharp text and transparent areas."
  - q: "How big will the PDF be?"
    a: "Roughly the size of the images you add. Very large photos make large PDFs; if the file must stay small for an upload form, compress the photos first, for example with an image compressor, then convert."
  - q: "Can I convert HEIC photos from an iPhone?"
    a: "Most browsers cannot read HEIC directly. Convert them to JPG first with the HEIC converter on this site — also offline in your browser — then add the JPGs here."
  - q: "What does \"Same as the image\" mean?"
    a: "The page is sized to the picture at 96 pixels per inch, plus the margin. It is the best choice for screenshots and drawings that should not be scaled onto a paper format."
---

## How it works

### From image to page

For each image the tool:

1. Decodes it with `createImageBitmap(file, { imageOrientation: 'from-image' })`, so the EXIF orientation of phone photos is honoured.
2. Draws it on a `<canvas>`, applying your rotation, and encodes it again: as **JPEG at 92% quality** for JPG photos, or as **PNG** for PNG, WebP and GIF sources so transparency and crisp edges survive. GIFs contribute their first frame.
3. Embeds the result in the PDF with **pdf-lib** (`embedJpg` / `embedPng`).

### Page layout

A4 is 595 × 842 points and US Letter 612 × 792 points (1 point = 1/72 inch). The image is scaled to fit inside the page minus the margin on every side, keeping its aspect ratio, and centred. With automatic orientation the page is turned to landscape whenever the image is wider than it is tall. With **Same as the image**, a page is the image's size at 96 DPI — a 1920 × 1080 screenshot gives a 1440 × 810 point page — plus the margin.

### Libraries

pdf-lib (MIT) is loaded from this site only when you create the PDF; the thumbnail grid uses the browser's own image decoding. Nothing is requested from third-party servers.

## Use cases

- **Send scans of paper documents** — receipts, contracts, homework — as one PDF that any office can open.
- **Upload ID documents or payslips** to a form that only accepts PDF, without passing them through an online converter first.
- **Make a portfolio or a photo booklet** from JPGs in the order you choose.
- **Archive screenshots** of a configuration, an error or a conversation as a single dated file.
- **Prepare print-ready pages** on A4 or Letter with even margins.
