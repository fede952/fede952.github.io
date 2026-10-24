---
title: "Compress Images Online: JPG, PNG, WebP"
description: "Shrink JPG, PNG and WebP images in your browser: set quality, target size and max width, convert to WebP. No upload, no sign-up, works offline once loaded."
intro: "**PixelShrink** compresses and converts images on your own device. Drop a photo, choose quality, a target file size or a maximum width, and download a smaller JPG, PNG or WebP. The image is never uploaded."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["compress image", "image compressor", "compress jpg", "compress png", "reduce image size", "convert to webp", "resize image online", "compress photo without upload"]
tags: ["images", "compression", "privacy", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/pixel-shrink/"
tool_title: "PixelShrink image compressor"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Drag an image onto the drop zone or click it to pick a file. PNG, JPEG, WebP and AVIF inputs are accepted; a preview shows the file size and dimensions."
  - "Choose the **output format**: keep the original, or convert to JPEG, PNG or WebP. WebP is usually the smallest for photos."
  - "Set **quality** (1–100, default 75), a **max size** in MB and a **max width** in pixels. The longest side is scaled down to that width, keeping the proportions."
  - "Click **Compress Image**. The before/after panel shows both sizes, both dimensions and the percentage saved."
  - "Click **Download Compressed Image** to save the result. If it is not smaller than the original, the tool tells you so: keep the original or try another format."
faq:
  - q: "Are my images uploaded to a server?"
    a: "No. The image is decoded, resized and re-encoded inside your browser, in a background Web Worker. Nothing is sent anywhere: once the page has loaded you can go offline and it still works. That also makes it safe for screenshots of documents, IDs or anything private."
  - q: "What quality setting should I use?"
    a: "For photos, 70–80 is the sweet spot: files shrink a lot and differences are hard to see at normal size. Go down to 50–60 for thumbnails or previews. Above 90 the file grows quickly for little visible gain."
  - q: "Should I convert to WebP?"
    a: "For the web, usually yes. WebP files are typically 25–35% smaller than JPEG at similar quality and every current browser displays them. Keep JPEG when the image is going to a system that only accepts JPG, such as some upload forms or print services."
  - q: "Why did my PNG get bigger?"
    a: "PNG is lossless, so a photograph saved as PNG is often larger than the JPEG it came from. PixelShrink reduces PNGs by limiting the colour palette, which works well for screenshots, logos and flat graphics and poorly for photos. For photos, choose WebP or JPEG instead."
  - q: "Can I compress an image to an exact size, like under 200 KB?"
    a: "Set **Max size** to 0.2 MB. If the first encode is larger, the library repeats the encode up to 10 times, lowering quality and dimensions a little each pass, and stops as soon as the file fits. Very large or detailed images may need a lower max width as well."
  - q: "Does compression remove EXIF data and GPS location?"
    a: "Yes. The image is redrawn on a canvas and encoded again, and metadata is not copied over, so EXIF fields such as camera model, date and GPS coordinates are dropped. If you only want to strip metadata without recompressing, use the EXIF Cleaner."
  - q: "Why is there no AVIF output?"
    a: "The output is produced by the browser's own image encoder, and most browsers can display AVIF but not create it from a canvas. PixelShrink tests this when it loads and shows the AVIF option only when your browser can genuinely encode it, rather than silently producing a PNG with an .avif name."
---

## How it works

PixelShrink is a thin interface over [browser-image-compression](https://github.com/Donaldcwl/browser-image-compression) (v2.0.2, self-hosted on this site). When you press Compress, the work moves to a **Web Worker**, so the page stays responsive even with a 20-megapixel photo.

1. **Decode.** The file is decoded into a bitmap with `createImageBitmap` (or an `<img>` element as a fallback), and EXIF orientation is applied so portrait photos are not rotated.
2. **Resize.** If the longest side is larger than *Max width*, the image is drawn onto a smaller canvas with the same aspect ratio. A 6000 × 4000 photo with a 2048 px limit becomes 2048 × 1365.
3. **Encode.** JPEG and WebP are encoded by the browser (`canvas.toBlob` / `OffscreenCanvas.convertToBlob`) with your quality setting as the encoder quality. PNG goes through **UPNG.js**, which quantises the image to a palette of at most 4096 × quality colours (3,072 colours at the default 75) before writing a lossless PNG, the trick that makes screenshots and UI graphics shrink by half or more.
4. **Fit the target size.** If the result is still larger than *Max size*, the encode is repeated up to **10 times**. Each pass multiplies quality by 0.95 (0.85 for PNG) and can scale the dimensions by 0.95, until the file fits or the passes run out.

The before/after panel compares the original file with the result, and the download is a local `blob:` URL named `yourfile-compressed.<format>`. Because the image is re-encoded from pixels, **metadata such as EXIF and GPS is not carried over**.

### Choosing a format

| Content | Best format | Why |
|---|---|---|
| Photos for a website or blog | WebP, quality 70–80 | Smallest files, universal browser support |
| Photos for email, forms, print | JPEG, quality 75–85 | Accepted everywhere |
| Screenshots, diagrams, logos | PNG or WebP | Sharp edges and flat colours compress well |
| Images with transparency | PNG or WebP | JPEG has no alpha channel |

**AVIF** is listed only when the browser can actually *encode* it from a canvas. Most browsers currently cannot, and PixelShrink checks this on load instead of guessing.

## Use cases

- **Faster web pages.** Large hero images are the most common cause of a poor Largest Contentful Paint score. Converting a 3 MB JPEG to a 2000 px WebP at quality 75 often lands under 300 KB.
- **Upload limits.** Government portals, job sites and support tickets often cap attachments at 1 or 2 MB. Set Max size and let the tool find the quality that fits.
- **Email and chat.** Send five holiday photos instead of one when each is a tenth of its original size.
- **Private documents.** Shrink a scan of an ID card or a contract without handing it to an online service you know nothing about.
- **App and game assets.** Batch-convert PNG sprites or screenshots to smaller files before committing them to a repository.
