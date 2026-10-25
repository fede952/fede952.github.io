---
title: "Remove EXIF Data & GPS Location from Photos"
description: "See the hidden EXIF metadata in a photo (GPS position, camera, date) and download a clean copy without it. Works offline in your browser, no upload."
intro: "**EXIF Cleaner** shows the metadata hidden inside a photo (GPS coordinates, camera model, capture date, software) and gives you a clean copy with all of it removed. The image never leaves your device."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["remove exif data", "exif remover", "remove gps from photo", "metadata remover", "strip exif online", "photo metadata viewer", "remove location from picture", "exif viewer"]
tags: ["privacy", "osint", "images", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/exif-cleaner/"
tool_title: "EXIF Cleaner metadata viewer and remover"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Drag a photo onto the drop zone or click to choose one. JPEG works best; PNG and WebP are accepted too."
  - "Read the **Metadata Found** table: camera make and model, capture date, software, exposure, ISO, focal length, orientation, dimensions, copyright, author and GPS coordinates."
  - "If a red warning appears, the photo contains a **GPS position**. The decimal coordinates shown are the place where the picture was taken, accurate to a few metres."
  - "Click **Purge Metadata & Download**. The image is redrawn without any metadata and saved in the same format."
  - "Click **Download Clean Image** to save `yourfile-clean.jpg` (or .png/.webp), and share that copy instead of the original."
faq:
  - q: "What is EXIF data?"
    a: "EXIF (Exchangeable Image File Format) is a block of metadata that cameras and phones write into every photo: device make and model, lens, exposure settings, date and time, the software used to edit it, and often the GPS coordinates of where it was taken. It is invisible when you view the picture but trivial to read with tools like this one."
  - q: "Do social networks remove EXIF automatically?"
    a: "The big platforms such as Facebook, Instagram, X and WhatsApp strip most metadata from the images they publish. Email attachments, cloud-drive links, forums, marketplaces, dating sites and many messaging apps sending \"as file\" or \"original quality\" do not. If you are not sure, clean the photo first."
  - q: "Is my photo uploaded to remove the metadata?"
    a: "No. Reading the metadata and creating the clean copy both happen in JavaScript inside this page. You can disconnect from the internet after the page loads and the tool keeps working, which also makes it suitable for sensitive photos."
  - q: "Does cleaning reduce image quality?"
    a: "PNG output is lossless. JPEG and WebP are re-encoded at quality 95, which is visually indistinguishable from the original for nearly all photos; the file size may change a little. The resolution stays exactly the same."
  - q: "Why does my PNG or WebP show no metadata?"
    a: "The viewer uses exif-js, which reads the EXIF block that JPEG files carry. PNG and WebP store metadata differently and are rarely tagged with GPS, so the table may stay empty for them. The clean copy is still re-encoded from pixels, so any metadata chunks they contain are dropped as well."
  - q: "Will the clean photo still display the right way up?"
    a: "Yes. Phones often save photos sideways and rely on the EXIF Orientation tag to rotate them. The browser applies that rotation when it draws the image, so the clean copy has the correct orientation baked into its pixels and no longer needs the tag."
  - q: "Can removed metadata be recovered from the clean copy?"
    a: "No. The clean file is a new image built only from pixels; the original metadata block is never copied into it. Keep your original if you want the date and location for your own photo library."
---

## How it works

### Reading the metadata

When you drop a file, the page reads it locally with `FileReader` and passes it to **exif-js** (v2.3.0, self-hosted). The library walks the JPEG's APP1 segment and decodes the TIFF-structured EXIF directories: the main image directory (camera make, model, software, orientation, copyright, artist), the Exif sub-directory (exposure time, f-number, ISO, focal length, flash, pixel dimensions, colour space) and the GPS directory.

GPS coordinates are stored as degrees, minutes and seconds plus a hemisphere reference (N/S, E/W). The tool converts them to decimal degrees, `degrees + minutes/60 + seconds/3600`, negative for south and west, and shows them with six decimal places, roughly 10 cm of precision. If any GPS position is present, the red warning is displayed.

### Creating the clean copy

Metadata is not edited out byte by byte: the tool throws the whole container away.

1. The image is decoded by the browser into raw pixels.
2. Those pixels are drawn at full resolution onto an HTML `<canvas>`. While drawing, the browser applies the EXIF orientation, so the result is upright.
3. The canvas is encoded into a brand-new file with `canvas.toBlob()`: **JPEG at quality 0.95** for JPEG input, **WebP at 0.95** for WebP input and **PNG** for everything else.

A canvas only contains pixels, so the new file carries **no EXIF, no GPS, no XMP or IPTC tags, no embedded thumbnail** (old thumbnails sometimes still show the *uncropped* original) and no colour profile. Images are output in sRGB, so wide-gamut photos can look very slightly less saturated.

You can verify the result yourself by dropping the downloaded `-clean` file back into the tool: the table will be empty and no GPS warning will appear.

### What it does not touch

The clean copy removes *metadata*, not what is visible in the picture. A street sign, a reflection in a window, a car number plate or a recognisable landmark can still reveal where a photo was taken. Crop or blur those before sharing.

## Use cases

- **Selling things online.** Photos of items taken at home can carry your home's GPS coordinates. Clean them before uploading to a marketplace or classified ad.
- **Sending pictures to people you don't know well**, such as a landlord, a dating match or a buyer, without handing over your address and phone model.
- **Journalism and activism.** Strip location and device details from images that could identify a source.
- **Checking what you are about to share.** Open a photo and see exactly what it reveals; it is often an eye-opener the first time you see your street on a map.
- **OSINT practice.** Investigators use EXIF as a lead. Use the viewer on sample images to learn what can be extracted, and why cleaning matters.
