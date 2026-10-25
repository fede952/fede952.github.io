---
title: "Merge & Split PDF Online, Private and Free"
description: "Merge PDF files, split them by pages or ranges, reorder, rotate and remove pages in your browser. Your PDFs are never uploaded. Free, no sign-up."
intro: "**Merge PDF** files into one, **split a PDF** into single pages or page ranges, and reorder, rotate or delete pages on the way — with page thumbnails you can drag. Everything happens in this browser tab: contracts, payslips and scans never leave your device."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["merge pdf", "split pdf", "combine pdf files", "reorder pdf pages", "split pdf online", "merge pdf without uploading", "extract pages from pdf", "rotate pdf pages"]
tags: ["pdf", "privacy", "documents", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/pdf-merge-split/"
tool_title: "PDF merge, split and page organizer"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Drop one or more PDF files onto the box, or click it to choose them. Every page appears as a numbered thumbnail, in file order."
  - "Arrange the pages: drag a thumbnail to a new position, or use the **←** and **→** buttons (handy on phones). **⟳** rotates a page by 90°, **✕** leaves it out of the result."
  - "To combine everything, set the **File name** and press **Merge & download**: you get one PDF with the pages exactly as arranged."
  - "To split, choose **Every page as its own PDF**, or **By page ranges** and type groups such as `1-3, 4, 5-` (the numbers are the ones on the thumbnails; `5-` means page 5 to the end)."
  - "Press **Split & download (.zip)**. Each group becomes a PDF named after the first file (`report-part-1.pdf`…); with only one group you get the PDF directly."
faq:
  - q: "Are my PDFs uploaded anywhere?"
    a: "No. The files are read by the browser, previewed with pdf.js and rebuilt with pdf-lib, both running in this tab. The page downloads those libraries once and sends nothing back; you can watch the Network panel while you merge to confirm it."
  - q: "Does merging reduce quality?"
    a: "No. Pages are copied as they are — text stays text, images keep their original compression and fonts are carried over. Nothing is rasterised or re-compressed, so the result is as sharp as the originals."
  - q: "Can I merge password-protected PDFs?"
    a: "Not directly: an encrypted PDF can't be read without its password, and the tool says so instead of producing a broken file. Open it in a PDF reader, save a copy without the password, then add that copy."
  - q: "Are links, bookmarks and form fields kept?"
    a: "Page content, annotations and links on the pages are copied. The document outline (bookmarks) and interactive form logic belong to the whole original file and are not rebuilt in the merged one, so check forms after merging."
  - q: "How large can the files be?"
    a: "There is no fixed limit; it depends on your device's memory. Documents of a few hundred pages work fine on a computer. Thumbnails are rendered for every page, so very large files take longer to appear."
  - q: "What does rotating do to the file?"
    a: "It sets the page's rotation in the PDF (by 90° steps), which every reader respects. The content itself is not redrawn, so rotating is lossless and can be undone by rotating again."
  - q: "How do I extract just a few pages?"
    a: "Use **By page ranges** with a single group, for example `3-5`: you download a PDF that contains only pages 3, 4 and 5. Alternatively remove the pages you don't want with ✕ and merge."
---

## How it works

### Two libraries, both local

Reading a PDF and writing one are separate jobs, so the tool uses two open-source libraries, served from this site and loaded only when you add a file:

- **pdf.js** (Mozilla, Apache-2.0), the engine of Firefox's PDF viewer, renders a small thumbnail of each page in a background worker so the page stays responsive.
- **pdf-lib** (MIT) builds the output. For each page in your order it copies the page object from its source document — content streams, fonts, images and annotations — into a new document with `copyPages`, applies the rotation you chose, and saves.

Before anything else the tool checks that each file starts with `%PDF-`, so a renamed Word document or a corrupt download is reported with its name.

### Page order and ranges

The thumbnails are a single list across all files: merging writes them in that order, and the numbers you type for splitting refer to it too. Ranges are comma-separated groups; each group can be a single page (`4`), a span (`1-3`), an open end (`5-` to the last page) or an open start (`-3`). Every group becomes one PDF; several PDFs are packed into a ZIP with JSZip.

### What is not included

The new document gets fresh metadata from pdf-lib instead of the source titles and authors, and document-level features such as the bookmark outline and form scripts are not recreated. For everyday merging and splitting — invoices, scans, chapters, slides — that is exactly what you want.

## Use cases

- **Combine scans** of a multi-page contract or form into one file before emailing it.
- **Split a large PDF** — a textbook, a manual, a year of bank statements — into chapters or months.
- **Remove pages** that contain personal data before sharing a document.
- **Fix page order and orientation** of a document scanned upside down or out of sequence.
- **Assemble an application**: CV, cover letter and certificates in the order the employer asked for — without handing them to an online service you know nothing about.
