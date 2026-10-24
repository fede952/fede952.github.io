# Vendored third-party libraries

Self-hosted copies of the browser libraries the site and its tools use, so no
page loads code from a third-party CDN (privacy: no visitor IP is sent to the
CDN; reliability: no external dependency). Fetched from jsDelivr at the exact
pinned version in the folder name. Update by re-downloading the same path
with a new version and changing the `src` that points here.

| Library | Version | Licence | Used by |
|---|---|---|---|
| medium-zoom | 1.1.0 | MIT | image zoom on article pages (extend_footer.html) |
| fuse.js | 7.0.0 | Apache-2.0 | site search palette (extend_footer.html) |
| exif-js | 2.3.0 | MIT | tools/exif-cleaner |
| chart.js | 4.4.7 | MIT | tools/freelance-calculator |
| browser-image-compression | 2.0.2 | MIT | tools/pixel-shrink (also loaded by its Web Worker via `libURL`) |
| qrcode-generator | 1.4.4 | MIT | tools/qr-generator |
