# Batch 2 report — branch `batch2`

Tools batch 2 (shareable + security niche) and per-page share cards. One commit per phase; nothing pushed or merged. All tests ran against local builds; no test touched the live site.

## Phase 1 — Per-page share cards (Open Graph)

Every tool, game and learn page now has its own 1200×630 share card in each of its languages: 416 cards in all.

**How they're built.** I used Hugo's image pipeline rather than a Node pre-build step. CI already runs Hugo, and a browser would have to be installed on every run otherwise.
- **Static layers** are rendered once by `scripts/og-assets.mjs` (Playwright, from the design tokens) and committed:
  - `assets/og/bg.png`: flat `--bg`, accent bar, divider, raven mark and domain;
  - `assets/og/icons/<icon>.png`: a 160 px tile for each of the 44 icons in `data/tool_icons.yaml`.

  Rerun the script after adding an icon or changing the tokens.
- **`layouts/partials/og/card.html`** composes the icon tile, the localised category (`cat_*` / `type_*` i18n keys) and the localised title with `images.Overlay` and `images.Text`. It publishes the result at a stable path, `/og/<lang>/<page path>.png`.
- **Fonts:** `images.Text` needs TTF, and the site self-hosts only a variable-weight WOFF2. I made static Bold and Regular instances of that same JetBrains Mono (OFL) with fonttools; they're in `assets/og/fonts/` with the licence.
- **Title wrapping:** the font is monospaced, so titles are wrapped to an exact character budget. That's 60 px and 28 characters per line, falling back to 50/34 and 42/41 to stay within three lines, with "…" beyond that.
- **Build time:** a cold build (`--ignoreCache`) takes 9.7 s.

**Head tags.** The overridden `templates/opengraph.html` and `templates/twitter_cards.html` emit, per page and per language:
- `og:image` plus `og:image:width`, `og:image:height`, `og:image:type` and `og:image:alt`;
- `twitter:card=summary_large_image` and `twitter:image`.

The card takes precedence over a front-matter cover. Every other page keeps the default `og-card.png`. The WebApplication and TechArticle JSON-LD `image` now point at the card as well.

**Files.** The largest card is 51 KB, and none is over 120 KB. Hugo writes PNGs without metadata chunks, and the privacy guard passes with the new layers in the tree.

**Validator-style test.** A new `og` check in `tests/static-checks.mjs` parses the head of every built page:
- every `og:image` must resolve;
- tool and learn cards must be their own language's PNG, really 1200×630 (read from the IHDR chunk), matching the declared width and height, under 120 KB and free of text/EXIF/XMP chunks;
- `twitter:card` must be `summary_large_image`, with `twitter:image` equal to `og:image`.

Result: 1,521 pages with Open Graph tags, 416 per-page cards, 0 problems.

**Found and fixed on the way:** Penta Framework's cover had `relative: true` with a site-absolute path, so its `og:image` pointed nowhere, in all six languages. It's now `relative: false`.

## Phase 2 — Phishing Quiz (`/tools/phishing-quiz/`)

**Pool.** 32 scenarios, 20 phishing and 12 legitimate: 15 emails, 5 SMS, 4 login pages, 2 QR codes and 6 bare URLs, in `static/js/tools/phish/scenarios.mjs`.
- **Fiction, enforced by test:** every brand is invented (Velorabank, Parcelux, Nimbusdrive, Fluxpay, Streamora, Brightmail, Codehaven, Citypark, Trattoria Lume). Every host is reserved (`.example`, `.test`, `.invalid`, `example.com`) or in the 192.0.2.0/24 documentation range, and `tests/unit/phish.test.mjs` fails on anything else.
- **Real names removed while writing:** the tax-office scenario first named real agencies in the Italian and Spanish texts. Both now use generic wording.
- **Localised scenarios, not just UI:** the language-neutral module holds the types, domains and which elements carry flags. `phish/<lang>.mjs` holds every visible string and every red-flag explanation, in all 6 languages (EN reference; PT is Brazilian). The test checks every language has every scenario, field and explanation.

**Rounds.** Each round has 10 scenarios with 3–4 legitimate and at least 3 types (`phish/quiz.mjs`, tested over 200 seeds), so "everything is phishing" can't win.

**Feedback.** After each answer the deciding elements are outlined and numbered on the mockup in reading order:
- red for phishing flags: sender domain, lookalike or subdomain URLs, mismatched link target, urgency, attachment type, QR code, form fields;
- green for the signs of a genuine message.

Each flag has a one-line explanation, plus a verdict. Email links show their real target on hover or focus, as in a mail client, and QR codes reveal what they encode only after the answer.

**Result screen.**
- **Score and rank:** four bands.
- **Topics to review:** taken from the missed scenarios, linking to Link Hazmat, PassFort and others.
- **Share:** uses the Web Share API, with a clipboard fallback. The text carries only the score and a URL.

**Result-specific share cards.** A static site can't change Open Graph tags per `?score=`, because crawlers receive the same HTML for every query string. So `partials/quiz/score-pages.html` publishes 11 small pages per language at `/<lang>/tools/phishing-quiz/score/<n>/` (driven by front matter `share_scores` / `share_card_title`). Each has:
- its own generated card;
- `noindex`, and a canonical link to the quiz;
- a redirect to `…/phishing-quiz/?score=<n>`, where the app shows a "Someone you know scored n/10, can you beat it?" banner.

No user data is involved.

**Accessibility.** The mockups are real text elements in labelled groups, not images, and QR codes have text alternatives. The quiz is playable with the keyboard alone: focus moves to the question, then to the verdict, then to Next. The functional test answers a question using only Tab and Enter.

**Ads.** None inside the quiz: the app is the iframe, `tool_after` sits after it (that is, after the result screen), and the normal content rules apply below.

**Page.** 6 languages with how-to, FAQ, How it works, a **"Use it for team training"** section (a 15-minute meeting format) and use cases. `reviewed: false`. No network request, so the privacy pages are unchanged.

**Tests.**
- Unit: pool, reserved domains, completeness of all 6 languages, rounds, ranks, topics, share data.
- Functional:
  - `phishing-quiz`: keyboard answer, highlights match explanations, scoring 9/10, rank, review links, exact share text, score page card and redirect, challenge banner, no request from the app;
  - `phishing-quiz-it`: Italian scenario text.

**Forward link.** The pages mention the Email Header Analyzer as plain text for now; the links are added in Phase 4 once that tool exists, so every phase commit passes the link check.

## Phase 3 — Screenshot Redactor (`/tools/screenshot-redactor/`)

**Input.** Paste (Ctrl/⌘+V), drop or pick an image. `createImageBitmap(…, { imageOrientation: 'from-image' })` applies EXIF rotation first, so you redact what you see.

**Redactions.**
- **Solid box:** the default, black or any colour.
- **Pixelate and Blur:** selecting either shows a visible warning that they can be partly reversed or guessed. "How it works" explains why: candidate texts rendered in the same font can be pixelated or blurred the same way and compared.

Every box is stored as a rectangle, and a full-resolution composite is rebuilt from the original pixels after each change. There's undo/redo (buttons and Ctrl+Z / Ctrl+Y), zoom −/Fit/+, and a Move mode for scrolling a zoomed image. Drawing uses Pointer Events, so mouse, pen and touch all work (`touch-action: none` on the canvas).

**Export.**
- **Formats:** PNG, or JPEG flattened on white.
- **Fresh encoding:** a new image from the composite, so redactions are burned into the pixels, with no layers, no original and no metadata.
- **Copy image:** copies the result to the clipboard.

**Optional OCR helper.** Tesseract.js 5.1.1 is self-hosted in `static/vendor/` (library, LSTM WASM core, English `best_int` model, 2.9 MB) and lazy-loaded only on "Suggest areas". Recognition runs on the device.

The suggestions come from `js/tools/redact-kit.mjs`:
- emails;
- IBANs, which must pass the ISO 13616 mod-97 check;
- card numbers, which must pass the Luhn check;
- phone numbers, by digit count;
- IPv4 (octet ranges) and IPv6 (compressed forms).

Matches are made per OCR line, so values split across words get one box covering all of them. Each suggestion is a dashed box that can be ticked or unticked, then applied as solid boxes.

**Privacy.** The only extra requests are same-site files, loaded on demand, and the page says so. There's no third-party request, so the privacy pages are unchanged.

**Tests.**
- **Unit:** validators against the ISO/ECBS IBAN examples and the 4111 test card; detection; multi-word box unions; no false positives on times, dates, versions, prices or invalid numbers; geometry; history.
- **Functional (`screenshot-redactor`):**
  - drawing with the mouse and with a touch drag, plus undo/redo;
  - the soft-mode warning;
  - **real OCR** on a generated screenshot finds exactly the email, IBAN and IP, and nothing on the decoy line;
  - the PNG export has black pixels where boxes were, untouched pixels elsewhere and no metadata chunks;
  - a JPEG export of the GPS fixture contains no EXIF.

  It runs with every external request blocked, which also proves Tesseract never contacts a CDN.

**Found and fixed.** `setPointerCapture` can throw for a pointer the browser doesn't track, and that aborted the drag. Capture is now optional.

## Phase 4 — Email Header Analyzer (`/tools/email-header-analyzer/`)

**Input.** Paste raw headers or a whole message source. Continuation lines are unfolded and parsing stops at the first empty line, so the body is ignored. Analysis runs 250 ms after typing or on Analyze; two built-in samples (genuine ESP mail, spoofed phishing) are fictional fixtures.

**What it shows** (logic in `js/tools/email-headers.mjs`, DOM-free):
- **Verdict:** danger / caution / ok, derived from the strongest signals.
- **Signals**, sorted by severity (high, medium, low, info, good), each with a plain explanation of when it is harmless: display name containing a different address, Reply-To / Return-Path / Message-ID on another organisational domain, SPF/DKIM/DMARC results with **alignment** against the From domain, DMARC policy, ARC chain, mass-mailer X-Mailer, future Date, clock skew, hops slower than an hour, missing Received or Authentication-Results.
- **Sender identity** table, **Authentication** table (who checked it, result pills, `header.d`, selector, policy) and the **Received timeline**, oldest first, with host, IP, protocol, UTC time and delay per hop.

The tool trusts the receiving provider's `Authentication-Results` and does no DNS or signature verification itself; the page explains why. Organisational domains use a small built-in list of two-level public suffixes (co.uk, com.br…), not the full PSL — good enough for mismatch hints, noted in the code.

**How to get the headers** — Gmail web, Outlook for Windows (classic), new Outlook / Outlook on the web, Apple Mail and Thunderbird, with shortcuts, in all 6 languages, plus "don't forward it to yourself".

**Privacy.** No network requests at all (asserted in the functional test); privacy pages unchanged.

**Integration.** Icon `mail-search` (security category), OG icon tile regenerated, related links Phishing Quiz ↔ Link Hazmat ↔ Email Header Analyzer; the quiz pages' "sender checks" mention is now a link in all 6 languages (the quiz's "sender" topic already pointed here).

**Tests.**
- **Unit (9):** header unfolding, address/domain parsing, hop order/IPs/delays, Authentication-Results parsing, and four fixtures in `tests/fixtures/email-headers/` (legit ESP, spoofed phish, forwarded list mail with ARC, no-auth with clock skew) — fictional `.example`/`.test` domains and documentation IPs only.
- **Functional (`email-header-analyzer`):** phishing sample → danger with the spoofing signals and hop delays, no unfilled placeholders; a pasted fixture → ok with 3 hops; Clear; German UI; zero external requests.

**Found and fixed.** On phones the auth table broke "DMARC" mid-word (`overflow-wrap: anywhere`); header cells are now `nowrap`.

## Phase 5 — SPF, DKIM & DMARC Checker (`/tools/spf-dmarc-checker/`)

**Network.** DNS-over-HTTPS GET to `https://cloudflare-dns.com/dns-query?name=…&type=…` with `accept: application/dns-json`, **only on Check** (`?domain=` only pre-fills the box). Disclosed on the tool (visible note, FAQ, intro), on all 6 privacy pages as a third exception next to ipwho.is and api.pwnedpasswords.com, and in the 6 `/tools/` intros ("Three tools contact an outside service"). Privacy pages' `lastmod` → 2026-10-26.

**Privacy guard extended.** It now fails if any of the three disclosed hosts is missing from a privacy page, or if a tool script `fetch()`es (or defines a `*_URL`) on any other absolute host.

**Checks** (`js/tools/mail-auth.mjs`, DOM-free, resolver injected):
- **SPF** — single `v=spf1` record; lookups counted per RFC 7208 §4.6.4 (include, a, mx, ptr, exists, redirect) **recursively through every include**, repeated includes counted again as receivers do; loops (on the evaluation path), includes/redirects to domains without SPF (permerror), void lookups > 2, `ptr`, macros (counted, not resolved), invalid terms, `+all` / `?all` / missing `all` / `~all` / `-all`; include tree with per-node counts.
- **DMARC** — `_dmarc` record with org-domain fallback and `sp=` for subdomains; policy, `pct`, `sp=none`, `rua`/`ruf`, external report authorization (`<domain>._report._dmarc.<rua-domain>`, RFC 7489 §7.1), strict `adkim`/`aspf`; tag table with meanings.
- **DKIM** — user selectors or 12 common names; RSA modulus size read from the SPKI/RSAPublicKey DER in `p=` (< 1024 high per RFC 8301, 1024 low, ≥ 2048 good), Ed25519, revoked (`p=`), `t=y`.
- **MX** (incl. RFC 7505 null MX) and **BIMI** (`default._bimi`, needs enforcing DMARC at pct=100).
- **Grade** A–F from a 100-point score (high −30, medium −12, low −4).
- **Fixes** — example records built from the current ones (merged duplicate SPF, `~all`, `ptr` removed, DMARC monitoring → enforcement, missing `rua`, the external-report authorization record, 2048-bit DKIM rotation) with copy buttons and an explicit "check with your provider" note; placeholders in `<angle brackets>`.

UI strings live in `js/tools/mail-auth/{en,it,es,de,fr,pt}.mjs` (only EN + the page language are loaded).

**Tests.**
- **Unit (12):** offline DNS fixtures in `tests/fixtures/mail-auth/zones.json` (fictional domains; DKIM public keys generated at test time so no key material is committed): TXT chunk unescaping and the DoH request shape/header, input normalisation (email, URL, IDN), SPF parsing, recursive count (24 on the broken fixture), redirect/loop/multiple, DMARC fallback/authorization, key sizes, null MX, A and F grades with exact fix values, and a completeness check that every finding/fix has strings with matching placeholders in all 6 languages.
- **Functional (`spf-dmarc-checker`):** DoH mocked from the same fixtures; asserts zero queries before Check, the dns-json accept header on every query, F on the broken domain (24/10, tree, fixes, copy), A on the good one with guessed selectors, invalid-input message, Italian UI, no other external request.

**Found and fixed.** My first copy handler clashed with tool-kit's delegated `[data-copy="#id"]` handler, which copied an empty string; the page now uses the shared handler.
