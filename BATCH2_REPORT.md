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

## Phase 6 — Encrypted Message Link (`/tools/encrypted-message/`)

**Crypto** (`js/tools/secret-link.mjs`, Web Crypto only):
- **Key derivation:** PBKDF2-HMAC-SHA-256 with **600,000 iterations** and a 16-byte random salt; the passphrase is NFC-normalised.
- **Encryption:** AES-256-GCM with a 12-byte random IV and a 128-bit tag. The version string `v1` is bound to the ciphertext as additional authenticated data.
- **Token:** `v1.<base64url(salt | iv | ciphertext+tag)>`.
- **Errors:** a wrong passphrase and a tampered link both fail with `auth`, because GCM can't tell them apart. The copy says so honestly. A malformed or truncated token fails with `format`.

**Where the ciphertext lives.** Only in the URL `#fragment`. The share link targets the **standalone app page** `/tools/encrypted-message/#v1.…`, not the content page. The content page loads AdSense and Umami; the standalone page loads neither and sets `referrer: no-referrer`. On open, the app keeps the token in memory, strips it from the address bar with `history.replaceState`, and reloads if another link is opened in the same tab (`hashchange`).

**Honest copy, in all 6 languages:**
- no self-destruct and no expiry: the link works for as long as copies exist, and there is nothing server-side to delete;
- send the link and the passphrase over different channels;
- a "what it does not protect against" list: weak passphrases (offline guessing), compromised devices, copies of the link.

**Other behaviour:**
- a link-length warning above 2,000 characters;
- a passphrase generator: 5×4 characters from a 56-symbol unambiguous alphabet, rejection-sampled, about 116 bits;
- a minimum of 8 characters;
- "Close and forget" clears the message.

**Tests.**
- **Unit vectors (6):**
  - round trip at the real 600k iterations, with fresh salt/IV per message;
  - wrong passphrase, including a case change;
  - tampering: a flipped ciphertext byte, tag byte or IV byte, or a truncated tag, all fail on the GCM tag; a changed version or bad Base64 fails as format;
  - Unicode/emoji in both the message and the passphrase, plus NFC equivalence and an empty message;
  - a **known-answer vector cross-checked against an independent `node:crypto` implementation**, in both directions;
  - the link format and the generator.
- **Functional (`encrypted-message`):**
  - passphrase required;
  - the generator;
  - the link targets the standalone page and contains no plaintext;
  - after opening, the fragment is stripped and **never appears in any request**;
  - wrong, tampered and truncated links are rejected with the right message;
  - the Unicode round trip;
  - the Italian long-link warning;
  - zero external requests.

**Found and fixed.** Opening a second link in the same tab only changed the hash, so the page stayed on the previous message. It now reloads on `hashchange`.

## Phase 7 — CVSS 4.0 Calculator with a 3.1 tab (`/tools/cvss-calculator/`)

**Sources, obtained and kept offline, nothing guessed.**
- **FIRST's official v4.0 calculator** (github.com/FIRSTdotorg/cvss-v4-calculator, commit `c5b0d40`, BSD-2-Clause) is vendored unmodified in `static/vendor/cvss-v4-calculator@c5b0d40/`:
  - `cvss_lookup.js`, the 270-entry MacroVector table;
  - `max_composed.js`, `max_severity.js` and `metrics.js`;
  - `cvss_score.js`;
  - `LICENSE`.

  `scripts/cvss-v4-data.mjs` evaluates the data files in an empty `vm` context and generates `js/tools/cvss/v4-data.mjs`, which credits the source and licence.
- **FIRST's official v3.1 calculator** (`first.org/cvss/calculator/cvsscalc31.js`, BSD-3) is kept in `tests/reference/` and used only as a test oracle.
- **FIRST's official examples:** every "score + vector" cell in the tables of first.org/cvss/v4.0/examples, saved to `tests/fixtures/cvss-first-examples.json` (19 v4.0 vectors, 10 v3.1 vectors, fetched 2026-10-25).
  - Prose-only examples were **not** turned into vectors, because that would mean interpreting them.

**Scoring** (`js/tools/cvss.mjs`).
- **v4.0** is a line-by-line port of `macroVector()` and `cvss_score()`, including the official calculator's behaviour when no max vector fits.
- **v3.1** uses the spec equations with the integer-arithmetic Roundup and the 3.1 modified-impact formula.
- Parsing accepts any metric order, outputs the canonical order, and rejects unknown, duplicate, invalid or missing base metrics.
- v4.0 shows the nomenclature (CVSS-B/BT/BE/BTE) and the MacroVector; supplemental metrics never change the score.

**UI.**
- Version tabs; pasting a 3.1 vector switches to the 3.1 tab.
- An accessible radio group per metric, so arrow keys work.
- Groups open automatically when a vector sets any of their metrics.
- Metric names come from FIRST's config, translated in 5 languages through a phrase table (with a coverage test).
- Copy vector, and **Copy link** to `/<lang>/tools/cvss-calculator/?vector=…`. The embedded app reads `?vector=` from the parent page (same origin) or from its own URL.

**Tests.**
- **Unit (8):**
  - the generated data equals the vendored files;
  - **all 19 FIRST v4.0 examples**;
  - **identical to the official `cvss_score.js` on 20,000 seeded random vectors**, MacroVector included;
  - **all 10 FIRST v3.1 examples**;
  - **identical to FIRST's `cvsscalc31.js` on 20,000 random vectors** (base, temporal and environmental);
  - Roundup and parsing;
  - UI definitions vs. allowed values, and translations.
- **Functional (`cvss-calculator`):**
  - a `?vector=` deep link on the content page gives 8.9 CVSS-BTE and the vector shown in the box;
  - all 19 examples typed into the UI;
  - clicks and arrow keys update the vector and score;
  - the invalid-vector message;
  - the 3.1 auto-tab, with temporal and environmental scores equal to FIRST's calculator;
  - copy link;
  - Italian labels.

**Found and fixed.** A deep-linked vector was scored but the box still showed the default vector. `load()` now writes the box unless the change came from typing in it.

## Phase 8 — Enhancements

### Hash Generator → file checksum verifier

A new **Verify a file checksum** section on `/tools/hash-generator/`, inside the inline partial. The text hashing is unchanged.

**Hashing.**
- **Streaming in a module Worker** (`js/tools/hash-worker.mjs`): `file.stream()` chunks go through incremental MD5, SHA-1, SHA-256 or SHA-512.
- The hashers come from **hash-wasm 4.12.0** (MIT), self-hosted in `static/vendor/hash-wasm@4.12.0/` as the four per-algorithm UMD builds with the WebAssembly embedded.
- They are imported by the Worker only when a file is chosen. Multi-gigabyte files work without being held in memory.
- There is a progress bar and a Cancel button.

**Expected checksum** (`js/tools/checksum.mjs`, DOM-free).
- **Accepted formats:**
  - a bare hash;
  - GNU `sha256sum` / `md5sum` lines, text or `*binary` mode;
  - BSD / `shasum --tag` lines (`SHA256 (file) = …`);
  - PowerShell `Get-FileHash` output, list and table format.
- **Whole listings:** pasting an entire `SHA256SUMS` file picks the line for the chosen file name (case-insensitive). With no matching line, it says so instead of guessing.
- **Algorithm:** set from the hash length. A different algorithm triggers a re-hash.

**Verdicts:**
- **Match** or **Mismatch**, the latter with "don't open it; re-download from the official site";
- a weak-hash note for MD5 and SHA-1 (a match only rules out accidental damage);
- messages for bad input and ambiguous listings.

**Content, in 6 languages:**
- new title and description;
- a **"How to verify a download"** section:
  - get the checksum from the official source, not the mirror;
  - paste formats;
  - one character is enough for a mismatch;
  - prefer SHA-256/512;
  - GPG/Sigstore signatures as the stronger check;
- an updated "Can I hash a file?" FAQ and a howto step;
- 18 new i18n keys per language.

**Tests.**
- **Unit (5):**
  - streaming digests equal **node:crypto** for all four algorithms at chunk sizes from 1 B to 1 MB on a 3 MB random file, plus the FIPS "abc" and RFC 1321 empty-string vectors;
  - cancel;
  - all paste formats;
  - SHA256SUMS selection;
  - helpers.
- **Functional (`hash-file`):**
  - a 24 MB file gives the same SHA-256 as node:crypto;
  - the progress bar hides when done;
  - a SHA256SUMS line matches; a one-character change is a mismatch;
  - an MD5 checksum is auto-detected, re-hashed, and shows the weak-hash note;
  - ambiguous and bad input messages;
  - the text hashes still work;
  - hash-wasm and the Worker are loaded on demand from this site.

### Password Generator → multilingual diceware passphrases

There's a **Password / Passphrase** mode switch.

**Passphrase options:**
- 3–12 words (default 6);
- a word list, defaulting to **the page language**;
- separator: hyphen, space, dot, underscore or none;
- capitalise words (adds no entropy, and the copy says so);
- add a digit (+log₂(10·words) bits);
- **remove accents**, shown only for lists that have accents.

The strength line shows the exact entropy; the info line shows bits per word, list size and source.

**Word lists.** All are vendored unmodified with their licence files and fetched lazily from this site:

| Language | List | Words | Bits/word | Licence |
|---|---|---|---|---|
| EN | EFF Large Wordlist (2016-07-18) | 7,776 | 12.92 | CC BY 4.0 (EFF copyright policy, attribution in `LICENSE`) |
| DE | dys2p/wordlists-de `de-7776-v1` (commit 6ef31b9) | 7,776 | 12.92 | Unlicense / CC0 / BSD-3 |
| IT, ES, FR, PT | BIP-39 lists from trezor/python-mnemonic (commit b57a5ad) | 2,048 | 11 | MIT |

**Notes on the lists:**
- **No invented or self-built lists.**
- The Spanish and French files are Unicode NFD, so they are normalised to NFC on load.
- Stripping accents keeps all 2,048 BIP-39 words distinct, which the tests check. If a list ever collapsed, the generator would use the deduplicated size, so the entropy shown stays honest.
- The EFF list contains four hyphenated words (drop-down, felt-tip, t-shirt, yo-yo). They are kept as published.

**Content, in 6 languages:**
- title, description and intro;
- a howto step;
- updated "remember these passwords?" FAQ, plus a new FAQ naming every list and its licence;
- a **Passphrases** section with an entropy table (4–8 words, both list sizes, computed values).

**Tests.**
- **Unit (5):**
  - list sizes, uniqueness, letters only, a licence file next to each list;
  - NFC and accent stripping;
  - entropy;
  - options;
  - rejection sampling with a forced top-bucket RNG, and a uniformity check.
- **Functional (`passphrase`):**
  - password mode by default, with no list loaded;
  - on `/it/`, the Italian list is the default (6 words = 66 bits);
  - French with accents stripped, 15 draws;
  - EFF, 7 words with capitals and a digit, exact entropy;
  - lists fetched lazily from `/vendor/`;
  - switching back to password mode.

**Found and fixed.** In both partials, the site CSS (`display: flex` on `.pg-checkbox` and `.hash-file-progress`) overrode the `hidden` attribute, so a finished progress bar and an irrelevant checkbox stayed visible. Both now have explicit `[hidden]` rules, and the tests assert it.

## Phase 9 — Integration and verification

**Integration.**
- **Catalogue:** all six new tools are in the security category in `data/tool_icons.yaml`, each with an original icon: `phish`, `redact`, `mail-search`, `mail-shield`, `lock-link` and `gauge-bars`. The OG icon tiles were regenerated.
- **Cross-links** in `data/related.yaml`:
  - Phishing Quiz ↔ Link Hazmat ↔ Email Header Analyzer ↔ SPF/DMARC Checker;
  - Screenshot Redactor ↔ EXIF Cleaner;
  - Encrypted Message ↔ PassFort / Password Generator;
  - CVSS ↔ Security Headers.
- **Sitemap and search:** all pages in 6 languages are in the sitemap (573 URLs) and in the per-language search indexes.
- **Ads:** layout v2 is unchanged. The quiz questions live inside the iframe, so no unit can sit between them. The CVSS app gained a scoring-credit footer (FIRST attribution, "not affiliated"), translated in 6 languages.
- **ARCHITECTURE.md** is updated:
  - the disclosed network exceptions and the privacy-guard fetch rule;
  - DOM-free modules and lazy vendored libraries;
  - parent-URL deep links;
  - the encrypted-link standalone target;
  - `article_mid` before the **2nd** `<h2>` on tool pages;
  - a new **Share cards (Open Graph)** section.

**Test harness fixes.**
- `tests/ads.mjs` counted controls inside a **closed `<details>`** as "tool controls". Chromium still lays them out, here 1,200 px below the iframe's end. That flagged the after-tool unit on the CVSS page at a random 92–148 px. The check now skips the content of closed `<details>`.
- `tests/visual.mjs` now also covers the eight new or changed tool pages.

**Full suites on the final build.**
- **Visual:** 152 page/viewport runs (19 pages × 4 viewports × EN/IT), 0 problems.
- **Functional:** all pass. That includes the 11 new tests from this batch:
  - `phishing-quiz` and `phishing-quiz-it`;
  - `screenshot-redactor`;
  - `email-header-analyzer`;
  - `spf-dmarc-checker`;
  - `encrypted-message`;
  - `cvss-calculator`;
  - `hash-file`;
  - `passphrase`;
  - plus the existing `hash-generator` test.
- **Unit:** 111/111.
- **Tool pages:** 222 runs, 0 problems.
- **Ads:** 456 runs, 0 problems, max CLS 0.033.
- **Static:** 3,020 HTML files, 0 broken internal links; 1,297 JSON-LD blocks, 0 errors; sitemap 573 URLs; 452 per-page share cards, all 1200×630.
- **Privacy guard:** 1,121 files, 71 images, 0 problems.

**Lighthouse 13.5.0, mobile** (default emulation, simulated throttling). Local production build, ad and analytics hosts blocked:

| Page | Perf | A11y | BP | SEO | LCP | TBT | CLS |
|---|---|---|---|---|---|---|---|
| Phishing Quiz | 93 | 100 | 100 | 100 | 2.85 s | 0 ms | 0.000 |
| Screenshot Redactor | 95 | 100 | 100 | 100 | 2.55 s | 17 ms | 0.000 |
| SPF/DKIM/DMARC Checker | 94 | 100 | 100 | 100 | 2.70 s | 0 ms | 0.001 |

All targets are met: Perf ≥ 90, A11y/BP/SEO 100, CLS < 0.05. Runs with third parties allowed were **not** made, because they would send requests to live ad servers.

## Federico TODO

1. **Review and merge `batch2`.** Nothing is pushed. Merge into `main` when happy, then deploy.
2. **After deploy, smoke-test the one network-dependent tool on the real domain.** The SPF/DKIM/DMARC Checker calls `cloudflare-dns.com` from `federicosella.com`; CORS was only exercised with a mocked resolver locally. Check one real domain of your own.
3. **Native-speaker pass over the new copy.** This covers the 6 new tools × 6 languages, plus the updated Hash and Password Generator pages; all are `reviewed: false`. In particular:
   - the localized **menu names** in "How to get the headers" (Outlook "Internet headers", Apple Mail "All Headers"/"Raw Source", Thunderbird "Message Source"). They differ by version and locale; the English labels match current versions, the translated labels are best effort and should be checked in each client;
   - the **CVSS metric-name translations**: FIRST publishes the metrics in English only, so these are unofficial;
   - the 32 Phishing Quiz scenarios in IT/ES/DE/FR/PT.
4. **Privacy policy.** The privacy pages now name `cloudflare-dns.com` as a third exception, in 6 languages, with `lastmod` 2026-10-26. If a lawyer reviews the policy, include this change.
5. **Share cards.** After deploy, paste a tool URL and a quiz score URL (`/en/tools/phishing-quiz/score/7/`) into the LinkedIn Post Inspector, the Facebook Sharing Debugger and an X post preview to confirm the cards are picked up. Platforms cache them.
6. **Quiz promotion.** The score pages are `noindex` by design. Share them from your socials; there's a "Use it for team training" section to point teams at.
7. **AdSense.** The new pages use the existing slots (`tool_top`, `article_mid`, `tool_after`, sidebar). Watch the first weeks of RPM on the quiz and the checkers. The quiz has no units inside the questions; the policy-safe choice is to keep it that way.
8. **Optional follow-ups**, not done:
   - an Argon2id option for the encrypted link (PBKDF2-SHA-256 at 600k iterations is used now; an Argon2 WASM build would be about 30 KB more to vendor);
   - a German BIP-39-style 2,048-word list, if you want equal list sizes across languages (German uses dys2p's 7,776-word list now);
   - OCR models for languages other than English in the Screenshot Redactor (each `traineddata` is 1–4 MB).
9. **Keep the vendored references current:**
   - CVSS: if FIRST updates `cvss-v4-calculator`, re-vendor it and run `node scripts/cvss-v4-data.mjs`; the unit tests compare against the vendored official code;
   - Hash Generator: if a newer `hash-wasm` is vendored, change the path in `js/tools/hash-worker.mjs`.
