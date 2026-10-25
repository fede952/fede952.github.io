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
