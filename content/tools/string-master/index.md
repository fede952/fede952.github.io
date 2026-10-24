---
title: "Word Counter & Text Case Converter"
description: "Count words, characters, lines and reading time live, then convert case, remove duplicate lines, trim whitespace or turn text into leetspeak. In-browser."
intro: "**StringMaster** is a small text workbench. Paste anything and it counts words, characters, lines and reading time as you type. One click converts case, removes duplicate lines, cleans up whitespace or turns the text into leetspeak. The text stays in your browser tab."
date: 2026-02-10
lastmod: 2026-10-24
reviewed: false
keywords: ["word counter", "character counter", "online text tools", "uppercase lowercase converter", "remove duplicate lines", "trim whitespace online", "leetspeak converter", "reading time calculator"]
tags: ["text", "developer-tools", "writing", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/string-master/"
tool_title: "StringMaster text tools"
tool_height: 750
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Paste or type your text in the **Input** box. **Words**, **Characters**, **Lines** and **Reading Time** update on every keystroke."
  - "Click **Uppercase** or **Lowercase** to convert the whole text."
  - "Click **Remove Duplicates** to keep only the first occurrence of every line, or **Trim Whitespace** to strip spaces at line ends and collapse runs of blank lines."
  - "Click **Hacker Mode** to rewrite the text in leetspeak (`hello` → `h3110`)."
  - "Click **Copy** to put the result on your clipboard. Transformations replace the text in place, so copy the original first if you may need it again."
faq:
  - q: "How are words counted?"
    a: "The text is split on any run of whitespace (spaces, tabs, line breaks), so `state-of-the-art` is one word and `e.g. this` is two. Languages written without spaces, such as Chinese or Japanese, are counted as one word per space-separated chunk, so use the character count for those."
  - q: "Do emoji and accented letters count as one character?"
    a: "Yes. The counter uses the browser's grapheme segmenter (`Intl.Segmenter`), so 👍, é and even a family emoji built from several code points each count once, matching what you see. Note that some platforms, such as SMS, count differently (in UTF-16 units or bytes), so their limits can be reached sooner."
  - q: "How is the reading time estimated?"
    a: "Word count divided by 200 words per minute, a common average for reading on screen, rounded up. Under a minute it shows seconds (`45s`), above it whole minutes (`4m`). Technical or dense text is usually read more slowly."
  - q: "Is Remove Duplicates case-sensitive?"
    a: "Yes, and exact: `Apple`, `apple` and `apple ` (with a trailing space) are three different lines. Run **Trim Whitespace** and **Lowercase** first if you want looser matching. The order of first occurrences is preserved, and repeated blank lines also collapse into one."
  - q: "Can I undo a transformation?"
    a: "There is no undo button, and because the text is replaced by script, Ctrl+Z may not bring it back in every browser. Lowercase, Remove Duplicates, Trim Whitespace and Hacker Mode all lose information, so keep a copy of the original."
  - q: "Can leetspeak be converted back?"
    a: "Not reliably. Both `i` and `l` become `1`, and digits that were already in the text are indistinguishable from substituted letters. Hacker Mode is a one-way style effect, not an encoding."
  - q: "Is my text sent anywhere?"
    a: "No. All counting and transformations are plain JavaScript in the page; nothing is stored or transmitted. That makes it safe for drafts, logs or internal documents."
---

## How it works

Every keystroke in the input box runs the same small analysis:

- **Words** = number of non-empty chunks after splitting the trimmed text on whitespace (`/\s+/`).
- **Characters** = number of grapheme clusters, the characters a person would count, via `Intl.Segmenter`. Browsers without it fall back to counting Unicode code points. Spaces and line breaks count as characters.
- **Lines** = number of line-break-separated lines. An empty box shows 0, and a trailing line break adds an empty last line.
- **Reading Time** = ⌈words ÷ 200 × 60⌉ seconds, shown in seconds below one minute and in rounded-up minutes above.

The buttons each apply one transformation to the whole text and then recount:

| Button | What it does | Example |
|---|---|---|
| **Uppercase** | Unicode upper case (`toUpperCase`) | `straße` → `STRASSE` |
| **Lowercase** | Unicode lower case (`toLowerCase`) | `HeLLo` → `hello` |
| **Remove Duplicates** | Keeps the first copy of each exact line, in order | `a, b, a, c` → `a, b, c` |
| **Trim Whitespace** | Trims each line, allows at most one blank line in a row, trims the ends | `··text··` → `text` |
| **Hacker Mode** | Replaces a→4, b→8, e→3, g→9, i→1, l→1, o→0, s→5, t→7 | `get root` → `937 r007` |
| **Copy** | Copies the text with the Clipboard API | — |

Two details worth knowing. Case conversion is not locale-specific, so Turkish dotted/dotless *i* follow the generic Unicode rules. Trim Whitespace only touches line ends and blank lines; double spaces *inside* a line are left alone, which keeps code indentation and tables readable.

## Use cases

- **Writing to a limit.** Check essays, meta descriptions, abstracts or social posts against a word or character budget as you edit.
- **Cleaning lists.** Paste a column of emails, hostnames or IDs exported from a spreadsheet and remove duplicates in one click. Lowercase first for case-insensitive data like email addresses.
- **Tidying logs and pasted output.** Strip trailing spaces and squeeze the blank-line padding from terminal output before pasting it into a ticket or document.
- **Normalising identifiers.** Lower-case tags or keys before comparing them, or upper-case constants and SQL keywords.
- **Fun text.** Turn a username, banner or CTF team name into leetspeak.
- **Estimating talk length.** Reading time is a rough guide for scripts; speaking is slower, typically around 130–150 words per minute.

To encode text rather than reshape it, see the [Base64 converter](/tools/base64-converter/) or the [hash generator](/tools/hash-generator/).
