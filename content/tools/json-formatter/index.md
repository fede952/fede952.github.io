---
title: "JSON Formatter & Validator, JSON to YAML"
description: "Format, minify and validate JSON with exact line and column errors, sort keys, browse it as a tree and convert JSON to YAML or CSV. Private, in your browser."
intro: "Paste JSON to **format** it with 2 or 4 spaces or tabs, **minify** it, **validate** it with an exact *line and column* for the first error, **sort keys**, browse it as a collapsible **tree**, or convert **JSON to YAML**, **YAML to JSON** and **JSON to CSV**. Files of several megabytes are handled by a background worker; nothing is uploaded."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["json formatter", "json validator", "json beautifier", "format json online", "json to yaml", "yaml to json", "json to csv", "json minify"]
tags: ["developer-tools", "json", "yaml", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-formatter/"
tool_title: "JSON formatter, validator and converter"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Paste your JSON into **Input**, open a `.json` file with **Open file**, or press **Sample** to try it."
  - "Press **Format** (or Ctrl/⌘ + Enter) to pretty-print it with the chosen **Indent**; **Minify** removes all whitespace. Tick **Sort keys** to order every object's keys alphabetically."
  - "If the JSON is invalid, the status line names the problem and its position — for example *Line 3, column 14: trailing comma* — and the offending line is shown with a caret under the exact character."
  - "Convert with **To YAML** or **To CSV** (choose the **CSV separator**). To go the other way, switch to **YAML input**, paste YAML and press **Format** to get JSON."
  - "Switch the output between **Text** and **Tree** to browse large structures, then **Copy** or **Download** the result."
faq:
  - q: "Is my JSON sent to a server?"
    a: "No. Parsing, formatting and conversion run in your browser — inputs over 2 MB in a Web Worker in the same tab. The page makes no request with your data, so API responses, tokens and configuration files stay on your machine."
  - q: "Why does it say \"trailing comma\"?"
    a: "JSON does not allow a comma after the last element of an object or array, even though JavaScript does. `[1, 2,]` and `{\"a\": 1,}` are invalid JSON; remove the final comma. Other common errors the validator names: single quotes, unquoted keys, comments and NaN or Infinity values."
  - q: "How does it find the line and column of an error?"
    a: "Browsers' JSON.parse messages differ and some only give a character offset. When parsing fails, the tool re-reads the text with its own strict RFC 8259 scanner, which stops at the first character that cannot be valid and reports that position as line and column."
  - q: "How is JSON converted to CSV?"
    a: "An array of objects becomes one row per object. Nested objects become dotted columns (`address.city`), arrays inside a row are written as JSON text, and the columns are the union of all keys in order of first appearance. Values with commas, quotes or line breaks are quoted as RFC 4180 requires. An array of arrays is written row by row."
  - q: "Are YAML comments and anchors kept when converting?"
    a: "YAML to JSON resolves anchors and aliases into plain values, and comments are dropped, because JSON has neither. JSON to YAML produces block-style YAML without anchors, so repeated structures are written out in full."
  - q: "Does sorting keys change my data?"
    a: "No values change. Object keys are reordered by Unicode code point (so uppercase sorts before lowercase), at every level; arrays keep their order because their order is part of the data. Sorted output is handy for diffs and for stable files in version control."
  - q: "How big a file can it handle?"
    a: "Tens of megabytes on a desktop. Above 2 MB, formatting and minifying run in a background worker so the page stays responsive. The tree view renders nodes only when you open them and shows at most 500 children per node at a time."
---

## How it works

### Validation that explains itself

The input is parsed with the browser's native `JSON.parse`, the fastest and most standards-compliant parser available. When it fails, a second, deliberately small scanner walks the text following the RFC 8259 grammar — objects, arrays, strings with their escape rules, numbers without leading zeros, `true`, `false`, `null` — and stops at the first character that cannot continue a valid document. That position is converted to a line and column and matched to a plain-language explanation: a trailing comma, a missing colon, a single-quoted string, an unescaped tab inside a string, or text after the end of the document.

### Formatting, minifying and sorting

Formatting uses `JSON.stringify` with the chosen indent (2 spaces, 4 spaces or a tab). Minifying writes the same structure with no whitespace. **Sort keys** rebuilds every object with its keys in code-point order before serialising; array order is never changed. Numbers are written as JavaScript reads them, so integers beyond 2^53 lose precision — keep such IDs as strings.

### Large inputs

Above 2 MB of UTF-8, formatting and minifying are handed to a **Web Worker**, a background thread in the same tab, so typing and scrolling stay smooth while a large API dump is processed. The tree view renders lazily: a node's children are created only when you expand it.

### Conversions

YAML support comes from **js-yaml** (MIT), served from this site and loaded only when you first use YAML. YAML is parsed with the safe default schema, so it cannot create custom objects or run code. CSV is generated by the tool itself, following RFC 4180 quoting and line endings.

## Use cases

- **Debugging APIs.** Pretty-print a one-line response, spot the field you need in the tree, or find exactly where a hand-edited payload breaks.
- **Configuration work.** Convert a Kubernetes or Docker Compose snippet between YAML and JSON, or validate a `package.json` or `tsconfig.json` after editing.
- **Data exports.** Turn an array of records into CSV for a spreadsheet, with nested fields flattened into columns.
- **Code review and version control.** Sort keys and format consistently so diffs show real changes, not reordering.
- **Sensitive payloads.** Inspect JWT payloads, webhook bodies or logs that contain personal data without pasting them into a third-party website.
