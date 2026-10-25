---
title: "Text Diff Checker: Compare Two Texts"
description: "Compare two texts or files side by side or inline, with word or character highlights, ignore whitespace or case, and copy a unified diff. Private, in-browser."
intro: "Paste two versions of a text, config file or piece of code to see every **added**, **removed** and **changed** line, **side by side** or **inline**, with the exact **words** or **characters** that changed highlighted. Ignore whitespace or case, fold unchanged lines, and **copy a unified diff** you can apply with `git apply` or `patch`. Nothing leaves your browser."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["text diff", "diff checker", "compare text online", "compare two files", "diff tool", "unified diff", "text compare", "find differences between texts"]
tags: ["developer-tools", "diff", "text", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/text-diff/"
tool_title: "Text diff checker"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Paste the old version into **Original** and the new one into **Changed**, or load each with **Open file**. Press **Sample** to try it with two versions of an nginx config."
  - "The result updates as you type. Choose **Side by side** to see both versions in columns or **Inline** for one column with − and + lines (the default on phones)."
  - "Set **Highlight** to **Words** or **Characters** to choose how precisely changes inside a modified line are marked."
  - "Tick **Ignore whitespace** to treat indentation and runs of spaces as equal, and **Ignore case** to treat upper and lower case as equal."
  - "Long unchanged stretches are folded to three lines of context; click a *⋯ unchanged lines* bar to expand it. Use **Copy unified diff** or **Download .diff** to share the change as a patch."
faq:
  - q: "Are my texts uploaded anywhere?"
    a: "No. The comparison runs entirely in your browser with the open-source jsdiff library, served from this site. Nothing you paste or open is sent to a server, so you can compare contracts, configuration files with secrets or private code."
  - q: "What is the difference between word and character highlighting?"
    a: "Both first match the texts line by line. Inside each changed line, word mode marks whole words and punctuation marks that differ — the clearest choice for prose and most code. Character mode marks individual characters, which shows a one-letter typo or a changed digit in a long identifier or number."
  - q: "What does \"Ignore whitespace\" ignore exactly?"
    a: "Leading and trailing whitespace and the amount of whitespace between words: `a  =  1` and `a = 1` count as the same line, and re-indented blocks do not show as changed. Whitespace between two words that were previously joined is still a difference. Blank lines are still compared as lines."
  - q: "What is a unified diff and how do I apply it?"
    a: "It is the standard text format for a change, used by git, code review tools and the patch utility: `---` and `+++` headers, then hunks starting with `@@` that show removed lines with − and added lines with +, plus three lines of context. Save it as a `.diff` file and run `git apply change.diff` or `patch -p0 < change.diff`."
  - q: "How does the tool decide that a line was changed rather than removed and added?"
    a: "It uses the Myers diff algorithm on whole lines to find the smallest set of removals and additions. When a block of removed lines is directly followed by added lines, they are paired one to one as modified lines. If a pair shares less than about 30% of its content, it is shown as replaced, without inner highlights."
  - q: "Can it compare large files?"
    a: "Yes, up to several megabytes. Texts over about 400,000 characters are compared when you press Compare, instead of on every keystroke. The view shows up to 4,000 rows; the unified diff always contains the complete result. Very different texts that would take too long are reported instead of freezing the page."
  - q: "Does it handle Windows line endings?"
    a: "Yes. CRLF and CR line endings are normalised before comparing, so a file saved on Windows and the same file saved on Linux compare as identical. A missing newline at the end of the last line is ignored in the view and marked in the unified diff."
---

## How it works

### Lines first, then words or characters

Both texts are split into lines and compared with the **Myers diff algorithm** (the one behind `git diff`), which finds the shortest sequence of removals and additions that turns the original into the changed text. Removed lines directly followed by added lines are paired as *modified*, and each pair is compared again, token by token: either words, whitespace and single punctuation marks, or individual characters. Only the tokens that differ are highlighted.

### Ignore options that do not rewrite your text

**Ignore whitespace** and **Ignore case** change how lines and tokens are *compared*, not what is shown: each column still displays exactly what you pasted. This keeps the view honest when, for example, a block of code was re-indented — the lines match, and you still see the new indentation in the right column.

### Unified diff output

The **Copy unified diff** and **Download .diff** buttons create a standard patch with three lines of context, headed with the file names when you opened files (otherwise `original.txt` and `changed.txt`). Applying it to the original reproduces the changed text exactly; the test suite for this tool checks that with `git apply`.

## Use cases

- **Code and configuration.** See what changed between two versions of an nginx, Docker Compose or YAML file before you deploy it, without committing anything.
- **Documents and contracts.** Find every edited word between two drafts of a contract, policy or article.
- **Logs and exports.** Compare two command outputs, CSV exports or lists to spot the rows that appeared or disappeared.
- **Sharing a change.** Turn your edit into a `.diff` file a colleague can apply with git, or paste into a ticket.
- **Copy-paste checks.** Confirm that a script, key or snippet copied between systems arrived without invisible changes — switch to character mode for the finest detail.
