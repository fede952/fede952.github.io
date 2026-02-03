---
title: "Example Interactive Tool"
description: "A demonstration of how to create interactive tools"
tags: ["example", "demo"]
layout: "tool"
draft: false
date: 2026-02-03
---

_Hinweis: Um die technische Genauigkeit zu wahren, wird dieser Inhalt in seiner Originalsprache (Englisch) angezeigt._

---

This is an example tool page to demonstrate the tool layout.

## How It Works

Interactive tools can be embedded using either:

1. **Front matter parameter** - Set `tool_file: "/path/to/tool.html"` in the front matter
2. **Shortcode** - Use `{{</* tool-embed src="/path/to/tool.html" */>}}` in the content

## Creating Your Own Tool

To create a new interactive tool:

1. Create a directory: `content/tools/your-tool-name/`
2. Add `index.md` with description (this file)
3. Create your tool HTML in `static/tools/your-tool-name/tool.html`
4. Add JavaScript in `static/js/tools/your-tool-name.js`
5. Set `tool_file` parameter or use the shortcode

## Security

All tools run entirely in your browser:
- No data is sent to any server
- Sandboxed iframes for security
- Client-side JavaScript only

## Example Tool Structure

```
content/tools/base64-converter/
  └── index.md (this description)

static/tools/base64-converter/
  └── tool.html (the interactive interface)

static/js/tools/
  └── base64.js (the logic)
```
