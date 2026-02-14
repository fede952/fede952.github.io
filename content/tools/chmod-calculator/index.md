---
title: "Cyberpunk Chmod Calculator"
description: "Visual Linux permissions generator. Convert rwx flags to octal (755) instantly."
date: 2026-02-14
tags: ["chmod", "linux", "permissions", "calculator", "tool"]
keywords: ["chmod calculator", "linux permissions calculator", "chmod 755", "file permissions", "rwx to octal", "octal permissions", "chmod generator"]
layout: "tool-split"
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    "name": "Cyberpunk Chmod Calculator",
    "description": "Visual Linux permissions generator. Toggle rwx flags and get the octal chmod command instantly.",
    "url": "https://federicosella.com/en/tools/chmod-calculator/",
    "applicationCategory": "DeveloperApplication",
    "operatingSystem": "Any",
    "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" }
  }
---

{{< chmod-tool >}}

## $ What_Is_Chmod

The `chmod` command in Linux/Unix changes file and directory permissions. It controls who can **read**, **write**, or **execute** a file.

## $ Permission_Matrix

| Value | Symbol | Meaning |
|-------|--------|---------|
| 4 | `r` | Read |
| 2 | `w` | Write |
| 1 | `x` | Execute |

Permissions are set for three groups: **Owner**, **Group**, and **Public** (others).

## $ Common_Examples

- `chmod 755` — Owner full, others read+execute (scripts, executables)
- `chmod 644` — Owner read+write, others read-only (config files, HTML)
- `chmod 600` — Owner read+write only (private keys, secrets)
- `chmod 777` — Full access for everyone (use with caution!)

## $ How_To_Use

1. Toggle the neon switches to set permissions for Owner, Group, and Public.
2. The octal value and symbolic representation update in real-time.
3. Enter your filename in the input field.
4. Click **Copy Command** to get the full `chmod` command ready to paste.
5. Use **Quick presets** for common permission sets.
