---
title: "CVSS 4.0 Calculator (with CVSS 3.1)"
description: "Calculate CVSS 4.0 scores with FIRST's official MacroVector method, or CVSS 3.1 base, temporal and environmental scores. Paste a vector or click metrics."
intro: "Pick the metrics or paste a vector string to get the **CVSS 4.0** score, severity, nomenclature (CVSS-B, BT, BE or BTE) and MacroVector, computed with **FIRST's official scoring logic and lookup table**. A second tab scores **CVSS 3.1** vectors, including temporal and environmental scores. Share a result with a `?vector=` link. Everything runs in your browser."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["cvss 4.0 calculator", "cvss calculator", "cvss 3.1 calculator", "cvss score calculator", "cvss vector calculator", "calculate cvss score", "cvss 4 macrovector", "cvss-bte score"]
tags: ["security", "vulnerability", "cvss", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/cvss-calculator/"
tool_title: "CVSS 4.0 and 3.1 calculator"
tool_height: 1400
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Choose **CVSS 4.0** or **CVSS 3.1** with the tabs."
  - "Paste a **vector string** (for example from a security advisory), or click the value of each base metric."
  - "Optionally open **Threat**, **Environmental** or, in 4.0, **Supplemental** metrics to refine the score for your environment."
  - "Read the **score**, **severity** and, in 4.0, the **nomenclature** that tells others which metric groups were used."
  - "Press **Copy vector** for reports, or **Copy link** to share a page that opens with the same vector."
faq:
  - q: "Is the score the same as FIRST's official calculator?"
    a: "It is computed with the same method: this tool's CVSS 4.0 code is a port of the scoring function of FIRST's official calculator and uses its MacroVector lookup table unchanged. Its test suite checks every example vector published on FIRST's CVSS 4.0 examples page and compares 20,000 random vectors with the official code; CVSS 3.1 is compared with FIRST's 3.1 calculator in the same way. This site is not affiliated with FIRST."
  - q: "Why does CVSS 4.0 not use a formula like 3.1?"
    a: "CVSS 4.0 groups the metrics into six equivalence sets and maps each combination, a MacroVector, to a score that experts assigned. The final score starts from that MacroVector's score and is adjusted by how far the vector is from the most severe vector in the same MacroVector. That is why the tool shows the MacroVector next to the score."
  - q: "What do CVSS-B, CVSS-BT, CVSS-BE and CVSS-BTE mean?"
    a: "They say which metric groups a CVSS 4.0 score includes: B is Base only, T adds Threat metrics (Exploit Maturity), E adds Environmental metrics. A base score from an advisory is CVSS-B; once you add exploit information and your own environment it becomes CVSS-BTE."
  - q: "What are the severity ranges?"
    a: "The qualitative scale is the same in CVSS 3.1 and 4.0: None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0."
  - q: "Do the Supplemental metrics change the score?"
    a: "No. Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort and Provider Urgency add context for decisions but do not affect the CVSS 4.0 score. They still appear in the vector."
  - q: "Is anything sent to a server?"
    a: "No. The calculation runs in your browser and the tool makes no network requests. A shared link contains only the vector string."
---

## How it works

### CVSS 4.0: MacroVectors and the official lookup table

The 11 base metrics, plus Exploit Maturity and the environmental requirements, are sorted into six equivalence groups (EQ1–EQ6), such as "how reachable is the system" (Attack Vector, Privileges Required, User Interaction) or "how bad is the impact on the vulnerable system". The level of each group forms a six-digit **MacroVector**, and FIRST's lookup table gives each of its 270 possible values a score. The vector's score is that score minus an adjustment based on its distance from the most severe vector in the same MacroVector, rounded to one decimal. The tool's implementation follows FIRST's official calculator step by step and uses its table as published (BSD-2-Clause licence, credited in the source).

### Environmental and threat metrics

**Exploit Maturity** defaults to the worst case (Attacked) when not set, and the security requirements default to High, as in the specification. **Modified** metrics replace the matching base metric for your environment — for example, a system that is only reachable from an internal network can use Modified Attack Vector: Adjacent.

### CVSS 3.1

The second tab applies the equations of the CVSS 3.1 specification: the base score from impact and exploitability (with the Scope adjustment), the temporal score from Exploit Code Maturity, Remediation Level and Report Confidence, and the environmental score with the modified metrics and the 3.1 rounding function.

## Use cases

- **Triage advisories** — paste the vector from a CVE record or vendor bulletin and see what drives the score.
- **Score your own findings** — for a penetration-test report or a bug bounty submission, with a vector others can verify.
- **Adapt to your environment** — use Environmental metrics to rank the same vulnerability differently on internet-facing and internal systems.
- **Compare 3.1 and 4.0** — many databases still publish both; score the same issue in each tab.
- **Learn the metrics** — every value is labelled, and the score updates as you click.
