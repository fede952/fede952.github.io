---
title: "SideCopy Targets Afghanistan Finance Ministry with Xeno RAT"
date: "2026-06-02T11:14:31Z"
original_date: "2026-06-02T09:05:40"
lang: "en"
translationKey: "sidecopy-targets-afghanistan-finance-ministry-with-xeno-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Pakistan-linked SideCopy group uses spear-phishing with Pashto-language LNK files to deliver Xeno RAT against Afghanistan's Ministry of Finance."
original_url: "https://thehackernews.com/2026/06/pakistan-linked-sidecopy-targets.html"
source: "The Hacker News"
severity: "High"
target: "Afghanistan Ministry of Finance"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Pakistan-linked SideCopy group uses spear-phishing with Pashto-language LNK files to deliver Xeno RAT against Afghanistan's Ministry of Finance.

{{< cyber-report severity="High" source="The Hacker News" target="Afghanistan Ministry of Finance" >}}

Cybersecurity researchers have disclosed a spear-phishing campaign likely conducted by the Pakistan-aligned SideCopy group, targeting Afghanistan's Ministry of Finance. The attack begins with a ZIP archive containing a malicious LNK file that uses a carefully crafted Pashto-language filename to lure victims.

{{< ad-banner >}}

The payload delivered is Xeno RAT, an open-source remote access trojan. This tool provides attackers with extensive control over compromised systems, enabling data theft and further network compromise. The use of Pashto language suggests a focus on local targets within Afghanistan.

SideCopy has been historically linked to Pakistan-based threat actors and has targeted South Asian entities. This campaign underscores the ongoing geopolitical cyber espionage activities in the region, with government ministries being prime targets for intelligence gathering.

{{< netrunner-insight >}}

SOC analysts should monitor for LNK files with Pashto filenames and ZIP archives in phishing emails targeting government entities. DevSecOps teams should enforce strict email attachment filtering and user awareness training, especially for organizations with ties to Afghan or South Asian affairs. Xeno RAT's open-source nature means detection signatures are available, so ensure your EDR solutions are updated.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/06/pakistan-linked-sidecopy-targets.html)**
