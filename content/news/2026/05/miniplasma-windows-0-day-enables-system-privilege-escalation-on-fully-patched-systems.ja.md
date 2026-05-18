---
title: "MiniPlasma Windows 0-Dayにより、完全にパッチが適用されたシステムでSYSTEM権限昇格が可能に"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "ja"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "セキュリティ研究者のChaotic Eclipseが、完全にパッチが適用されたシステム上でSYSTEM権限を付与する、Windows Cloud Files Mini Filter Driver (cldflt.sys)のゼロデイ脆弱性「MiniPlasma」のPoCを公開。"
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Windows Cloud Files Mini Filter Driver (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

セキュリティ研究者のChaotic Eclipseが、完全にパッチが適用されたシステム上でSYSTEM権限を付与する、Windows Cloud Files Mini Filter Driver (cldflt.sys)のゼロデイ脆弱性「MiniPlasma」のPoCを公開。

{{< cyber-report severity="High" source="The Hacker News" target="Windows Cloud Files Mini Filter Driver (cldflt.sys)" >}}

最近公開されたWindowsの脆弱性「YellowKey」や「GreenPlasma」の背後にいるセキュリティ研究者Chaotic Eclipseが、完全にパッチが適用されたWindowsシステム上で攻撃者にSYSTEM権限を付与する、Windows権限昇格のゼロデイ脆弱性の概念実証（PoC）を公開しました。コードネーム「MiniPlasma」と呼ばれるこの脆弱性は、Windows Cloud Files Mini Filter Driverである「cldflt.sys」に影響を与えます。

{{< ad-banner >}}

この脆弱性により、限られたユーザーアクセス権を持つ攻撃者が権限をSYSTEMに昇格させ、システム全体を危険にさらす可能性があります。ゼロデイであるため、現在公式パッチは提供されておらず、PoCが悪用された場合、完全にパッチが適用されたシステムでも脆弱性が悪用されるリスクがあります。

組織はcldflt.sysドライバーの異常な動作を監視し、Cloud Files機能へのアクセス制限や、パッチがリリースされるまでの一時的な緩和策の適用など、追加のセキュリティ強化策を検討すべきです。

{{< netrunner-insight >}}

SOCアナリストは、cldflt.sysを標的とした悪用試行の監視を優先すべきです。PoCにより攻撃者のハードルが下がったためです。DevSecOpsチームはWindowsイメージのセキュリティ強化を見直し、必要でなければCloud Files Mini Filter Driverを無効化することを検討し、Microsoftからの公式修正を待つべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
