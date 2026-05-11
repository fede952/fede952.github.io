---
title: "マイクロソフト パッチチューズデー 2026年4月：167件の脆弱性、SharePointゼロデイ、BlueHammer"
date: "2026-05-11T10:37:48Z"
original_date: "2026-04-14T21:47:59"
lang: "ja"
translationKey: "microsoft-patch-tuesday-april-2026-167-flaws-sharepoint-zero-day-bluehammer"
author: "NewsBot (Validated by Federico Sella)"
description: "マイクロソフトは、SharePointのゼロデイ脆弱性や一般公開されたWindows Defenderの欠陥（BlueHammer）を含む167件の脆弱性を修正。Google ChromeとAdobe Readerも、活発に悪用されているバグを修正。"
original_url: "https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/"
source: "Krebs on Security"
severity: "Critical"
target: "Microsoft Windows、SharePoint、Windows Defender、Chrome、Adobe Reader"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

マイクロソフトは、SharePointのゼロデイ脆弱性や一般公開されたWindows Defenderの欠陥（BlueHammer）を含む167件の脆弱性を修正。Google ChromeとAdobe Readerも、活発に悪用されているバグを修正。

{{< cyber-report severity="Critical" source="Krebs on Security" target="Microsoft Windows、SharePoint、Windows Defender、Chrome、Adobe Reader" >}}

マイクロソフトの2026年4月のパッチチューズデーでは、Windowsおよび関連ソフトウェアにおける167件ものセキュリティ脆弱性が修正されました。最も深刻なものの中には、SharePoint Serverのゼロデイ脆弱性があり、リモートコード実行を許す可能性がありますが、報告書ではCVE識別子は提供されていません。さらに、「BlueHammer」と呼ばれるWindows Defenderの一般公開された弱点も修正されました。

{{< ad-banner >}}

別途、Google Chromeは2026年で4つ目のゼロデイを修正し、頻繁なブラウザアップデートの傾向が続いています。Adobe Readerも、リモートコード実行につながる活発に悪用されている欠陥に対処するための緊急アップデートを受け取りました。組織は、活発な悪用を考慮して、これらのアップデートを優先すべきです。

今月のパッチの膨大な量は、堅牢なパッチ管理プロセスの重要性を浮き彫りにしています。セキュリティチームは、SharePointのゼロデイとWindows Defenderの問題を最優先事項として焦点を当て、同時にChromeとAdobe Readerがエンタープライズ全体で更新されていることを確認する必要があります。

{{< netrunner-insight >}}

SOCアナリストは、SharePointのゼロデイとBlueHammer Windows Defenderの欠陥を即時パッチ適用の優先事項とすべきです。これらは活発に悪用されているか、一般に知られているためです。DevSecOpsチームは、これらのアップデートをCI/CDパイプラインに統合し、Defenderの修正によってエンドポイント保護ツールが妨げられないことを確認する必要があります。ChromeとAdobe Readerのパッチも、その活発な悪用状況を考慮して緊急の注意を要します。

{{< /netrunner-insight >}}

---

**[完全な記事を Krebs on Security で読む ›](https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/)**
