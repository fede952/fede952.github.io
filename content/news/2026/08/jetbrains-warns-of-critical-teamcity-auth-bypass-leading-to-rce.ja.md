---
title: "JetBrains、TeamCityの重大な認証バイパスによりRCEにつながる可能性を警告"
date: "2026-08-03T10:38:49Z"
original_date: "2026-07-30T22:01:31"
lang: "ja"
translationKey: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
slug: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "JetBrainsは、TeamCity On-Premisesの重大な認証バイパスによりリモートコード実行が可能になる可能性があると警告しています。直ちにパッチを適用することを推奨します。"
original_url: "https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/"
source: "BleepingComputer"
severity: "Critical"
target: "TeamCity On-Premises"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

JetBrainsは、TeamCity On-Premisesの重大な認証バイパスによりリモートコード実行が可能になる可能性があると警告しています。直ちにパッチを適用することを推奨します。

{{< cyber-report severity="Critical" source="BleepingComputer" target="TeamCity On-Premises" >}}

JetBrainsは、TeamCity On-Premisesに影響する重大な認証バイパスの脆弱性について警告を発しました。この欠陥は、認証されていない攻撃者によって悪用され、影響を受けるサーバー上でリモートコード実行を達成する可能性があり、ビルドおよび継続的インテグレーションパイプラインをTeamCityに依存している組織に深刻なリスクをもたらします。

{{< ad-banner >}}

この脆弱性は、TeamCityサーバーが機密性の高いソースコード、ビルド成果物、資格情報を保持していることが多く、攻撃者にとって価値の高い標的となるため、特に懸念されます。悪用に成功すると、サーバーが完全に侵害され、サーバーが適切に分離されていない場合には、より広範なインフラストラクチャが侵害される可能性があります。

TeamCity On-Premisesを使用している組織は、ベンダーが提供するセキュリティ更新プログラムを直ちに適用することを優先すべきです。パッチが適用されるまでは、TeamCityサーバーへのネットワークアクセスを制限し、不審なアクティビティを監視することをお勧めします。

{{< netrunner-insight >}}

これは緊急事態として扱うべき重大な脆弱性です。SOCアナリストは、組織がTeamCity On-Premisesを使用しているかどうかを直ちに確認し、パッチの状態を検証する必要があります。認証されていないRCEの可能性を考慮すると、サーバーが公開されている場合は侵害を想定し、徹底的なフォレンジックレビューを実施してください。DevSecOpsチームは、ビルドサーバーをセグメント化し、厳格なアクセス制御を適用して爆発半径を軽減することも検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/)**
