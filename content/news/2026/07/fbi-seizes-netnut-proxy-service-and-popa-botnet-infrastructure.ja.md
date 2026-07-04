---
title: "FBI、NetNutプロキシサービスとPopaボットネットのインフラを押収"
date: "2026-07-04T09:20:04Z"
original_date: "2026-07-02T19:27:33"
lang: "ja"
translationKey: "fbi-seizes-netnut-proxy-service-and-popa-botnet-infrastructure"
author: "NewsBot (Validated by Federico Sella)"
description: "FBIは、調査報道を受けて、200万台の侵害デバイスからなるPopaボットネットに関連する住宅用プロキシサービスNetNutのドメインを押収しました。"
original_url: "https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/"
source: "Krebs on Security"
severity: "High"
target: "住宅用プロキシサービスNetNutおよびPopaボットネット"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBIは、調査報道を受けて、200万台の侵害デバイスからなるPopaボットネットに関連する住宅用プロキシサービスNetNutのドメインを押収しました。

{{< cyber-report severity="High" source="Krebs on Security" target="住宅用プロキシサービスNetNutおよびPopaボットネット" >}}

FBIは業界パートナーと連携し、上場イスラエル企業Alarum Technologies（NASDAQ: ALAR）が運営する住宅用プロキシサービスNetNutに関連する数百のドメインを押収しました。この措置は、KrebsOnSecurityの報道がNetNutをPopaボットネット（ユーザーの同意なしに侵害された少なくとも200万台のデバイスからなるネットワーク）に結びつけたことを受けたものです。

{{< ad-banner >}}

Popaボットネットは、感染したデバイスを利用してNetNutのプロキシインフラを介してトラフィックをルーティングし、クレデンシャルスタッフィング、広告詐欺、アカウント乗っ取りなどの悪意ある活動を可能にします。今回の押収により、プロキシサービスとボットネットのコマンド＆コントロール機能の両方が妨害されます。

この作戦は、サイバー犯罪を助長するプロキシサービスを標的とする法執行機関の増加傾向を浮き彫りにしています。組織は、押収されたドメインへの接続についてネットワークトラフィックを確認し、残存するボットネット活動を監視する必要があります。

{{< netrunner-insight >}}

SOCアナリストにとって、この摘発は脅威インテリジェンスフィードにおける住宅用プロキシIP範囲の監視の重要性を強調しています。DevSecOpsチームは、サードパーティのプロキシサービスとの統合を監査し、Popaの残骸が代替インフラに残存する可能性があるため、堅牢なボットネット検出メカニズムを確保する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を Krebs on Security で読む ›](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)**
