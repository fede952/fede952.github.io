---
title: "シルバーフォックスAPT、税金をテーマにした攻撃で新たなバックドア「ABCDoor」を展開"
date: "2026-05-05T09:10:11Z"
original_date: "2026-05-04T14:39:26"
lang: "ja"
translationKey: "silver-fox-apt-launches-tax-themed-attacks-with-new-abcdoor-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "中国支援のシルバーフォックスがインドとロシアを標的に、税金をテーマにしたフィッシング攻撃を展開。ABCDoorバックドアとValleyRATマルウェアを配布。"
original_url: "https://www.darkreading.com/endpoint-security/silver-fox-tax-themed-attacks-india-russia"
source: "Dark Reading"
severity: "High"
target: "インドとロシアの組織"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

中国支援のシルバーフォックスがインドとロシアを標的に、税金をテーマにしたフィッシング攻撃を展開。ABCDoorバックドアとValleyRATマルウェアを配布。

{{< cyber-report severity="High" source="Dark Reading" target="インドとロシアの組織" >}}

中国が支援する高度持続的脅威グループ「シルバーフォックス」は、税金をテーマにしたソーシャルエンジニアリングを用いた新たなキャンペーンを開始し、インドとロシアの組織を標的にしています。この攻撃では、1,600件以上のソーシャルエンジニアリングメッセージが様々なセクターに送られ、これまで文書化されていないマルウェア（ABCDoorバックドアやValleyRATなど）が配布されました。

{{< ad-banner >}}

ABCDoorバックドアはシルバーフォックスの兵器庫に新たに加わったもので、持続的なアクセスを確立しデータを窃取するように設計されています。既知のリモートアクセス型トロイの木馬であるValleyRATもこれらの攻撃で展開されています。このキャンペーンは、同グループが金融機関や政府機関に引き続き焦点を当て、タイムリーな税金テーマを利用して被害者の関与を高めていることを浮き彫りにしています。

セキュリティ研究者は、影響を受ける地域の組織に対し、メールフィルタリングとユーザー教育の強化を呼びかけています。攻撃はソーシャルエンジニアリングに大きく依存しているためです。キャンペーンに関連する侵害指標（IOC）を監視し、新しいバックドアやRATを検出するためにネットワーク防御を更新する必要があります。

{{< netrunner-insight >}}

SOCアナリストは、税金をテーマにしたフィッシングメールの監視を優先し、ABCDoorバックドアのネットワークシグネチャに対する行動検出ルールを展開すべきです。DevSecOpsチームは、エンドポイント検出および対応（EDR）ツールがValleyRATの永続化メカニズムを識別できるように調整し、シルバーフォックスに関連する既知のC2インフラストラクチャをブロックすることを検討する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を Dark Reading で読む ›](https://www.darkreading.com/endpoint-security/silver-fox-tax-themed-attacks-india-russia)**
