---
title: "QuickFoxのサプライチェーン攻撃、トロイの木馬化されたインストーラを介してFDMTPバックドアを配布"
date: "2026-08-05T09:34:12Z"
original_date: "2026-08-05T05:47:19"
lang: "ja"
translationKey: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
slug: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
author: "NewsBot (Validated by Federico Sella)"
description: "QuickFox VPNを標的とした長期にわたるサプライチェーン攻撃が、インストーラをトロイの木馬化し、2025年8月以降、海外の中国人ユーザーを標的にFDMTPバックドアを展開しています。"
original_url: "https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html"
source: "The Hacker News"
severity: "High"
target: "QuickFox VPNユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuickFox VPNを標的とした長期にわたるサプライチェーン攻撃が、インストーラをトロイの木馬化し、2025年8月以降、海外の中国人ユーザーを標的にFDMTPバックドアを展開しています。

{{< cyber-report severity="High" source="The Hacker News" target="QuickFox VPNユーザー" >}}

Fortinet FortiGuard Labsは、海外の中国人ユーザーの間で人気のあるVPNおよびネットワーク高速化ツールであるQuickFoxを標的とした、長期間にわたるサプライチェーン攻撃を公開しました。この攻撃は少なくとも2025年8月から活動しており、アプリケーションのWindowsインストーラのトロイの木馬化されたバージョンが、FDMTPというバックドアを配布します。

{{< ad-banner >}}

トロイの木馬化されたインストーラは、公式または信頼できるチャネルを通じて配布され、ソフトウェアサプライチェーンの整合性を損なっています。実行されると、FDMTPは攻撃者に被害者のシステムへのリモートアクセスと制御を提供し、データ盗難、監視、またはさらなるマルウェア展開につながる可能性があります。

このインシデントは、ニッチでありながら信頼されているツール、特に特定のコミュニティにサービスを提供するツールに対するサプライチェーン攻撃のリスクが高まっていることを浮き彫りにしています。QuickFoxを使用している組織や個人は、インストールの整合性を検証し、FDMTPに関連する侵害の指標を監視する必要があります。

{{< netrunner-insight >}}

この攻撃は、一見評判の良いベンダーのツールであっても、堅牢なソフトウェア整合性検証の必要性を強調しています。SOCアナリストは、FDMTPの指標を探し、VPNクライアントからの異常なネットワーク接続を監視する必要があります。DevSecOpsチームは、ソフトウェア展開パイプラインでコード署名とハッシュ検証を強制し、このようなサプライチェーンリスクを軽減する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html)**
