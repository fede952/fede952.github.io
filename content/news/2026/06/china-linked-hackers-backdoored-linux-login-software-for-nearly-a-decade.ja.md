---
title: "中国関連のハッカーがLinuxログインソフトウェアを10年近くバックドア化"
date: "2026-06-15T13:04:59Z"
original_date: "2026-06-12T18:17:55"
lang: "ja"
translationKey: "china-linked-hackers-backdoored-linux-login-software-for-nearly-a-decade"
author: "NewsBot (Validated by Federico Sella)"
description: "Velvet Antとして知られる中国系グループがPAMとOpenSSHコンポーネントを侵害し、ほぼ10年間検出されずにLinuxログインシステムに潜伏していた。"
original_url: "https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html"
source: "The Hacker News"
severity: "High"
target: "Linuxログインシステム（PAM、OpenSSH）"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Velvet Antとして知られる中国系グループがPAMとOpenSSHコンポーネントを侵害し、ほぼ10年間検出されずにLinuxログインシステムに潜伏していた。

{{< cyber-report severity="High" source="The Hacker News" target="Linuxログインシステム（PAM、OpenSSH）" >}}

Velvet Antとして追跡される中国関連の脅威アクターが、PAM（Pluggable Authentication Modules）やOpenSSHを含むLinuxの主要なログインコンポーネントをバックドア化し、ほぼ10年にわたり持続的なアクセスを維持していたことが判明した。このグループは、認証スタックの深部にバックドアを埋め込み、標準的なクリーンアップ手順に耐性を持たせたネットワークを標的にした。

{{< ad-banner >}}

セキュリティ企業Sygniaによると、攻撃者はログインソフトウェアへの信頼を悪用して検出を回避した。ユーザーアクセスを制御するメカニズムそのものを改変することで、システムアップデートや定期的なセキュリティスキャンを生き延びる足場を確保した。このキャンペーンは、国家支援グループが基盤インフラを標的にする際の高度化の高まりを示している。

この侵害は、組織が通常のエンドポイント検出を超えて重要なシステムコンポーネントの整合性を監視する必要性を強調している。防御側は、PAMモジュールやSSHバイナリのファイル整合性監視、および認証ログの行動分析を検討し、バックドア化されたログインプロセスを示す異常を特定すべきである。

{{< netrunner-insight >}}

SOCアナリストやDevSecOpsチームにとって、これは攻撃者が認証レイヤー自体を標的にしているという厳粛な警告である。PAMやSSHバイナリに対するランタイム整合性チェックを実装し、改ざんを検出するためにカーネルレベルの監視を検討せよ。また、インシデント対応プレイブックの一環として、SSHキーベースの認証とPAM設定の変更をレビューすること。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)**
