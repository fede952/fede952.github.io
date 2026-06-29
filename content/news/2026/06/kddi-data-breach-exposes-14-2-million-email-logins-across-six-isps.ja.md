---
title: "KDDIのデータ漏洩、6つのISPで1420万件のメールログイン情報が流出"
date: "2026-06-29T11:56:07Z"
original_date: "2026-06-28T14:13:46"
lang: "ja"
translationKey: "kddi-data-breach-exposes-14-2-million-email-logins-across-six-isps"
author: "NewsBot (Validated by Federico Sella)"
description: "日本の通信事業者KDDIが、他の5つのISPに影響を与えるメールシステムの侵害を開示。最大1420万件のユーザー認証情報が漏洩した可能性がある。"
original_url: "https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/"
source: "BleepingComputer"
severity: "High"
target: "日本のISPメールシステム"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

日本の通信事業者KDDIが、他の5つのISPに影響を与えるメールシステムの侵害を開示。最大1420万件のユーザー認証情報が漏洩した可能性がある。

{{< cyber-report severity="High" source="BleepingComputer" target="日本のISPメールシステム" >}}

日本の通信事業者KDDI株式会社は、国内の他の5つのインターネットサービスプロバイダ（ISP）が使用するメールシステムの1つに脅威アクターがアクセスしたデータ漏洩を開示した。この侵害により、最大1420万件のメールログイン情報が流出し、複数のプロバイダの多数のユーザーに影響を与える可能性がある。

{{< ad-banner >}}

侵害されたシステムは、複数のISPのバックエンドとして機能するKDDIのメールインフラの一部である。侵入の正確な方法は明らかにされていないが、このインシデントは、単一障害点が複数の組織に連鎖的に影響を及ぼす可能性がある共有サービスプロバイダアーキテクチャに内在するリスクを浮き彫りにしている。

KDDIは影響を受けたISPに通知し、侵害の封じ込めに取り組んでいる。ユーザーはパスワードを変更し、利用可能な場合は多要素認証を有効にするよう推奨されている。このインシデントは、共有インフラコンポーネントの堅牢なセグメンテーションと監視の必要性を強調している。

{{< netrunner-insight >}}

この侵害は、ISPエコシステムにおけるサプライチェーンリスクの典型的な例です。SOCアナリストは、メールシステムから他の重要な資産への横方向の移動を監視することを優先すべきであり、DevSecOpsチームは共有バックエンドサービスに対して厳格なネットワークセグメンテーションと最小権限アクセスを実施する必要があります。今後数週間で、これらの流出したアカウントを標的にしたクレデンシャルスタッフィング攻撃が予想されます。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/)**
