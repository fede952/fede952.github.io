---
title: "Ghostwriter、Prometheusを装ったフィッシングでウクライナ政府を標的に"
date: "2026-05-25T11:07:58Z"
original_date: "2026-05-22T16:20:32"
lang: "ja"
translationKey: "ghostwriter-targets-ukraine-government-with-prometheus-phishing-lures"
author: "NewsBot (Validated by Federico Sella)"
description: "ベラルーシに連携する脅威アクターGhostwriterが、Prometheusをテーマにしたフィッシングメールを使用してウクライナ政府機関を標的にし、侵害されたアカウントを介してマルウェアを展開している。"
original_url: "https://thehackernews.com/2026/05/ghostwriter-targets-ukraine-government.html"
source: "The Hacker News"
severity: "High"
target: "ウクライナ政府機関"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ベラルーシに連携する脅威アクターGhostwriterが、Prometheusをテーマにしたフィッシングメールを使用してウクライナ政府機関を標的にし、侵害されたアカウントを介してマルウェアを展開している。

{{< cyber-report severity="High" source="The Hacker News" target="ウクライナ政府機関" >}}

ベラルーシに連携する脅威アクターGhostwriter（別名UAC-0057およびUNC1151）が、ウクライナのオンライン学習プラットフォームPrometheusに関連する誘い文句を使ったフィッシングメールで、ウクライナの政府機関を標的にしていることが確認された。ウクライナのコンピュータ緊急対応チーム（CERT-UA）は、この攻撃が侵害されたアカウントから政府機関に悪意のあるメールを送信するものであると報告している。

{{< ad-banner >}}

フィッシングメールはPrometheusを装ったマルウェアを配信するように設計されており、おそらく諜報活動や妨害工作のための初期アクセスベクトルとして機能する。Ghostwriterは歴史的にベラルーシの利益に沿った情報工作やサイバー諜報活動と関連しており、今回のキャンペーンは進行中の紛争の中でウクライナの標的に焦点を当て続けている。

ウクライナの組織、特に政府機関は、Prometheusや他の教育プラットフォームを参照するフィッシングメールに警戒すべきである。CERT-UAは、送信者の身元を確認し、信頼できないソースからのリンクをクリックしたり添付ファイルを開いたりしないことを推奨している。多要素認証を導入し、異常なアカウント活動を監視することで、侵害のリスクを軽減できる。

{{< netrunner-insight >}}

このキャンペーンは、特に紛争地域の政府機関におけるメールセキュリティ管理の重要性を強調している。SOCアナリストは、Prometheusのようなローカルプラットフォームを装ったフィッシングの監視を優先すべきであり、DevSecOpsチームはスプーフィングリスクを低減するために厳格なメール認証（DMARC、DKIM、SPF）を実施すべきである。さらに、初期ベクトルとして侵害されたアカウントが使用されていることは、迅速なインシデント対応と資格情報のローテーションの必要性を示している。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/05/ghostwriter-targets-ukraine-government.html)**
