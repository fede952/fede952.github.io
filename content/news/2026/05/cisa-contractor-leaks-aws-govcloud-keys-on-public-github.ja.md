---
title: "CISA請負業者がAWS GovCloudキーを公開GitHubに意図的に漏洩"
date: "2026-05-23T09:02:01Z"
original_date: "2026-05-22T16:34:24"
lang: "ja"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-public-github"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA請負業者がAWS GovCloudキーや機密情報を公開GitHubアカウントに意図的に公開した後、議員らが説明を要求。CISAは侵害の封じ込めに苦慮している。"
original_url: "https://krebsonsecurity.com/2026/05/lawmakers-demand-answers-as-cisa-tries-to-contain-data-leak/"
source: "Krebs on Security"
severity: "High"
target: "CISA AWS GovCloud環境"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA請負業者がAWS GovCloudキーや機密情報を公開GitHubアカウントに意図的に公開した後、議員らが説明を要求。CISAは侵害の封じ込めに苦慮している。

{{< cyber-report severity="High" source="Krebs on Security" target="CISA AWS GovCloud環境" >}}

上下両院の議員らは、KrebsOnSecurityがCISAの請負業者がAWS GovCloudキーと膨大な量のその他の機密情報を公開GitHubアカウントに意図的に公開したと報じた後、米国サイバーセキュリティ・インフラストラクチャセキュリティ庁（CISA）に説明を求めている。機密の認証情報やデータを暴露したこの侵害は、同庁のセキュリティ慣行を懸念する議員らから緊急の質問を引き起こした。

{{< ad-banner >}}

CISAは現在、侵害の封じ込めと漏洩した認証情報の無効化に苦慮している。この事件は、機密システムへの請負業者のアクセスに伴うリスクと、特に政府機関が使用するクラウド環境のセキュリティ確保の課題を浮き彫りにしている。同庁は、暴露されたデータの全容や関与した請負業者の身元をまだ明らかにしていない。

{{< netrunner-insight >}}

この事件は、クラウド環境における請負業者の活動に対する厳格なアクセス制御と継続的な監視の重要性を強調している。SOCアナリストは、漏洩した認証情報を監査するためにGitHubリポジトリを優先的に調査し、自動シークレットスキャンツールを実装すべきである。DevSecOpsチームは、最小権限アクセスを徹底し、露出の疑いがあれば直ちにすべてのクラウドキーをローテーションしなければならない。

{{< /netrunner-insight >}}

---

**[完全な記事を Krebs on Security で読む ›](https://krebsonsecurity.com/2026/05/lawmakers-demand-answers-as-cisa-tries-to-contain-data-leak/)**
