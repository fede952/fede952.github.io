---
title: "フィッシング攻撃がイタリアのエネルギー規制機関ARERAを模倣しデータを窃取"
date: "2026-08-17T07:49:27Z"
original_date: "2026-08-05T13:20:37"
lang: "ja"
translationKey: "phishing-attack-mimics-italian-energy-regulator-arera-to-steal-data"
slug: "phishing-attack-mimics-italian-energy-regulator-arera-to-steal-data"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGIDは、ARERAを偽装した不正サイトを警告しています。このサイトは、水道社会ボーナスを餌に、タイポスクワッティングを通じて個人情報や財務情報を収集します。"
original_url: "https://cert-agid.gov.it/news/phishing-ai-danni-di-arera-utilizza-il-tema-bonus-sociale-idrico/"
source: "CERT-AgID"
severity: "Medium"
target: "イタリア国民およびARERA利用者"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGIDは、ARERAを偽装した不正サイトを警告しています。このサイトは、水道社会ボーナスを餌に、タイポスクワッティングを通じて個人情報や財務情報を収集します。

{{< cyber-report severity="Medium" source="CERT-AgID" target="イタリア国民およびARERA利用者" >}}

CERT-AGIDは、イタリアのエネルギー・ネットワーク・環境規制機関であるARERAの名称とロゴを模倣した不正ウェブサイトを特定しました。このサイトは、経済的または身体的困難にある家庭の水道供給コストを削減するための正当な措置である「水道社会ボーナス」に関連する返金を約束して被害者を誘惑します。

{{< ad-banner >}}

このフィッシングキャンペーンは、タイポスクワッティング技術を用いて偽ドメインの信頼性を高め、正規のARERAウェブサイトとほぼ同一に見せかけています。目的は、ユーザーを騙して個人情報や財務情報を開示させ、それを個人情報の盗用や金融詐欺に悪用することです。

このインシデントは、よく知られた政府機関や規制機関を悪用するフィッシングキャンペーンの継続的な脅威を浮き彫りにしています。ユーザーは、返金やボーナスを提供すると主張する通信の信頼性を確認し、不審なメールやメッセージ内のリンクをクリックしないようにすることをお勧めします。

{{< netrunner-insight >}}

SOCアナリストにとって、このキャンペーンは、重要な公共サービスに関連するタイポスクワッティングドメインを監視する必要性を示しています。DNSフィルタリングを実装し、公式チャネルの確認についてユーザーを教育することで、このような脅威を軽減できます。DevSecOpsチームは、類似ドメインを追跡する脅威インテリジェンスフィードを統合して、プロアクティブにアクセスをブロックすることを検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を CERT-AgID で読む ›](https://cert-agid.gov.it/news/phishing-ai-danni-di-arera-utilizza-il-tema-bonus-sociale-idrico/)**
