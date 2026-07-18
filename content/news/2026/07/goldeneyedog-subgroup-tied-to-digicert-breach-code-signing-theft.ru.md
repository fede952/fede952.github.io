---
title: "Подгруппа GoldenEyeDog связана с взломом DigiCert и кражей подписей кода"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "ru"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "Исследователи связывают инцидент с DigiCert в апреле 2026 года с CylindricalCanine, подгруппой китайской киберпреступной группы GoldenEyeDog, известной нацеленностью на секторы азартных игр и гейминга."
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "инфраструктура подписи кода DigiCert"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Исследователи связывают инцидент с DigiCert в апреле 2026 года с CylindricalCanine, подгруппой китайской киберпреступной группы GoldenEyeDog, известной нацеленностью на секторы азартных игр и гейминга.

{{< cyber-report severity="High" source="The Hacker News" target="инфраструктура подписи кода DigiCert" >}}

Исследователи в области кибербезопасности связали инцидент безопасности в DigiCert в апреле 2026 года с кластером угроз, названным CylindricalCanine. Группа описывается как подгруппа GoldenEyeDog (также известной как APT-Q-27, Dragon Breath и Miuuti Group), китайской киберпреступной группы, которая исторически нацелена на секторы азартных игр и гейминга.

{{< ad-banner >}}

Взлом включал кражу сертификатов подписи кода, что может позволить злоумышленникам подписывать вредоносное ПО легитимными учетными данными, обходя средства безопасности. Expel поделилась техническими деталями события, подчеркнув сложный характер операции.

Организациям, использующим сертификаты, выданные DigiCert, следует проверить свои инвентаризации сертификатов и отслеживать любое несанкционированное использование. Инцидент подчеркивает риски, связанные с атаками на цепочки поставок, нацеленными на доверенные центры сертификации.

{{< netrunner-insight >}}

Для аналитиков SOC: приоритетно отслеживайте аномалии в подписи кода и неожиданное использование сертификатов. Командам DevSecOps следует внедрить строгое управление жизненным циклом сертификатов и рассмотреть использование краткосрочных сертификатов для ограничения ущерба от кражи.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
