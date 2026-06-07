---
title: "Червь Miasma поразил 73 репозитория Microsoft GitHub в атаке на цепочку поставок"
date: "2026-06-07T09:57:27Z"
original_date: "2026-06-06T06:58:04"
lang: "ru"
translationKey: "miasma-worm-hits-73-microsoft-github-repos-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Репозитории Microsoft GitHub в Azure, Azure-Samples, Microsoft и MicrosoftDocs были скомпрометированы самореплицирующимся червем Miasma, затронув 73 репозитория."
original_url: "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
source: "The Hacker News"
severity: "High"
target: "репозитории Microsoft GitHub"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Репозитории Microsoft GitHub в Azure, Azure-Samples, Microsoft и MicrosoftDocs были скомпрометированы самореплицирующимся червем Miasma, затронув 73 репозитория.

{{< cyber-report severity="High" source="The Hacker News" target="репозитории Microsoft GitHub" >}}

Кампания самореплицирующейся атаки на цепочку поставок Miasma расширилась, нацелившись на репозитории Microsoft GitHub, скомпрометировав 73 репозитория в четырех организациях: Azure, Azure-Samples, Microsoft и MicrosoftDocs. Инцидент был сообщен OpenSourceMalware, что побудило GitHub отключить доступ к затронутым репозиториям для сдерживания распространения.

{{< ad-banner >}}

Эта атака подчеркивает растущую угрозу самореплицирующегося вредоносного ПО в цепочках поставок программного обеспечения. Компрометируя доверенные репозитории, злоумышленники могут внедрять вредоносный код в проекты, зависящие от этих источников, потенциально затрагивая широкий круг пользователей и организаций.

Хотя конкретные технические детали компрометации остаются нераскрытыми, инцидент подчеркивает необходимость усиления мер безопасности в конвейерах CI/CD и управлении репозиториями. Организациям следует пересмотреть свои зависимости от репозиториев Microsoft GitHub и отслеживать любую аномальную активность.

{{< netrunner-insight >}}

Для аналитиков SOC: приоритетно отслеживайте необычные коммиты или шаблоны доступа в ваших собственных организациях GitHub. Команды DevSecOps должны внедрять строгие правила защиты веток, требовать подписанные коммиты и реализовать автоматическое сканирование на предмет самореплицирующегося вредоносного ПО в конвейерах CI/CD. Этот инцидент является ярким напоминанием о том, что даже крупные вендоры, такие как Microsoft, не застрахованы от атак на цепочку поставок.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)**
