---
title: "0-день MiniPlasma в Windows позволяет повысить привилегии до SYSTEM на полностью обновленных системах"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "ru"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "Исследователь безопасности Chaotic Eclipse опубликовал PoC для MiniPlasma — нулевого дня в мини-фильтре драйвера облачных файлов Windows (cldflt.sys), предоставляющего привилегии SYSTEM на полностью обновленных системах."
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Мини-фильтр драйвера облачных файлов Windows (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Исследователь безопасности Chaotic Eclipse опубликовал PoC для MiniPlasma — нулевого дня в мини-фильтре драйвера облачных файлов Windows (cldflt.sys), предоставляющего привилегии SYSTEM на полностью обновленных системах.

{{< cyber-report severity="High" source="The Hacker News" target="Мини-фильтр драйвера облачных файлов Windows (cldflt.sys)" >}}

Chaotic Eclipse, исследователь безопасности, стоящий за недавно раскрытыми уязвимостями Windows YellowKey и GreenPlasma, опубликовал доказательство концепции (PoC) для нулевого дня повышения привилегий в Windows, который позволяет злоумышленникам получить привилегии SYSTEM на полностью обновленных системах Windows. Уязвимость, получившая кодовое название MiniPlasma, затрагивает "cldflt.sys" — мини-фильтр драйвера облачных файлов Windows.

{{< ad-banner >}}

Эта ошибка позволяет злоумышленнику с ограниченным доступом пользователя повысить привилегии до SYSTEM, что потенциально может привести к полной компрометации системы. Являясь нулевым днем, официальное исправление в настоящее время недоступно, что оставляет полностью обновленные системы уязвимыми для эксплуатации в случае использования PoC.

Организациям следует отслеживать необычное поведение драйвера cldflt.sys и рассмотреть дополнительные меры защиты, такие как ограничение доступа к функции облачных файлов или применение временных мер до выхода патча.

{{< netrunner-insight >}}

Аналитикам SOC следует уделить первоочередное внимание мониторингу попыток эксплуатации, нацеленных на cldflt.sys, так как PoC снижает барьер для атакующих. Командам DevSecOps следует пересмотреть настройки безопасности образов Windows и рассмотреть возможность отключения мини-фильтра драйвера облачных файлов, если он не требуется, в ожидании официального исправления от Microsoft.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
