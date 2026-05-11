---
title: "Вторник исправлений от Microsoft, апрель 2026: 167 уязвимостей, zero-day в SharePoint, BlueHammer"
date: "2026-05-11T10:37:48Z"
original_date: "2026-04-14T21:47:59"
lang: "ru"
translationKey: "microsoft-patch-tuesday-april-2026-167-flaws-sharepoint-zero-day-bluehammer"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft исправляет 167 уязвимостей, включая zero-day в SharePoint и публично раскрытую ошибку в Windows Defender (BlueHammer). Google Chrome и Adobe Reader также получают исправления для активно эксплуатируемых уязвимостей."
original_url: "https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/"
source: "Krebs on Security"
severity: "Critical"
target: "Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft исправляет 167 уязвимостей, включая zero-day в SharePoint и публично раскрытую ошибку в Windows Defender (BlueHammer). Google Chrome и Adobe Reader также получают исправления для активно эксплуатируемых уязвимостей.

{{< cyber-report severity="Critical" source="Krebs on Security" target="Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader" >}}

Вторник исправлений от Microsoft за апрель 2026 года устраняет ошеломляющие 167 уязвимостей безопасности в Windows и связанном программном обеспечении. Среди наиболее критических — zero-day уязвимость в SharePoint Server, которая может привести к удаленному выполнению кода, хотя идентификатор CVE в отчете не указан. Кроме того, исправлена публично раскрытая слабость в Windows Defender, получившая название «BlueHammer».

{{< ad-banner >}}

Отдельно Google Chrome исправил свою четвертую zero-day уязвимость в 2026 году, продолжая тенденцию частых обновлений браузера. Adobe Reader также получил экстренное обновление для устранения активно эксплуатируемой ошибки, которая может привести к удаленному выполнению кода. Организациям следует уделить первоочередное внимание этим обновлениям из-за активной эксплуатации.

Огромный объем исправлений в этом месяце подчеркивает важность надежных процессов управления обновлениями. Командам безопасности следует сосредоточиться на zero-day в SharePoint и проблеме Windows Defender как на первоочередных задачах, а также обеспечить обновление Chrome и Adobe Reader во всей организации.

{{< netrunner-insight >}}

Для аналитиков SOC: приоритетно исправьте zero-day в SharePoint и ошибку BlueHammer в Windows Defender, так как они либо активно эксплуатируются, либо публично известны. Командам DevSecOps следует интегрировать эти обновления в свои конвейеры CI/CD и убедиться, что средства защиты конечных точек не нарушены из-за исправления Defender. Исправления для Chrome и Adobe Reader также требуют срочного внимания из-за их активной эксплуатации.

{{< /netrunner-insight >}}

---

**[Читать полную статью на Krebs on Security ›](https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/)**
