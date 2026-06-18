---
title: "CISA предупреждает о критическом обходе аутентификации в Rockwell FactoryTalk Analytics PavilionX"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "ru"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA сообщает об уязвимости CVE-2025-14272, затрагивающей Rockwell Automation FactoryTalk Analytics PavilionX <7.01, позволяющей неавторизованные привилегированные операции в средах критического производства."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA сообщает об уязвимости CVE-2025-14272, затрагивающей Rockwell Automation FactoryTalk Analytics PavilionX <7.01, позволяющей неавторизованные привилегированные операции в средах критического производства.

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISA опубликовала рекомендацию (ICSA-26-167-01) относительно уязвимости отсутствия авторизации в Rockwell Automation FactoryTalk Analytics PavilionX. Ошибка, отслеживаемая как CVE-2025-14272, затрагивает версии до 7.01 и позволяет неавторизованному злоумышленнику выполнять привилегированные операции, такие как управление пользователями и ролями.

{{< ad-banner >}}

Уязвимость возникает из-за неправильной проверки авторизации в конечных точках API. Успешная эксплуатация может привести к полному административному контролю над затронутой системой. Rockwell Automation выпустила версию 7.01 для устранения проблемы, и пользователям настоятельно рекомендуется немедленно обновиться.

Учитывая развертывание этого продукта в критически важных производственных секторах по всему миру, риск нарушения работы или компрометации данных значителен. Организациям следует уделить первоочередное внимание установке исправлений и пересмотреть контроль доступа для снижения потенциальной эксплуатации.

{{< netrunner-insight >}}

Это классический обход авторизации, который следует рассматривать как исправление высокого приоритета. Аналитикам SOC следует отслеживать аномальные вызовы API или повышения привилегий в средах PavilionX. Команды DevSecOps должны убедиться, что версия 7.01 развернута, а сегментация сети ограничивает доступ к этим конечным точкам.

{{< /netrunner-insight >}}

---

**[Читать полную статью на CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
