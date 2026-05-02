---
title: "Уязвимости в ABB Ability Symphony Plus Engineering позволяют выполнять код"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "ru"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA предупреждает об уязвимостях в ABB Ability Symphony Plus Engineering из-за устаревшей PostgreSQL, что позволяет выполнять произвольный код на затронутых системах."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA предупреждает об уязвимостях в ABB Ability Symphony Plus Engineering из-за устаревшей PostgreSQL, что позволяет выполнять произвольный код на затронутых системах.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

CISA опубликовала предупреждение (ICSA-26-120-06), описывающее множественные уязвимости в ABB Ability Symphony Plus Engineering, вызванные использованием PostgreSQL версии 13.11 и более ранних. Недостатки включают целочисленное переполнение, SQL-инъекцию, состояние гонки TOCTOU и ошибки сброса привилегий, что может позволить аутентифицированному злоумышленнику выполнить произвольный код в системе.

{{< ad-banner >}}

Затронутые версии охватывают Ability Symphony Plus от 2.2 до 2.4 SP2 RU1. Уязвимости особенно опасны с учетом развертывания продукта в критически важных секторах инфраструктуры, таких как химическая промышленность, критическое производство, энергетика, водоснабжение и водоотведение по всему миру.

Наиболее заметная уязвимость, CVE-2023-5869, имеет оценку CVSS 8.8 и связана с целочисленным переполнением, которое может быть вызвано специально созданными данными от аутентифицированного пользователя PostgreSQL. Успешная эксплуатация может привести к полной компрометации системы, что подчеркивает необходимость немедленного исправления.

{{< netrunner-insight >}}

Это предупреждение подчеркивает риск использования устаревших зависимостей в средах OT. Аналитикам SOC следует уделить первоочередное внимание обнаружению экземпляров ABB Symphony Plus и обеспечить обновление PostgreSQL до версии выше 13.11. Команды DevSecOps должны интегрировать сканирование зависимостей в конвейеры CI/CD для систем промышленного управления, чтобы выявлять такие унаследованные уязвимости на ранних этапах.

{{< /netrunner-insight >}}

---

**[Читать полную статью на CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
