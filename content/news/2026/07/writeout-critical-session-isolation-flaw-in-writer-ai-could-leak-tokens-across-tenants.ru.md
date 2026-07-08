---
title: "WriteOut: Критическая ошибка изоляции сессий в Writer AI может привести к утечке токенов между арендаторами"
date: "2026-07-08T09:23:55Z"
original_date: "2026-07-07T13:27:09"
lang: "ru"
translationKey: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
slug: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
author: "NewsBot (Validated by Federico Sella)"
description: "Уязвимость в Writer AI, получившая кодовое название WriteOut, позволяет одним кликом вызвать утечку токенов сессий между арендаторами. Ошибка уже исправлена."
original_url: "https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html"
source: "The Hacker News"
severity: "Critical"
target: "корпоративная платформа Writer AI"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Уязвимость в Writer AI, получившая кодовое название WriteOut, позволяет одним кликом вызвать утечку токенов сессий между арендаторами. Ошибка уже исправлена.

{{< cyber-report severity="Critical" source="The Hacker News" target="корпоративная платформа Writer AI" >}}

Исследователи в области кибербезопасности из Sand Security раскрыли критическую уязвимость изоляции сессий в Writer, корпоративной платформе генеративного ИИ. Ошибка, названная WriteOut, может позволить злоумышленнику получить токены сессий между арендаторами, что приведет к компрометации нескольких арендаторов одним кликом.

{{< ad-banner >}}

Уязвимость связана с неправильной изоляцией сессий в функции предварительного просмотра агента, что позволяет внешнему злоумышленнику перейти от отсутствия доступа к полному захвату любого арендатора Writer AI. Writer уже исправил проблему, но это открытие подчеркивает риски многопользовательских платформ ИИ.

Организации, использующие Writer AI, должны убедиться, что последние исправления установлены, и проверить конфигурации управления сессиями. Уязвимость WriteOut служит напоминанием о необходимости приоритизации изоляции арендаторов в облачных сервисах ИИ.

{{< netrunner-insight >}}

Для аналитиков SOC: отслеживайте аномальное использование токенов сессий и паттерны межарендаторного доступа в логах Writer AI. Командам DevSecOps следует обеспечить строгую изоляцию сессий и рассмотреть возможность внедрения дополнительных проверок границ арендаторов в многопользовательских развертываниях ИИ.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html)**
