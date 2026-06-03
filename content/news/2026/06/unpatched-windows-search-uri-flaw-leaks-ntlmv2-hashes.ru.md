---
title: "Неисправленная уязвимость обработчика URI Windows Search раскрывает хеши NTLMv2"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "ru"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Исследователи раскрыли неисправленную уязвимость в обработчике URI search: Windows, которая может раскрывать хеши NTLMv2, аналогично уязвимости CVE-2026-33829 в инструменте Snipping Tool."
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Обработчик URI search: Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Исследователи раскрыли неисправленную уязвимость в обработчике URI search: Windows, которая может раскрывать хеши NTLMv2, аналогично уязвимости CVE-2026-33829 в инструменте Snipping Tool.

{{< cyber-report severity="High" source="The Hacker News" target="Обработчик URI search: Windows" >}}

Исследователи в области кибербезопасности из Huntress раскрыли подробности неисправленной уязвимости в обработчике URI search: Windows, которая может позволить злоумышленникам украсть хеши NTLMv2. Проблема напоминает CVE-2026-33829, уязвимость подмены в обработчике URI ms-screensketch: инструмента Snipping Tool Windows, которая также раскрывала хеши NTLM.

{{< ad-banner >}}

Недавно выявленная ошибка находится в схеме URI search:, используемой для запуска поисковых запросов Windows. Создав вредоносную ссылку или файл, который активирует обработчик URI search:, злоумышленник может заставить целевую систему аутентифицироваться на удаленном сервере, тем самым раскрыв хеш NTLMv2 пользователя. Этот хеш затем может быть взломан офлайн или использован в атаках ретрансляции.

На дату публикации официальный патч от Microsoft не выпущен. Организациям рекомендуется следить за обновлениями и рассмотреть возможность блокировки обработчика URI search: с помощью групповой политики или средств защиты конечных точек до появления исправления.

{{< netrunner-insight >}}

Это классический вектор ретрансляции NTLM, за которым аналитикам SOC следует следить в журналах аутентификации. Инженерам DevSecOps следует немедленно проверить использование любых обработчиков URI в своих средах и рассмотреть возможность применения мер смягчения, таких как отключение NTLMv2 или принудительное использование подписи SMB. Пока Microsoft не выпустит патч, считайте, что URI search: является потенциальной точкой входа для кражи учетных данных.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
