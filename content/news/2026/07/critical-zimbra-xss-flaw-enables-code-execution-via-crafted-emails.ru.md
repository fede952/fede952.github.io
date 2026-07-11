---
title: "Критическая XSS-уязвимость Zimbra позволяет выполнять код через специально созданные письма"
date: "2026-07-11T08:44:58Z"
original_date: "2026-07-11T06:45:55"
lang: "ru"
translationKey: "critical-zimbra-xss-flaw-enables-code-execution-via-crafted-emails"
slug: "critical-zimbra-xss-flaw-enables-code-execution-via-crafted-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "Zimbra призывает обновить критическую уязвимость хранимого XSS в Classic Web Client, которая позволяет выполнять произвольный код через специально созданные письма."
original_url: "https://thehackernews.com/2026/07/critical-zimbra-flaw-could-let-crafted_0483473395.html"
source: "The Hacker News"
severity: "Critical"
target: "Zimbra Classic Web Client"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Zimbra призывает обновить критическую уязвимость хранимого XSS в Classic Web Client, которая позволяет выполнять произвольный код через специально созданные письма.

{{< cyber-report severity="Critical" source="The Hacker News" target="Zimbra Classic Web Client" >}}

Zimbra раскрыла критическую уязвимость безопасности в своем Classic Web Client, которая может позволить злоумышленникам выполнять произвольный код через хранимый межсайтовый скриптинг (XSS). Уязвимость позволяет специально созданным письмам запускать вредоносные сценарии в сеансе пользователя, что потенциально может привести к полной компрометации почтового клиента и связанных данных.

{{< ad-banner >}}

Уязвимость, которой еще не присвоен идентификатор CVE, затрагивает компонент Classic Web Client. Zimbra настоятельно рекомендует всем клиентам немедленно применить доступные обновления для снижения риска. Оценка CVSS не предоставлена, но возможность выполнения кода через доставку электронной почты делает эту проблему высокоприоритетной для организаций, использующих Zimbra.

Будучи уязвимостью хранимого XSS, атака не требует взаимодействия с пользователем, кроме открытия вредоносного письма. Это повышает вероятность эксплуатации, особенно в средах, где фильтрация электронной почты может не обнаружить вредоносную нагрузку. Администраторам следует уделить первоочередное внимание установке исправлений и пересмотреть средства контроля безопасности электронной почты.

{{< netrunner-insight >}}

Для аналитиков SOC это классический хранимый XSS, обходящий традиционные почтовые фильтры. Командам DevSecOps следует немедленно исправить Zimbra Classic Web Client и рассмотреть возможность развертывания межсетевых экранов веб-приложений с правилами XSS. Отслеживайте необычное выполнение скриптов в сеансах пользователей как сигнал обнаружения.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/critical-zimbra-flaw-could-let-crafted_0483473395.html)**
