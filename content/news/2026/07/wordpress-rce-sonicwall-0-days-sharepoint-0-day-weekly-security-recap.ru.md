---
title: "WordPress RCE, SonicWall 0-Day, SharePoint 0-Day: еженедельный обзор безопасности"
date: "2026-07-21T09:25:16Z"
original_date: "2026-07-20T13:32:26"
lang: "ru"
translationKey: "wordpress-rce-sonicwall-0-days-sharepoint-0-day-weekly-security-recap"
slug: "wordpress-rce-sonicwall-0-days-sharepoint-0-day-weekly-security-recap"
author: "NewsBot (Validated by Federico Sella)"
description: "На этой неделе угрозы включают WordPress RCE, SonicWall 0-day, атаки на AI-сервисы и SharePoint 0-day. Небольшие входные данные приводят к выполнению кода, потере памяти и краже ключей."
original_url: "https://thehackernews.com/2026/07/weekly-recap-wordpress-rce-sonicwall-0.html"
source: "The Hacker News"
severity: "Critical"
target: "WordPress, SonicWall, SharePoint, AI-сервисы"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

На этой неделе угрозы включают WordPress RCE, SonicWall 0-day, атаки на AI-сервисы и SharePoint 0-day. Небольшие входные данные приводят к выполнению кода, потере памяти и краже ключей.

{{< cyber-report severity="Critical" source="The Hacker News" target="WordPress, SonicWall, SharePoint, AI-сервисы" >}}

Ландшафт безопасности этой недели отмечен множеством критических уязвимостей, затрагивающих широко используемые платформы. Уязвимости удаленного выполнения кода (RCE) в WordPress, zero-day в SonicWall и 0-day в SharePoint активно эксплуатируются или были раскрыты. Злоумышленники используют простые векторы атак — открытые системы, слабую проверку ввода и устаревшие драйверы — для достижения выполнения кода, повреждения памяти и кражи учетных данных.

{{< ad-banner >}}

В дополнение к традиционным уязвимостям программного обеспечения, AI-сервисы подверглись атакам: противники используют поддельные промпты и публичные репозитории кода для доставки вредоносного ПО. Общая черта в том, что небольшие, казалось бы, безобидные входные данные могут привести к разрушительным последствиям, таким как отключение средств безопасности или эксфильтрация криптографических ключей.

Защитникам необходимо в первую очередь устанавливать исправления для этих уязвимостей, особенно тех, по которым известна активная эксплуатация. Уязвимости SonicWall и SharePoint особенно тревожны из-за их широкого распространения в корпоративных средах. Организациям также следует пересмотреть доступность AI-сервисов и внедрить строгую проверку ввода и контроль доступа.

{{< netrunner-insight >}}

Аналитикам SOC следует немедленно проверить индикаторы компрометации, связанные с этими уязвимостями, особенно необычные исходящие соединения или дампы памяти процессов. Командам DevSecOps необходимо внедрить принцип минимальных привилегий для API AI-сервисов и реализовать мониторинг безопасности во время выполнения для обнаружения аномального поведения, вызванного небольшими вредоносными входными данными.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/weekly-recap-wordpress-rce-sonicwall-0.html)**
