---
title: "DragonForce использует ретрансляторы Microsoft Teams для маскировки трафика Backdoor.Turn C2"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "ru"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Группа вымогателей DragonForce развертывает собственную Go-основанную RAT Backdoor.Turn, скрывая трафик C2 в ретрансляторах Microsoft Teams, нацелившись на крупную американскую сервисную компанию."
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "Крупная американская сервисная компания"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Группа вымогателей DragonForce развертывает собственную Go-основанную RAT Backdoor.Turn, скрывая трафик C2 в ретрансляторах Microsoft Teams, нацелившись на крупную американскую сервисную компанию.

{{< cyber-report severity="High" source="The Hacker News" target="Крупная американская сервисная компания" >}}

Угрозы, связанные с группой вымогателей DragonForce, были замечены в использовании собственного Go-основанного трояна удаленного доступа (RAT) под названием Backdoor.Turn для сокрытия трафика управления и контроля (C2) внутри инфраструктуры ретрансляторов Microsoft Teams. Бэкдор был развернут против крупной американской сервисной компании, согласно данным Broadcom-owned Symantec и Carbon Black.

{{< ad-banner >}}

Используя легитимные ретрансляторы Microsoft Teams, злоумышленники могут смешивать вредоносный трафик с обычными бизнес-коммуникациями, что затрудняет обнаружение для сетевых защитников. Go-основанная RAT предоставляет злоумышленникам постоянный доступ и возможность выполнять команды, похищать данные и развертывать дополнительные полезные нагрузки.

Этот метод подчеркивает эволюцию тактик групп вымогателей для обхода традиционных инструментов мониторинга сети. Организации, использующие Microsoft Teams, должны пересмотреть свои конфигурации безопасности и отслеживать аномальные паттерны трафика ретрансляторов.

{{< netrunner-insight >}}

Аналитикам SOC следует отслеживать необычный трафик ретрансляторов Microsoft Teams, особенно с нестандартных конечных точек или в нерабочее время. Команды DevSecOps должны применять строгий список разрешенных приложений и проверять трафик Teams на наличие зашифрованных туннелей, которые могут указывать на связь C2. Эта атака подчеркивает необходимость принципов нулевого доверия даже для доверенных платформ совместной работы.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
