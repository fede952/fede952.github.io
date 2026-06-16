---
title: "Группа вымогателей DragonForce использует ретрансляторы Microsoft Teams для сокрытия трафика C2"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "ru"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Группа вымогателей DragonForce развертывает кастомное вредоносное ПО 'Backdoor.Turn' для сокрытия трафика управления и контроля (C2) в инфраструктуре ретрансляции Microsoft Teams."
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "инфраструктура ретрансляции Microsoft Teams"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Группа вымогателей DragonForce развертывает кастомное вредоносное ПО 'Backdoor.Turn' для сокрытия трафика управления и контроля (C2) в инфраструктуре ретрансляции Microsoft Teams.

{{< cyber-report severity="High" source="BleepingComputer" target="инфраструктура ретрансляции Microsoft Teams" >}}

Группа вымогателей DragonForce была замечена в использовании кастомного вредоносного ПО под названием 'Backdoor.Turn' для сокрытия трафика управления и контроля (C2) в инфраструктуре ретрансляции Microsoft Teams. Эта техника позволяет злоумышленникам смешивать вредоносные коммуникации с легитимным трафиком Teams, что затрудняет обнаружение для защитников сети.

{{< ad-banner >}}

Злоупотребляя ретрансляторами Microsoft Teams, группа вымогателей может обходить традиционные средства сетевой безопасности, которые могут не проверять трафик к доверенным сервисам. Вредоносное ПО, вероятно, использует API или протоколы Teams для туннелирования данных C2, обходя сигнатурное обнаружение и обеспечивая постоянный доступ к скомпрометированным сетям.

Организациям, использующим Microsoft Teams, следует отслеживать необычные исходящие паттерны трафика к конечным точкам Teams и рассмотреть возможность внедрения дополнительной проверки зашифрованных туннелей. Этот инцидент подчеркивает растущую тенденцию групп вымогателей использовать техники living-off-the-land и злоупотребления доверенными сервисами для уклонения от обнаружения.

{{< netrunner-insight >}}

Для аналитиков SOC это подчеркивает необходимость установления базового уровня нормального трафика Teams и оповещения об аномалиях, таких как неожиданные объемы данных или подключения к нестандартным конечным точкам Teams. Командам DevSecOps следует пересмотреть разрешения на интеграцию Teams и ограничить ненужный доступ к API, чтобы уменьшить поверхность атаки для злоупотребления ретрансляцией.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
