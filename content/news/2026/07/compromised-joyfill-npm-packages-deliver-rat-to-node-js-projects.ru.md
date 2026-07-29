---
title: "Скомпрометированные npm-пакеты joyfill доставляют RAT в проекты Node.js"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "ru"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "Бета-версии @joyfill/layouts и @joyfill/components содержат JavaScript-имплант, внедряемый во время импорта, который расшифровывает код для развертывания трояна удаленного доступа."
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "Разработчики Node.js, использующие пакеты joyfill"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Бета-версии @joyfill/layouts и @joyfill/components содержат JavaScript-имплант, внедряемый во время импорта, который расшифровывает код для развертывания трояна удаленного доступа.

{{< cyber-report severity="High" source="The Hacker News" target="Разработчики Node.js, использующие пакеты joyfill" >}}

Два npm-пакета в пространстве имен @joyfill, @joyfill/layouts версии 0.1.2-2773.beta.0 и @joyfill/components версии 4.0.0-rc24-2773-beta.4, были скомпрометированы. Эти бета-релизы содержат JavaScript-имплант, внедряемый во время импорта, который расшифровывает код, в конечном итоге доставляя троян удаленного доступа (RAT), связанный с семейством вредоносных программ DEV#POPPER.

{{< ad-banner >}}

Вредоносный код выполняется при импорте пакетов в проект Node.js, предоставляя злоумышленникам удаленный доступ к скомпрометированной системе. Эта атака подчеркивает сохраняющийся риск атак на цепочку поставок, нацеленных на экосистему npm, особенно через бета-версии или версии-кандидаты, которые могут получать меньше внимания.

Разработчикам, использовавшим эти конкретные версии, следует немедленно сменить учетные данные, проверить индикаторы компрометации и проанализировать свои деревья зависимостей на наличие других подозрительных пакетов. Реестр npm, вероятно, удалил вредоносные версии, но существующие установки остаются угрозой.

{{< netrunner-insight >}}

Этот инцидент подчеркивает важность проверки предрелизных пакетов и внедрения проверок целостности зависимостей. Аналитикам SOC следует отслеживать необычные исходящие соединения из приложений Node.js, а команды DevSecOps должны применять строгую фиксацию версий и использовать такие инструменты, как npm audit или SCA-сканеры, для обнаружения известных вредоносных пакетов.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
