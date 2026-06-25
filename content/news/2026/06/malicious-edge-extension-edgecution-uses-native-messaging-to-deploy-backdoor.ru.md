---
title: "Вредоносное расширение Edge 'Edgecution' использует Native Messaging для развертывания бэкдора"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "ru"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "Вредоносное расширение Microsoft Edge под названием 'Edgecution' выходит из песочницы браузера через Native Messaging, чтобы развернуть бэкдор на Python в атаках программ-вымогателей."
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Пользователи Microsoft Edge"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Вредоносное расширение Microsoft Edge под названием 'Edgecution' выходит из песочницы браузера через Native Messaging, чтобы развернуть бэкдор на Python в атаках программ-вымогателей.

{{< cyber-report severity="High" source="BleepingComputer" target="Пользователи Microsoft Edge" >}}

Вредоносное расширение Microsoft Edge под названием 'Edgecution' было замечено в атаке с использованием программы-вымогателя, где оно использует API Native Messaging браузера для выхода из песочницы и выполнения произвольного кода на хост-системе. Расширение действует как мост для развертывания бэкдора на Python, обеспечивая постоянный доступ и дальнейшие вредоносные действия.

{{< ad-banner >}}

Цепочка атаки начинается с установки вредоносного расширения, которое затем злоупотребляет Native Messaging для связи с нативным приложением вне песочницы браузера. Этот метод обходит типичные границы безопасности браузера, позволяя злоумышленнику выполнять команды и загружать дополнительные полезные нагрузки, включая программы-вымогатели.

Исследователи безопасности отмечают, что этот метод особенно коварен, поскольку использует легитимную функцию браузера, что затрудняет обнаружение традиционными решениями безопасности конечных точек. Организациям рекомендуется отслеживать несанкционированные расширения браузера и по возможности ограничивать разрешения Native Messaging.

{{< netrunner-insight >}}

Эта атака подчеркивает важность мониторинга установок расширений браузера и активности Native Messaging. Аналитикам SOC следует обращать внимание на аномальное поведение расширений и неожиданные коммуникации с нативными хостами, а команды DevSecOps должны внедрять строгие списки разрешенных расширений и отключать ненужные хосты Native Messaging.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
