---
title: "Выпущен PoC-эксплойт для обхода Windows BitLocker нулевого дня: YellowKey и GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "ru"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "Опубликованы доказательства концепции для двух незапатченных уязвимостей Windows — YellowKey (обход BitLocker) и GreenPlasma (повышение привилегий), что создает риски для зашифрованных дисков."
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "защищенные BitLocker диски Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Опубликованы доказательства концепции для двух незапатченных уязвимостей Windows — YellowKey (обход BitLocker) и GreenPlasma (повышение привилегий), что создает риски для зашифрованных дисков.

{{< cyber-report severity="High" source="BleepingComputer" target="защищенные BitLocker диски Windows" >}}

Исследователь в области кибербезопасности опубликовал доказательства концепции (PoC) для двух незапатченных уязвимостей Microsoft Windows, названных YellowKey и GreenPlasma. YellowKey — это обход BitLocker, позволяющий злоумышленникам получать доступ к данным на защищенных дисках без надлежащей аутентификации, а GreenPlasma — ошибка повышения привилегий, которая может дать атакующему расширенные права на скомпрометированной системе.

{{< ad-banner >}}

Публикация этих PoC увеличивает риск эксплуатации, так как злоумышленники теперь могут использовать эти техники. Организациям, использующим BitLocker для полнодискового шифрования, следует оценить свою подверженность риску и рассмотреть дополнительные меры защиты, такие как включение защиты TPM+PIN или использование предзагрузочной аутентификации.

Microsoft еще не выпустила исправления для этих уязвимостей, оставляя системы незащищенными до выхода обновлений. Специалистам по безопасности следует отслеживать необычные паттерны доступа к зашифрованным дискам и применять обходные меры, где это возможно, например, отключать ненужные параметры загрузки или вводить строгие политики PIN-кодов.

{{< netrunner-insight >}}

Для аналитиков SOC: приоритетно отслеживайте несанкционированные попытки доступа к дискам, защищенным BitLocker, и события повышения привилегий. Инженерам DevSecOps следует протестировать свои среды с помощью опубликованных PoC для выявления уязвимых конфигураций и внедрения компенсирующих мер, таких как Secure Boot и журналы измеренной загрузки.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
