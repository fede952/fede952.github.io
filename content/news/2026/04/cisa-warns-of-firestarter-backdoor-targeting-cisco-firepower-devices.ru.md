---
title: "CISA предупреждает о бэкдоре FIRESTARTER, нацеленном на устройства Cisco Firepower"
date: "2026-04-23T12:00:00"
lang: "ru"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA и NCSC предупреждают об использовании APT-группировками бэкдора FIRESTARTER для сохранения постоянства на устройствах Cisco ASA/FTD. Изложены срочные меры реагирования."
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "устройства Cisco Firepower и Secure Firewall"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA и NCSC предупреждают об использовании APT-группировками бэкдора FIRESTARTER для сохранения постоянства на устройствах Cisco ASA/FTD. Изложены срочные меры реагирования.

{{< cyber-report severity="High" source="CISA" target="устройства Cisco Firepower и Secure Firewall" >}}

CISA и Национальный центр кибербезопасности Великобритании (NCSC) опубликовали отчет о вредоносном ПО FIRESTARTER, которое используется продвинутыми постоянными угрозами (APT) для сохранения постоянства на общедоступных устройствах Cisco Firepower и Secure Firewall под управлением ASA или FTD. Анализ основан на образце, полученном в ходе криминалистического расследования, и CISA подтвердила успешные внедрения в дикой природе на устройствах Cisco Firepower с ПО ASA.

{{< ad-banner >}}

Публикация соответствует Чрезвычайной директиве CISA 25-03, предписывающей агентствам FCEB США собирать и отправлять дампы памяти на платформу Malware Next Generation CISA и немедленно сообщать о результатах через круглосуточный операционный центр. Организациям рекомендуется не предпринимать дополнительных действий до получения дальнейших указаний от CISA.

Хотя вредоносное ПО актуально как для устройств Cisco Firepower, так и для Secure Firewall, CISA наблюдала успешные внедрения только на устройствах Firepower под управлением ASA. В отчете подчеркивается необходимость бдительности и активного поиска индикаторов компрометации.

{{< netrunner-insight >}}

Аналитикам SOC следует в первую очередь собирать дампы памяти с устройств Cisco ASA/FTD и отправлять их в CISA для анализа. Командам DevSecOps необходимо обеспечить установку обновлений и настройку устройств Cisco в соответствии с лучшими практиками, а также отслеживать необычные механизмы сохранения постоянства. Этот бэкдор подчеркивает критическую важность защиты периферийных сетевых устройств от угроз уровня APT.

{{< /netrunner-insight >}}

---

**[Читать полную статью на CISA ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
