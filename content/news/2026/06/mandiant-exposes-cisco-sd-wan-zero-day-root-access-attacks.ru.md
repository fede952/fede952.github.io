---
title: "Mandiant раскрывает атаки на Cisco SD-WAN с получением root-доступа через zero-day"
date: "2026-06-25T10:15:15Z"
original_date: "2026-06-24T21:29:10"
lang: "ru"
translationKey: "mandiant-exposes-cisco-sd-wan-zero-day-root-access-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "Новые подробности показывают, как хакеры использовали CVE-2026-20245 в zero-day-атаках для создания поддельных root-учетных записей на устройствах Cisco Catalyst SD-WAN."
original_url: "https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/"
source: "BleepingComputer"
severity: "High"
target: "устройства Cisco Catalyst SD-WAN"
cve: "CVE-2026-20245"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Новые подробности показывают, как хакеры использовали CVE-2026-20245 в zero-day-атаках для создания поддельных root-учетных записей на устройствах Cisco Catalyst SD-WAN.

{{< cyber-report severity="High" source="BleepingComputer" target="устройства Cisco Catalyst SD-WAN" cve="CVE-2026-20245" >}}

Mandiant раскрыла новые технические подробности о том, как злоумышленники использовали zero-day-уязвимость в программном обеспечении Cisco Catalyst SD-WAN, отслеживаемую как CVE-2026-20245, для получения root-доступа к целевым устройствам. Атаки включали создание поддельных root-учетных записей, что обеспечивало постоянный несанкционированный доступ.

{{< ad-banner >}}

Уязвимость, которую Cisco исправила в недавнем уведомлении, использовалась в ограниченных целевых атаках. Анализ Mandiant раскрывает конкретную цепочку эксплуатации, подчеркивая важность своевременного применения обновлений безопасности.

Организациям, использующим решения Cisco SD-WAN, рекомендуется проверить свои системы на признаки компрометации, такие как несанкционированные учетные записи или необычная активность на уровне root. Инцидент подчеркивает критическую необходимость надежного управления исправлениями и мониторинга сетевой инфраструктуры.

{{< netrunner-insight >}}

Для аналитиков SOC: приоритетно отслеживайте события создания несанкционированных учетных записей и повышения привилегий на устройствах Cisco SD-WAN. Командам DevSecOps следует обеспечить быстрое развертывание исправлений безопасности Cisco и рассмотреть сегментацию интерфейсов управления SD-WAN для уменьшения поверхности атаки.

{{< /netrunner-insight >}}

---

**[Читать полную статью на BleepingComputer ›](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)**
