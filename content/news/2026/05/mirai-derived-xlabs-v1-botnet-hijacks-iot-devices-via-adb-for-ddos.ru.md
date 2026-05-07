---
title: "Ботнет xlabs_v1 на базе Mirai захватывает IoT-устройства через ADB для DDoS-атак"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "ru"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "Исследователи обнаружили xlabs_v1, новый ботнет на основе Mirai, который использует открытые порты Android Debug Bridge для вербовки IoT-устройств в DDoS-сеть."
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "IoT-устройства с открытым ADB"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Исследователи обнаружили xlabs_v1, новый ботнет на основе Mirai, который использует открытые порты Android Debug Bridge для вербовки IoT-устройств в DDoS-сеть.

{{< cyber-report severity="High" source="The Hacker News" target="IoT-устройства с открытым ADB" >}}

Специалисты по кибербезопасности выявили новый ботнет на базе Mirai, идентифицирующий себя как xlabs_v1, который нацелен на устройства, подключенные к интернету и работающие с Android Debug Bridge (ADB). Ботнет стремится включить скомпрометированные устройства в сеть, способную запускать атаки типа «отказ в обслуживании» (DDoS).

{{< ad-banner >}}

Обнаружение было сделано компанией Hunt.io после того, как они нашли открытый каталог на сервере, размещенном в Нидерландах. Вредоносное ПО использует ADB — инструмент командной строки для отладки Android-устройств, который часто остается открытым на IoT-устройствах, позволяя удаленным злоумышленникам получить несанкционированный доступ.

Эта кампания подчеркивает постоянную угрозу со стороны вариантов Mirai, нацеленных на плохо защищенные IoT-устройства. Организациям рекомендуется отключать ADB на рабочих устройствах и ограничивать сетевой доступ, чтобы предотвратить такой захват.

{{< netrunner-insight >}}

Для аналитиков SOC: отслеживайте неожиданные ADB-подключения с внешних IP-адресов. Командам DevSecOps следует убедиться, что ADB отключен в производственных сборках, а IoT-устройства сегментированы от критических сетей, чтобы снизить охват этого ботнета.

{{< /netrunner-insight >}}

---

**[Читать полную статью на The Hacker News ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
