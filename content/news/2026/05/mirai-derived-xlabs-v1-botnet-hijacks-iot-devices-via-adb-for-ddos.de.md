---
title: "Mirai-basiertes xlabs_v1 Botnetz kapert IoT-Geräte über ADB für DDoS"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "de"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "Forscher entdecken xlabs_v1, ein neues auf Mirai basierendes Botnetz, das exponierte Android Debug Bridge-Ports ausnutzt, um IoT-Geräte in ein DDoS-Netzwerk zu rekrutieren."
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "IoT-Geräte mit exponierter ADB"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Forscher entdecken xlabs_v1, ein neues auf Mirai basierendes Botnetz, das exponierte Android Debug Bridge-Ports ausnutzt, um IoT-Geräte in ein DDoS-Netzwerk zu rekrutieren.

{{< cyber-report severity="High" source="The Hacker News" target="IoT-Geräte mit exponierter ADB" >}}

Cybersicherheitsforscher haben ein neues, von Mirai abgeleitetes Botnetz identifiziert, das sich selbst als xlabs_v1 bezeichnet und auf internetexponierte Geräte abzielt, die Android Debug Bridge (ADB) ausführen. Das Botnetz zielt darauf ab, kompromittierte Geräte in ein Netzwerk einzubinden, das Distributed-Denial-of-Service-Angriffe (DDoS) starten kann.

{{< ad-banner >}}

Die Entdeckung wurde von Hunt.io gemacht, nachdem sie ein exponiertes Verzeichnis auf einem Server in den Niederlanden identifiziert hatten. Die Malware nutzt ADB aus, ein Befehlszeilentool zum Debuggen von Android-Geräten, das oft auf IoT-Geräten exponiert bleibt und es entfernten Angreifern ermöglicht, unbefugten Zugriff zu erlangen.

Diese Kampagne unterstreicht die anhaltende Bedrohung durch Mirai-Varianten, die auf schlecht gesicherte IoT-Geräte abzielen. Organisationen wird empfohlen, ADB auf Produktionsgeräten zu deaktivieren und den Netzwerkzugriff einzuschränken, um solche Übernahmen zu verhindern.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf unerwartete ADB-Verbindungen von externen IPs. DevSecOps-Teams sollten sicherstellen, dass ADB in Produktionsbuilds deaktiviert ist und dass IoT-Geräte von kritischen Netzwerken segmentiert werden, um die Reichweite dieses Botnetzes zu begrenzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
