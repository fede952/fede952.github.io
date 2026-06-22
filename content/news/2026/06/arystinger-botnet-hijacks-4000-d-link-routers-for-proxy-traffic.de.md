---
title: "AryStinger-Botnetz kapert über 4.000 D-Link-Router für Proxy-Traffic"
date: "2026-06-22T12:48:45Z"
original_date: "2026-06-21T14:14:22"
lang: "de"
translationKey: "arystinger-botnet-hijacks-4000-d-link-routers-for-proxy-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Ein neues Botnetz namens AryStinger hat über 4.000 veraltete D-Link-Router kompromittiert und sie in Proxys für bösartigen Traffic verwandelt. Es sind keine CVE- oder CVSS-Daten verfügbar."
original_url: "https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/"
source: "BleepingComputer"
severity: "Medium"
target: "Veraltete D-Link-Router"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ein neues Botnetz namens AryStinger hat über 4.000 veraltete D-Link-Router kompromittiert und sie in Proxys für bösartigen Traffic verwandelt. Es sind keine CVE- oder CVSS-Daten verfügbar.

{{< cyber-report severity="Medium" source="BleepingComputer" target="Veraltete D-Link-Router" >}}

Ein bisher nicht dokumentiertes Malware-Botnetz namens AryStinger hat laut einem Bericht von BleepingComputer weltweit mehr als 4.000 veraltete D-Link-Router kompromittiert. Das Botnetz verwandelt diese Geräte in Proxys für bösartigen Traffic, sodass Angreifer ihre Aktivitäten anonymisieren und möglicherweise weitere Angriffe starten können.

{{< ad-banner >}}

Die kompromittierten Router laufen vermutlich mit veralteter Firmware, die bekannte Schwachstellen aufweist, obwohl im Bericht keine spezifischen CVE-Identifikatoren genannt wurden. Die Infrastruktur und Verbreitungsmethoden des Botnetzes werden noch analysiert, aber das Ausmaß der Infektion unterstreicht die Risiken, die von ungepatchten IoT-Geräten ausgehen.

Organisationen wird empfohlen, ihre Netzwerkgeräte zu inventarisieren, sicherzustellen, dass die Firmware auf dem neuesten Stand ist, und auf ungewöhnliche Verkehrsmuster zu achten, die auf eine Proxy-Nutzung hindeuten könnten. Das Fehlen detaillierter technischer Indikatoren im ersten Bericht deutet darauf hin, dass weitere Untersuchungen erforderlich sind, um Erkennungssignaturen zu entwickeln.

{{< netrunner-insight >}}

Für SOC-Analysten ist dies eine Erinnerung, auf unerwartete ausgehende Verbindungen von Netzwerkgeräten zu achten, insbesondere von älteren Routern. DevSecOps-Teams sollten Richtlinien für Firmware-Updates durchsetzen und die Segmentierung von IoT-Geräten von kritischen Netzwerken in Betracht ziehen. Ohne spezifische IoCs sind Basislinien-Traffic-Analyse und Geräte-Fingerprinting der Schlüssel, um solche Botnetz-Aktivitäten zu erkennen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)**
