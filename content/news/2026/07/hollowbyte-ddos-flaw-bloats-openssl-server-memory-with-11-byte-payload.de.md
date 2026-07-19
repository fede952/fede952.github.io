---
title: "HollowByte-DoS-Schwachstelle bläht OpenSSL-Server-Speicher mit 11-Byte-Payload auf"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "de"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine als HollowByte bezeichnete Sicherheitslücke ermöglicht es nicht authentifizierten Angreifern, mit einer bösartigen Payload von nur 11 Bytes einen Denial-of-Service-Zustand auf OpenSSL-Servern auszulösen."
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "OpenSSL-Server"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine als HollowByte bezeichnete Sicherheitslücke ermöglicht es nicht authentifizierten Angreifern, mit einer bösartigen Payload von nur 11 Bytes einen Denial-of-Service-Zustand auf OpenSSL-Servern auszulösen.

{{< cyber-report severity="High" source="BleepingComputer" target="OpenSSL-Server" >}}

Eine neu entdeckte Sicherheitslücke namens HollowByte ermöglicht es nicht authentifizierten Angreifern, einen Denial-of-Service (DoS)-Zustand auf OpenSSL-Servern zu verursachen, indem sie eine speziell präparierte Payload von nur 11 Bytes senden. Der Fehler nutzt Ineffizienzen bei der Speicherzuweisung aus, wodurch der Serverspeicher aufgebläht wird und schließlich die verfügbaren Ressourcen erschöpft.

{{< ad-banner >}}

Der Angriff erfordert keine Authentifizierung und kann remote ausgeführt werden, was ihn zu einer erheblichen Bedrohung für jede Organisation macht, die auf OpenSSL für sichere Kommunikation angewiesen ist. Die minimale Payload-Größe ermöglicht es Angreifern, ihre Wirkung mit begrenzter Bandbreite zu verstärken und Server mit minimalem Aufwand zu überlasten.

Obwohl noch keine CVE-Kennung vergeben wurde, wurde die Sicherheitslücke dem OpenSSL-Projekt gemeldet, und Patches werden erwartet. In der Zwischenzeit wird Administratoren empfohlen, die Speichernutzung zu überwachen und Ratenbegrenzungen oder Intrusion-Detection-Regeln zu implementieren, um eine mögliche Ausnutzung abzumildern.

{{< netrunner-insight >}}

Für SOC-Analysten ist dies ein klassischer Low-Bandwidth-, High-Impact-DoS-Vektor, der traditionelle volumetrische Abwehrmechanismen umgehen kann. DevSecOps-Teams sollten das Patchen priorisieren, sobald verfügbar, und die Bereitstellung von Speicherüberwachungsalarmen in Betracht ziehen, um anomales Wachstum zu erkennen. Die 11-Byte-Payload macht dies zu einem idealen Kandidaten für die Aufnahme in Bedrohungserkennungsregeln.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
