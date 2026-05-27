---
title: "CISA warnt vor ABB Camera Connect-Sicherheitslücken durch VLC Media Player-Komponente"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB Ability Camera Connect Versionen ≤1.5.0.14 enthalten einen anfälligen VLC Media Player 2.2.4 mit mehreren Speicherfehlern, darunter CVE-2024-46461, die ein kritisches Risiko darstellen."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB Ability Camera Connect Versionen ≤1.5.0.14 enthalten einen anfälligen VLC Media Player 2.2.4 mit mehreren Speicherfehlern, darunter CVE-2024-46461, die ein kritisches Risiko darstellen.

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

CISA hat eine Sicherheitswarnung (ICSA-26-146-05) veröffentlicht, die mehrere Schwachstellen in ABB Ability Camera Connect Versionen 1.5.0.14 und niedriger beschreibt. Die Fehler stammen von einer veralteten Drittanbieterkomponente, dem VLC Media Player Version 2.2.4, der mit dem Installationspaket gebündelt ist. Ein Update auf Version 1.5.0.15 behebt das Problem, indem die anfällige Komponente ersetzt wird.

{{< ad-banner >}}

Zu den Schwachstellen gehören Heap-basierter Pufferüberlauf, Integer-Unterlauf, Schreibzugriff außerhalb der Grenzen, unkontrolliertes Suchelement, Integer-Überlauf, Off-by-One-Fehler, Lesezugriff außerhalb der Grenzen, Double-Free, unsachgemäße Einschränkung von Operationen in Speicherpuffern und Use-after-Free. Insbesondere beschreibt CVE-2024-46461 einen Heap-basierten Überlauf im VLC Media Player 3.0.20 und früher über einen böswillig erstellten MMS-Stream, der zu einem Denial-of-Service führt.

Mit einem CVSS v3-Score von 9,8 werden diese Schwachstellen als kritisch eingestuft. Betroffene kritische Infrastruktursektoren umfassen Chemie, Gewerbeanlagen, Kommunikation, Kritische Fertigung, Energie und Verkehrssysteme. Das Produkt ist weltweit im Einsatz, und eine Ausnutzung könnte einem Angreifer ermöglichen, das System auf verschiedene Weise zu kompromittieren.

{{< netrunner-insight >}}

Diese Warnung unterstreicht das Risiko von vererbten Schwachstellen aus Drittanbieterkomponenten. SOC-Analysten sollten die Aktualisierung von ABB Ability Camera Connect auf Version 1.5.0.15 priorisieren und nach Ausnutzungsversuchen gegen VLC Media Player-Fehler suchen. DevSecOps-Teams müssen eine strenge Versionskontrolle von Komponenten und regelmäßige Scans gebündelter Bibliotheken durchsetzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
