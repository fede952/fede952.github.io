---
title: "CISA warnt vor Siemens Opcenter RDnL-Schwachstelle über ActiveMQ Artemis fehlende Authentifizierung"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Opcenter RDnL ist von CVE-2026-27446 betroffen, einer fehlenden Authentifizierungsschwachstelle in ActiveMQ Artemis, die nicht authentifizierten Angreifern im angrenzenden Netzwerk erlaubt, Nachrichten einzuschleusen oder zu extrahieren."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Opcenter RDnL ist von CVE-2026-27446 betroffen, einer fehlenden Authentifizierungsschwachstelle in ActiveMQ Artemis, die nicht authentifizierten Angreifern im angrenzenden Netzwerk erlaubt, Nachrichten einzuschleusen oder zu extrahieren.

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

CISA hat eine Warnung (ICSA-26-134-09) veröffentlicht, die eine fehlende Authentifizierung für kritische Funktionen in Apache ActiveMQ Artemis beschreibt, die Siemens Opcenter RDnL betrifft. Die Schwachstelle, verfolgt als CVE-2026-27446 mit einem CVSS v3-Score von 7.1, erlaubt einem nicht authentifizierten Angreifer im angrenzenden Netzwerk, einen Ziel-Broker zu zwingen, eine ausgehende Core-Federation-Verbindung zu einem schädlichen Broker herzustellen. Dies kann zur Nachrichteneinschleusung in jede Warteschlange oder zur Nachrichtenextraktion aus jeder Warteschlange über den schädlichen Broker führen.

{{< ad-banner >}}

Die Schwachstelle betrifft alle Versionen von Siemens Opcenter RDnL. Während die Integritätsauswirkung aufgrund fehlender Auto-Refresh-Funktionalität und des Fehlens vertraulicher Informationen in den Nachrichten als gering eingestuft wird, bleiben die Verfügbarkeitsauswirkung und das Potenzial zur Nachrichtenmanipulation erheblich. ActiveMQ Artemis hat einen Fix veröffentlicht, und Siemens empfiehlt, sofort auf die neueste Version zu aktualisieren.

Angesichts der weltweiten Bereitstellung im kritischen Fertigungssektor sollten Organisationen, die Opcenter RDnL verwenden, das Patchen priorisieren. Der Angriffsvektor über das angrenzende Netzwerk reduziert die unmittelbare Gefährdung, stellt aber in segmentierten Umgebungen weiterhin ein Risiko dar. Blaue Teams sollten auf ungewöhnliche Core-Federation-Verbindungen und schädliche Broker-Aktivitäten achten.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf unerwartete ausgehende Core-Federation-Verbindungen von ActiveMQ Artemis-Brokern, da dies der primäre Indikator für eine Ausnutzung ist. DevSecOps-Teams sollten sofort auf die neueste ActiveMQ Artemis-Version aktualisieren und den Core-Protokollzugriff auf vertrauenswürdige Netzwerke beschränken. Diese Schwachstelle unterstreicht das Risiko fehlender Authentifizierung in Middleware-Komponenten, selbst wenn die unmittelbare Auswirkung gering erscheint.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
