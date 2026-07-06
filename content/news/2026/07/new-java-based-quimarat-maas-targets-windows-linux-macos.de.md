---
title: "Neuer Java-basierter QuimaRAT MaaS bedroht Windows, Linux, macOS"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "de"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "QuimaRAT, ein plattformübergreifender Java-RAT, der als Malware-as-a-Service verkauft wird, bedroht Windows-, Linux- und macOS-Systeme. Forscher von LevelBlue beschreiben sein Abonnementmodell und seine Fähigkeiten."
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "Windows-, Linux- und macOS-Systeme"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuimaRAT, ein plattformübergreifender Java-RAT, der als Malware-as-a-Service verkauft wird, bedroht Windows-, Linux- und macOS-Systeme. Forscher von LevelBlue beschreiben sein Abonnementmodell und seine Fähigkeiten.

{{< cyber-report severity="High" source="The Hacker News" target="Windows-, Linux- und macOS-Systeme" >}}

Cybersicherheitsforscher von LevelBlue haben einen neuen Java-basierten Trojaner für den Fernzugriff (RAT) namens QuimaRAT identifiziert, der Windows-, Linux- und macOS-Umgebungen angreifen kann. Die Malware wird im Rahmen eines Malware-as-a-Service-Modells (MaaS) vermarktet, mit Abonnementstufen von 150 $ für einen Monat bis 1.200 $ für lebenslangen Zugang sowie einer 300 $-Stufe.

{{< ad-banner >}}

Die plattformübergreifende Natur von QuimaRAT, ermöglicht durch Java, erlaubt es, verschiedene Betriebssysteme zu kompromittieren, was es zu einer vielseitigen Bedrohung für Organisationen mit heterogenen Umgebungen macht. Das MaaS-Modell senkt die Einstiegshürde für weniger qualifizierte Bedrohungsakteure und könnte die Häufigkeit von Angriffen erhöhen.

Während spezifische technische Details zu den Fähigkeiten von QuimaRAT im ersten Bericht begrenzt sind, deutet seine Java-basierte Architektur darauf hin, dass es gängige Techniken wie Keylogging, Bildschirmaufnahme und Dateiexfiltration nutzen könnte. Organisationen sollten verdächtige Java-Prozesse überwachen und Anwendungs-Allowlisting implementieren, um das Risiko zu mindern.

{{< netrunner-insight >}}

Für SOC-Analysten bedeutet die plattformübergreifende Natur von QuimaRAT, dass Erkennungsregeln Windows-, Linux- und macOS-Endpunkte abdecken müssen. DevSecOps-Teams sollten die Java-Laufzeitnutzung überprüfen und die Ausführung unsignierter Java-Anwendungen einschränken. Angesichts des MaaS-Modells ist mit Angreifern mit geringer Qualifikation zu rechnen, die diesen RAT einsetzen, daher ist eine grundlegende Überwachung auf ungewöhnliche Netzwerkverbindungen und Prozessverhalten entscheidend.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
