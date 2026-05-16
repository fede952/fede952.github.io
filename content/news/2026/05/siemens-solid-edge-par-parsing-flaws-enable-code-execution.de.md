---
title: "Siemens Solid Edge PAR-Parsing-Schwachstellen ermöglichen Codeausführung"
date: "2026-05-16T08:48:36Z"
original_date: "2026-05-14T12:00:00"
lang: "de"
translationKey: "siemens-solid-edge-par-parsing-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Zwei Dateiparsing-Schwachstellen in Siemens Solid Edge SE2026 erlauben Angreifern, über speziell gestaltete PAR-Dateien beliebigen Code auszuführen. Aktualisieren Sie auf V226.0 Update 5."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03"
source: "CISA"
severity: "High"
target: "Siemens Solid Edge SE2026"
cve: "CVE-2026-44411"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Zwei Dateiparsing-Schwachstellen in Siemens Solid Edge SE2026 erlauben Angreifern, über speziell gestaltete PAR-Dateien beliebigen Code auszuführen. Aktualisieren Sie auf V226.0 Update 5.

{{< cyber-report severity="High" source="CISA" target="Siemens Solid Edge SE2026" cve="CVE-2026-44411" cvss="7.8" >}}

Siemens Solid Edge SE2026 vor Update 5 ist von zwei Dateiparsing-Schwachstellen betroffen, die ausgelöst werden können, wenn die Anwendung speziell gestaltete PAR-Dateien liest. Die Fehler umfassen einen nicht initialisierten Pointer-Zugriff (CVE-2026-44411) und einen stackbasierten Pufferüberlauf (CVE-2026-44412), die es einem Angreifer ermöglichen könnten, die Anwendung zum Absturz zu bringen oder beliebigen Code im Kontext des aktuellen Prozesses auszuführen.

{{< ad-banner >}}

Die Schwachstellen haben einen CVSS v3.1-Basiswert von 7,8 (High) mit dem Vektor AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, was auf lokalen Zugriff, geringe Komplexität, keine erforderlichen Berechtigungen, erforderliche Benutzerinteraktion und hohe Auswirkungen auf Vertraulichkeit, Integrität und Verfügbarkeit hinweist. Siemens hat Version V226.0 Update 5 veröffentlicht, um diese Probleme zu beheben, und empfiehlt Benutzern, sofort zu aktualisieren.

Angesichts der weltweiten Bereitstellung im kritischen Fertigungssektor sollten Organisationen, die Solid Edge verwenden, das Patchen priorisieren. Die Schwachstellen erfordern Benutzerinteraktion (Öffnen einer bösartigen PAR-Datei), daher wird auch eine Sensibilisierungsschulung der Benutzer als kompensierende Kontrolle empfohlen.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf ungewöhnliche PAR-Dateiverarbeitung oder Abstürze in Solid Edge-Prozessen. DevSecOps-Ingenieure sollten Anwendungs-Whitelisting durchsetzen und Dateitypen einschränken, um die Angriffsfläche zu reduzieren. Da es sich um lokale, benutzerinteraktionsabhängige Schwachstellen handelt, sind Phishing-Simulationen und Endpunkterkennungsregeln für verdächtige Dateiöffnungen wichtige Gegenmaßnahmen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03)**
