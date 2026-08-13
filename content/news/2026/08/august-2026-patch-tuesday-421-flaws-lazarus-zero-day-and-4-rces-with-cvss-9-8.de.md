---
title: "Patch-Dienstag August 2026: 421 Schwachstellen, Lazarus Zero-Day und 4 RCEs mit CVSS 9.8"
date: "2026-08-13T08:21:14Z"
original_date: "2026-08-12T08:28:22"
lang: "de"
translationKey: "august-2026-patch-tuesday-421-flaws-lazarus-zero-day-and-4-rces-with-cvss-9-8"
slug: "august-2026-patch-tuesday-421-flaws-lazarus-zero-day-and-4-rces-with-cvss-9-8"
author: "NewsBot (Validated by Federico Sella)"
description: "Der Patch-Dienstag von Microsoft im August 2026 behebt 421 Schwachstellen, darunter einen WinSock-Treiber-Zero-Day, der von Lazarus ausgenutzt wird, sowie vier nicht authentifizierte RCEs mit CVSS 9.8."
original_url: "https://www.cybersecurity360.it/news/patch-tuesday-agosto-2026-un-driver-windows-il-gruppo-lazarus-e-400-vulnerabilita-sullo-sfondo/"
source: "Cybersecurity360"
severity: "Critical"
target: "Microsoft Windows WinSock-Treiber"
cve: null
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Der Patch-Dienstag von Microsoft im August 2026 behebt 421 Schwachstellen, darunter einen WinSock-Treiber-Zero-Day, der von Lazarus ausgenutzt wird, sowie vier nicht authentifizierte RCEs mit CVSS 9.8.

{{< cyber-report severity="Critical" source="Cybersecurity360" target="Microsoft Windows WinSock-Treiber" cvss="9.8" >}}

Der Patch-Dienstag von Microsoft im August 2026 behebt insgesamt 421 Schwachstellen und stellt damit ein bedeutendes Update dar. Darunter befindet sich eine Zero-Day-Schwachstelle im Windows-WinSock-Treiber, die von der Lazarus-Gruppe, einem bekannten nordkoreanischen Bedrohungsakteur, aktiv ausgenutzt wird. Dieser Zero-Day ist besonders besorgniserregend, da er Angreifern ermöglicht, erhöhte Privilegien zu erlangen oder beliebigen Code auszuführen, was potenziell betroffene Systeme gefährden kann.

{{< ad-banner >}}

Zusätzlich zu dem Zero-Day enthält das Update vier nicht authentifizierte Schwachstellen für Remote-Codeausführung (RCE), die alle mit einem CVSS-Score von 9.8 bewertet wurden. Diese kritischen Fehler könnten ohne Benutzerinteraktion remote ausgenutzt werden, was sie zu einer hohen Priorität für sofortiges Patchen macht. Die schiere Anzahl der Schwachstellen unterstreicht die Bedeutung eines robusten Patch-Management-Prozesses.

Der Artikel hebt auch einen Wandel in den Strategien zur Schwachstellenverwaltung hervor und stellt fest, dass mit der Einführung von KI-gesteuerter Erkennung die kontextbasierte Priorisierung effektiver wird als die traditionelle scorebasierte Priorisierung. Dies deutet darauf hin, dass Organisationen Schwachstellen basierend auf ihrer spezifischen Umgebung und Bedrohungslandschaft priorisieren sollten, anstatt sich ausschließlich auf CVSS-Scores zu verlassen.

{{< netrunner-insight >}}

Für SOC-Analysten sollte der Lazarus-Zero-Day in WinSock als sofortige Priorität behandelt werden, da er bereits ausgenutzt wird. Patchen Sie ihn umgehend auf allen Windows-Endpunkten. DevSecOps-Teams sollten KI-gesteuerten Kontext nutzen, um die 421 Schwachstellen zu priorisieren, wobei der Fokus auf solchen liegen sollte, die internetexponiert oder für den Geschäftsbetrieb kritisch sind, anstatt nur hohen CVSS-Scores hinterherzujagen. Denken Sie daran: Die vier RCEs mit CVSS 9.8 sind nicht authentifiziert, daher sollten sie vor allen anderen nicht kritischen Updates gepatcht werden.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf Cybersecurity360 lesen ›](https://www.cybersecurity360.it/news/patch-tuesday-agosto-2026-un-driver-windows-il-gruppo-lazarus-e-400-vulnerabilita-sullo-sfondo/)**
