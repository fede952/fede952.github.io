---
title: "TONTOU-CPU-Angriff umgeht Spectre-v2-Fixes und leakt Linux-Passwort-Hashes"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "de"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Forscher entwickeln den TONTOU-Angriff, der aktuelle Spectre-v2-Mitigationen umgeht und erfolgreich Geheimnisse, einschließlich Passwort-Hashes, aus Linux-Systemen leakt."
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "Linux-Systeme"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Forscher entwickeln den TONTOU-Angriff, der aktuelle Spectre-v2-Mitigationen umgeht und erfolgreich Geheimnisse, einschließlich Passwort-Hashes, aus Linux-Systemen leakt.

{{< cyber-report severity="High" source="BleepingComputer" target="Linux-Systeme" >}}

Sicherheitsforscher haben einen neuen Angriff auf spekulative Ausführung vorgestellt, genannt TONTOU, der aktuelle Mitigationen für die Spectre-v2-Schwachstelle umgeht. Der Angriff zielt auf die Branch-Prediction-Mechanismen der CPU ab, die zuvor gepatcht wurden, um Side-Channel-Lecks zu verhindern. Durch die Ausnutzung einer Lücke in diesen Verteidigungsmaßnahmen konnten die Forscher sensible Daten aus dem Kernel-Speicher von Linux-Maschinen extrahieren.

{{< ad-banner >}}

Der Proof-of-Concept-Exploit demonstriert die Schwere des Problems, indem er erfolgreich Passwort-Hashes aus dem Zielsystem leakt. Dies deutet darauf hin, dass der Angriff verwendet werden könnte, um Benutzeranmeldeinformationen zu kompromittieren und möglicherweise Privilegien zu erweitern. Die Ergebnisse unterstreichen die anhaltende Herausforderung, Side-Channel-Angriffe auf spekulative Ausführung vollständig zu mitigieren, da trotz früherer Fixes weiterhin neue Variationen auftauchen.

Obwohl die Forscher noch keine vollständigen technischen Details veröffentlicht haben, unterstreicht ihre Arbeit die Notwendigkeit anhaltender Wachsamkeit bei der CPU-Sicherheit. Systemadministratoren wird empfohlen, auf Updates von CPU-Herstellern und Linux-Distributionen zu achten und zusätzliche Härtungsmaßnahmen wie Kernel Address Space Layout Randomization (KASLR) und Microcode-Updates in Betracht zu ziehen.

{{< netrunner-insight >}}

Dieser Angriff ist eine deutliche Erinnerung daran, dass Schwachstellen bei spekulativer Ausführung nicht vollständig behoben sind. SOC-Analysten sollten das Patchen priorisieren und auf Anzeichen von Ausnutzung achten, während DevSecOps-Ingenieure ihre Bedrohungsmodelle auf Side-Channel-Risiken überprüfen sollten. Angesichts des Potenzials, Passwort-Hashes zu leaken, ist sofortige Aufmerksamkeit für Linux-Kernel-Updates und CPU-Microcode gerechtfertigt.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
