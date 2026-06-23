---
title: "Bösartige npm-Pakete getarnt als PostCSS-Tools liefern Windows-RAT aus"
date: "2026-06-23T10:35:14Z"
original_date: "2026-06-23T08:54:32"
lang: "de"
translationKey: "malicious-npm-packages-disguised-as-postcss-tools-deliver-windows-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Drei bösartige npm-Pakete, die als PostCSS-Tools getarnt sind, wurden entdeckt, wie sie einen Windows-Fernzugriffs-Trojaner ausliefern. Forscher raten zur Vorsicht bei der Installation von npm-Paketen."
original_url: "https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html"
source: "The Hacker News"
severity: "High"
target: "npm-Nutzer, Windows-Systeme"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Drei bösartige npm-Pakete, die als PostCSS-Tools getarnt sind, wurden entdeckt, wie sie einen Windows-Fernzugriffs-Trojaner ausliefern. Forscher raten zur Vorsicht bei der Installation von npm-Paketen.

{{< cyber-report severity="High" source="The Hacker News" target="npm-Nutzer, Windows-Systeme" >}}

Cybersicherheitsforscher haben drei bösartige npm-Pakete identifiziert – aes-decode-runner-pro, postcss-minify-selector und postcss-minify-selector-parser – die darauf ausgelegt sind, einen Windows-basierten Fernzugriffs-Trojaner (RAT) auszuliefern. Die Pakete wurden im letzten Monat von einem npm-Benutzer veröffentlicht und haben insgesamt 1.016 Downloads angesammelt, was auf eine moderate, aber besorgniserregende Verbreitung hindeutet.

{{< ad-banner >}}

Die Pakete tarnen sich als legitime PostCSS-Tools, einen beliebten CSS-Postprozessor, um Entwickler zur Installation zu verleiten. Nach der Installation führt der bösartige Code eine Nutzlast aus, die Fernzugriff auf das infizierte Windows-System ermöglicht, was Angreifern potenziell erlaubt, Daten zu exfiltrieren, zusätzliche Malware zu installieren oder sich im Netzwerk seitwärts zu bewegen.

Dieser Vorfall unterstreicht die anhaltende Bedrohung durch Typosquatting und Dependency Confusion im npm-Ökosystem. Entwicklern wird empfohlen, Paketnamen sorgfältig zu überprüfen, Quellcode vor der Installation zu prüfen und Tools zur Paketintegritätsverifikation zu verwenden, um solche Risiken zu mindern.

{{< netrunner-insight >}}

Für SOC-Analysten und DevSecOps-Ingenieure ist dies eine Erinnerung, strenge Prüfungen der Paketherkunft durchzusetzen und auf anomale npm-Paketinstallationen zu achten. Erwägen Sie die Implementierung automatisierter Scans nach bekannten bösartigen Paketen und die Schulung von Entwicklern über die Risiken, Paketnamen blind zu vertrauen. Die relativ niedrige Downloadzahl deutet darauf hin, dass diese Kampagne möglicherweise noch in einem frühen Stadium ist, daher ist eine proaktive Suche nach ähnlichen Paketen angebracht.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)**
