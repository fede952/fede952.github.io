---
title: "Kompromittierte joyfill-npm-Pakete liefern RAT an Node.js-Projekte"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "de"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "Beta-Versionen von @joyfill/layouts und @joyfill/components enthalten einen JavaScript-Implantat zur Importzeit, das verschlüsselten Code auflöst, um einen Trojaner für den Fernzugriff zu installieren."
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "Node.js-Entwickler, die joyfill-Pakete verwenden"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Beta-Versionen von @joyfill/layouts und @joyfill/components enthalten einen JavaScript-Implantat zur Importzeit, das verschlüsselten Code auflöst, um einen Trojaner für den Fernzugriff zu installieren.

{{< cyber-report severity="High" source="The Hacker News" target="Node.js-Entwickler, die joyfill-Pakete verwenden" >}}

Zwei npm-Pakete im @joyfill-Namespace, @joyfill/layouts Version 0.1.2-2773.beta.0 und @joyfill/components Version 4.0.0-rc24-2773-beta.4, wurden kompromittiert. Diese Beta-Versionen enthalten einen JavaScript-Implantat zur Importzeit, der verschlüsselten Code auflöst und letztendlich einen Trojaner für den Fernzugriff (RAT) ausliefert, der mit der Malware-Familie DEV#POPPER in Verbindung steht.

{{< ad-banner >}}

Der schädliche Code wird ausgeführt, wenn die Pakete in ein Node.js-Projekt importiert werden, und gibt Angreifern Fernzugriff auf das kompromittierte System. Der Angriff unterstreicht das anhaltende Risiko von Lieferkettenangriffen auf das npm-Ökosystem, insbesondere durch Beta- oder Release-Candidate-Versionen, die möglicherweise weniger genau geprüft werden.

Entwickler, die diese spezifischen Versionen verwendet haben, sollten sofort Anmeldeinformationen rotieren, nach Indikatoren für eine Kompromittierung suchen und ihre Abhängigkeitsbäume auf andere verdächtige Pakete überprüfen. Die npm-Registry hat die bösartigen Versionen wahrscheinlich entfernt, aber bestehende Installationen bleiben eine Bedrohung.

{{< netrunner-insight >}}

Dieser Vorfall unterstreicht die Bedeutung der Prüfung von Vorabversionen und der Implementierung von Integritätsprüfungen für Abhängigkeiten. SOC-Analysten sollten auf ungewöhnliche ausgehende Verbindungen von Node.js-Anwendungen achten, während DevSecOps-Teams strikte Versionsfestlegungen durchsetzen und Tools wie npm audit oder SCA-Scanner verwenden sollten, um bekannte schädliche Pakete zu erkennen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
