---
title: "SAP npm-Pakete von Supply-Chain-Angriff mit Credential-Diebstahl betroffen"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "de"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine als 'Mini Shai-Hulud' bezeichnete Kampagne zielt auf SAP-bezogene npm-Pakete mit Credential-stehlender Malware ab und betrifft mehrere Pakete. Forscher mehrerer Firmen warnen vor Supply-Chain-Risiken."
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "SAP-bezogene npm-Pakete"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine als 'Mini Shai-Hulud' bezeichnete Kampagne zielt auf SAP-bezogene npm-Pakete mit Credential-stehlender Malware ab und betrifft mehrere Pakete. Forscher mehrerer Firmen warnen vor Supply-Chain-Risiken.

{{< cyber-report severity="High" source="The Hacker News" target="SAP-bezogene npm-Pakete" >}}

Cybersicherheitsforscher haben eine Supply-Chain-Angriffskampagne aufgedeckt, die auf SAP-bezogene npm-Pakete abzielt. Die als 'Mini Shai-Hulud' bezeichnete Kampagne setzt über kompromittierte Pakete Malware zum Stehlen von Anmeldeinformationen ein, wie Berichte von Aikido Security, Onapsis, OX Security, SafeDep, Socket, StepSecurity und Wiz zeigen.

{{< ad-banner >}}

Der Angriff betrifft mehrere npm-Pakete, die mit SAP verbunden sind, obwohl spezifische Paketnamen und Versionen nicht offengelegt wurden. Die Malware ist darauf ausgelegt, Anmeldeinformationen zu stehlen, was Angreifern potenziell Zugang zu sensiblen SAP-Umgebungen und nachgelagerten Systemen verschaffen könnte.

Dieser Vorfall unterstreicht die wachsende Bedrohung für Software-Lieferketten, insbesondere für unternehmenskritische Plattformen wie SAP. Organisationen, die betroffene Pakete verwenden, wird empfohlen, ihre Abhängigkeiten zu überprüfen und alle potenziell kompromittierten Anmeldeinformationen zu rotieren.

{{< netrunner-insight >}}

Für SOC-Analysten und DevSecOps-Teams unterstreicht dieser Angriff die Notwendigkeit einer rigorosen Abhängigkeitsprüfung und Integritätschecks für npm-Pakete. Überwachen Sie auf ungewöhnliche ausgehende Verbindungen von SAP-bezogenen Systemen und erwägen Sie die Implementierung von Runtime Application Self-Protection (RASP), um Credential-Diebstahl zu erkennen. Rotieren Sie sofort alle Anmeldeinformationen, die möglicherweise durch kompromittierte Pakete offengelegt wurden.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
