---
title: "Polymarket verliert 3 Millionen Dollar durch Supply-Chain-Angriff über Drittanbieter"
date: "2026-06-28T09:58:42Z"
original_date: "2026-06-26T18:04:12"
lang: "de"
translationKey: "polymarket-loses-3m-in-supply-chain-attack-via-third-party-vendor"
author: "NewsBot (Validated by Federico Sella)"
description: "Hacker injizierten nach einem Einbruch bei einem Drittanbieter ein bösartiges Skript in das Frontend von Polymarket, was zu Kundenverlusten in Höhe von 3 Millionen Dollar führte. Die Plattform wird die Opfer vollständig entschädigen."
original_url: "https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Polymarket Frontend-Nutzer"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Hacker injizierten nach einem Einbruch bei einem Drittanbieter ein bösartiges Skript in das Frontend von Polymarket, was zu Kundenverlusten in Höhe von 3 Millionen Dollar führte. Die Plattform wird die Opfer vollständig entschädigen.

{{< cyber-report severity="High" source="BleepingComputer" target="Polymarket Frontend-Nutzer" >}}

Polymarket, eine dezentrale Prognosemarkt-Plattform, gab bekannt, dass Angreifer einen Drittanbieter kompromittiert haben, um ein bösartiges Skript in sein Frontend einzuschleusen, was zu einem geschätzten Verlust von 3 Millionen Dollar für Kunden führte. Der als Supply-Chain-Angriff beschriebene Vorfall zielte auf die Benutzeroberfläche der Plattform ab, um Gelder abzuschöpfen.

{{< ad-banner >}}

Das Unternehmen erklärte, dass es betroffene Kunden vollständig entschädigen wird, obwohl die genaue Anzahl der Opfer nicht bekannt gegeben wurde. Der Vorfall unterstreicht die Risiken, die mit Drittanbieter-Abhängigkeiten in DeFi- und Krypto-Plattformen verbunden sind, wo die Integrität des Frontends für die Transaktionssicherheit entscheidend ist.

Obwohl keine spezifische CVE oder CVSS-Bewertung bereitgestellt wurde, verdeutlicht der Angriffsvektor – Kompromittierung eines Anbieters zur Änderung von Frontend-Code – die Notwendigkeit robuster Supply-Chain-Sicherheitsmaßnahmen, einschließlich Code-Signing, Integritätsprüfungen und Risikobewertungen von Anbietern.

{{< netrunner-insight >}}

Dieser Vorfall ist ein Paradebeispiel für einen Supply-Chain-Angriff, der auf die Frontend-Integrität abzielt. SOC-Analysten sollten auf unbefugte Skriptinjektionen in Webanwendungen achten, insbesondere bei solchen, die auf Drittanbieter-Bibliotheken oder CDNs angewiesen sind. DevSecOps-Teams müssen strenge Content Security Policies (CSP), Subresource Integrity (SRI)-Prüfungen und regelmäßige Anbieter-Audits durchsetzen, um solche Risiken zu mindern.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)**
