---
title: "Salesforce-Angriffe weiten sich aus: Icarus veröffentlicht gestohlene Daten über Klue-Breach"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "de"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "Angreifer nutzten Klues OAuth-Tokens, um auf Salesforce-Instanzen zuzugreifen; weitere Opfer tauchen auf, während Icarus gestohlene Daten veröffentlicht."
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "Salesforce-Instanzen über Klue-OAuth-Tokens"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Angreifer nutzten Klues OAuth-Tokens, um auf Salesforce-Instanzen zuzugreifen; weitere Opfer tauchen auf, während Icarus gestohlene Daten veröffentlicht.

{{< cyber-report severity="High" source="Dark Reading" target="Salesforce-Instanzen über Klue-OAuth-Tokens" >}}

Der Umfang der laufenden Angriffe auf Salesforce hat sich ausgeweitet, da die als Icarus verfolgten Bedrohungsakteure Daten von mehreren Opfern veröffentlichen. Die Angreifer drangen zunächst in den Anwendungsanbieter Klue ein und nutzten dessen OAuth-Tokens, um unbefugten Zugriff auf die Salesforce-Umgebungen der Kunden zu erlangen.

{{< ad-banner >}}

Laut Dark Reading sind nach der ersten Offenlegung neue Opfer aufgetaucht, was darauf hindeutet, dass die Angriffskampagne umfassender ist als bisher angenommen. Die Verwendung von OAuth-Tokens ermöglichte es den Angreifern, traditionelle Authentifizierungskontrollen zu umgehen und direkt auf Salesforce-Daten zuzugreifen, ohne typische Warnungen auszulösen.

Organisationen, die Salesforce-Integrationen mit Drittanbietern wie Klue nutzen, werden dringend aufgefordert, OAuth-Token-Berechtigungen zu überprüfen und auf anomale Zugriffsmuster zu achten. Die Icarus-Gruppe hat begonnen, gestohlene Daten zu veröffentlichen, was die Dringlichkeit für betroffene Unternehmen erhöht, zu reagieren.

{{< netrunner-insight >}}

Dieser Angriff unterstreicht das Risiko des Missbrauchs von OAuth-Tokens in SaaS-Ökosystemen. SOC-Analysten sollten die Überwachung auf ungewöhnliche API-Aufrufe und Token-Nutzung von integrierten Drittanbieter-Apps priorisieren. DevSecOps-Teams müssen ein strenges Token-Lebenszyklus-Management durchsetzen und Just-in-Time-Berechtigungen implementieren, um den Schadensradius zu begrenzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf Dark Reading lesen ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
