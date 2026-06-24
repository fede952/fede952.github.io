---
title: "LastPass bestätigt Datenleck durch Klue-Supply-Chain-Angriff"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "de"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPass gab bekannt, dass Angreifer OAuth-Tokens von der Drittanbieter-App Klue gestohlen haben, um in der Salesforce-Umgebung auf Kundendaten zuzugreifen."
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "LastPass Salesforce-Umgebung"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPass gab bekannt, dass Angreifer OAuth-Tokens von der Drittanbieter-App Klue gestohlen haben, um in der Salesforce-Umgebung auf Kundendaten zuzugreifen.

{{< cyber-report severity="High" source="BleepingComputer" target="LastPass Salesforce-Umgebung" >}}

LastPass hat bestätigt, dass Hacker nach dem Diebstahl von OAuth-Tokens des Unternehmens beim Klue-Supply-Chain-Angriff Anfang des Monats auf Kundendaten in der Salesforce-Umgebung zugegriffen haben. Der am 23. Juni 2026 bekannt gegebene Vorfall unterstreicht die Risiken von Drittanbieter-Integrationen und Token-Diebstahl.

{{< ad-banner >}}

Die Angreifer nutzten kompromittierte OAuth-Tokens von Klue, einer Drittanbieter-Anwendung, um unbefugten Zugriff auf die Salesforce-Instanz von LastPass zu erlangen. Dieser Supply-Chain-Angriff ermöglichte es den Bedrohungsakteuren, Kundendaten zu exfiltrieren, ohne typische Authentifizierungswarnungen auszulösen.

LastPass benachrichtigt betroffene Kunden und hat die kompromittierten Tokens widerrufen. Das Unternehmen überprüft außerdem seine Drittanbieter-Zugriffsrichtlinien, um ähnliche Vorfälle zu verhindern. Dieser Vorfall unterstreicht die Bedeutung der Überwachung der OAuth-Token-Nutzung und der Implementierung strenger Zugriffskontrollen für integrierte Dienste.

{{< netrunner-insight >}}

Dieser Vorfall ist ein Paradebeispiel für Supply-Chain-Risiken durch Missbrauch von OAuth-Tokens. SOC-Analysten sollten die Überwachung auf anomale Token-Nutzung priorisieren und Token-Ablaufrichtlinien implementieren. DevSecOps-Teams müssen das Prinzip der geringsten Privilegien für Drittanbieter-Integrationen durchsetzen und die Verwendung kurzlebiger Tokens in Betracht ziehen, um den Schadensradius zu verringern.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
