---
title: "Klue OAuth-Verstoß: Icarus-Hacker stehlen Salesforce-Tokens"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "de"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue bestätigt Diebstahl von OAuth-Tokens, der Salesforce-Integrationen betrifft; Icarus-Erpressungsgruppe übernimmt Verantwortung und Opferliste wächst."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "Klue Marktinformationsplattform"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue bestätigt Diebstahl von OAuth-Tokens, der Salesforce-Integrationen betrifft; Icarus-Erpressungsgruppe übernimmt Verantwortung und Opferliste wächst.

{{< cyber-report severity="High" source="BleepingComputer" target="Klue Marktinformationsplattform" >}}

Die Marktinformationsplattform Klue hat einen Sicherheitsvorfall bestätigt, bei dem Angreifer OAuth-Tokens gestohlen haben, die zur Verbindung mit den Salesforce-Umgebungen von Kunden verwendet werden. Der Verstoß, für den sich die neu aufgetauchte Erpressungsgruppe 'Icarus' verantwortlich erklärt, hat zu einer wachsenden Liste betroffener Opfer geführt.

{{< ad-banner >}}

Die gestohlenen OAuth-Tokens könnten Angreifern den Zugriff auf Salesforce-Daten ermöglichen, ohne dass eine weitere Authentifizierung erforderlich ist, was ein erhebliches Risiko für Klue-Kunden darstellt. Der Vorfall unterstreicht die Gefahren der Offenlegung von OAuth-Tokens und die Notwendigkeit eines robusten Token-Lebenszyklus-Managements.

Während die Icarus-Gruppe den Angriff öffentlich für sich beansprucht, sollten Organisationen, die die Salesforce-Integration von Klue nutzen, umgehend alle zugehörigen OAuth-Tokens widerrufen und rotieren sowie auf unbefugten Zugriff überwachen. Das volle Ausmaß des Verstoßes wird noch untersucht.

{{< netrunner-insight >}}

Dieser Vorfall unterstreicht die entscheidende Bedeutung der Sicherung von OAuth-Tokens als sensible Anmeldeinformationen. SOC-Analysten sollten die Überwachung auf anomale Salesforce-API-Aufrufe priorisieren und Token-Ablaufrichtlinien durchsetzen. DevSecOps-Teams müssen strenge Token-Bereichs- und Rotationsmechanismen implementieren, um den Schadensradius im Falle einer Kompromittierung zu begrenzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
