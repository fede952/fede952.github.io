---
title: "Neuer wp2shell-WordPress-Kernfehler ermöglicht nicht authentifizierten Angreifern die Codeausführung"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "de"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine anonyme HTTP-Anfrage kann Code auf WordPress-Seiten ausführen. Der Fehler betrifft den Kern, sodass selbst reine Installationen angreifbar sind. Jede 6.9- und 7.0-Seite war bis zum Patch gefährdet."
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "WordPress-Kern (Versionen 6.9 und 7.0)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine anonyme HTTP-Anfrage kann Code auf WordPress-Seiten ausführen. Der Fehler betrifft den Kern, sodass selbst reine Installationen angreifbar sind. Jede 6.9- und 7.0-Seite war bis zum Patch gefährdet.

{{< cyber-report severity="Critical" source="The Hacker News" target="WordPress-Kern (Versionen 6.9 und 7.0)" >}}

Eine kritische Schwachstelle zur nicht authentifizierten Remote-Codeausführung wurde im WordPress-Kern entdeckt, die die Versionen 6.9 und 7.0 betrifft. Der als wp2shell bezeichnete Fehler ermöglicht es einem Angreifer, beliebigen Code auf einer Zielseite auszuführen, indem er eine speziell gestaltete HTTP-Anfrage sendet. Bemerkenswert ist, dass die Schwachstelle in der Kernsoftware existiert, sodass selbst eine frische WordPress-Installation ohne Plugins angreifbar ist.

{{< ad-banner >}}

Die vollständigen technischen Details und ein funktionierender Proof-of-Concept wurden veröffentlicht, zusammen mit CVE-Identifikatoren, die den beiden zugrunde liegenden Fehlern zugewiesen wurden. Es wurde auch eine Bedingung für einen persistenten Objekt-Cache identifiziert, die die Ausnutzung in bestimmten Umgebungen erschweren kann. Alle Seiten, die die betroffenen Versionen ausführen, galten bis zur Anwendung von Patches als gefährdet.

Administratoren werden dringend aufgefordert, sofort auf die neueste gepatchte Version zu aktualisieren. Angesichts der einfachen Ausnutzbarkeit und der weiten Verbreitung von WordPress stellt diese Schwachstelle eine erhebliche Bedrohung für die Websicherheit dar. Organisationen sollten das Patchen priorisieren und ihre Web Application Firewall-Regeln überprüfen, um Exploit-Versuche zu erkennen und zu blockieren.

{{< netrunner-insight >}}

Dies ist ein Paradebeispiel dafür, warum Kernsoftware gegen nicht authentifizierte Angriffe gehärtet werden muss. SOC-Analysten sollten sofort nach WordPress 6.9- und 7.0-Instanzen suchen und den Patch-Status überprüfen. DevSecOps-Teams sollten dies als Erinnerung betrachten, Runtime Application Self-Protection (RASP) zu implementieren und auf anomale HTTP-Anfragen zu achten, die auf wp-admin oder wp-includes abzielen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
