---
title: "CSS-Angriffe durchbrechen E-Mail-Grenzen, um Passwörter und Tokens zu stehlen"
date: "2026-08-09T07:52:16Z"
original_date: "2026-08-08T08:03:57"
lang: "de"
translationKey: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
slug: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Neue Forschungsergebnisse zeigen CSS-basierte Angriffe, die aus dem E-Mail-Inhalt ausbrechen, um Webmail-Oberflächen zu kapern und Anmeldedaten sowie Tokens bei großen Anbietern zu stehlen."
original_url: "https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html"
source: "The Hacker News"
severity: "High"
target: "Webmail-Oberflächen (Outlook, Gmail, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Neue Forschungsergebnisse zeigen CSS-basierte Angriffe, die aus dem E-Mail-Inhalt ausbrechen, um Webmail-Oberflächen zu kapern und Anmeldedaten sowie Tokens bei großen Anbietern zu stehlen.

{{< cyber-report severity="High" source="The Hacker News" target="Webmail-Oberflächen (Outlook, Gmail, etc.)" >}}

Der Sicherheitsforscher Gareth von PortSwigger hat eine neuartige Klasse von Angriffen aufgedeckt, die CSS nutzen, um die vorgesehene Isolierung zwischen E-Mail-Inhalt und der umgebenden Webmail-Oberfläche zu durchbrechen. Durch das Erstellen bösartiger E-Mails kann ein Angreifer bewirken, dass Inhalte ihre Nachrichtengrenze überschreiten und die Benutzeroberfläche des Webmail-Dienstes stören, wodurch möglicherweise Passwörter erfasst, Sitzungstokens gestohlen und vertrauenswürdige Benutzeraktionen gekapert werden.

{{< ad-banner >}}

Die Forschung demonstriert Angriffsketten, die große Webmail-Anbieter wie Outlook, Gmail, Fastmail, Proton Mail, Yahoo Mail und AOL Mail betreffen. Über den Diebstahl von Anmeldedaten hinaus können die Techniken verwendet werden, um Konten von Drittanbietern zu übernehmen, sensible Tokens preiszugeben und sogar KI-Tools zu manipulieren, die E-Mails lesen, was die Angriffsfläche erheblich vergrößert.

Diese Erkenntnisse verdeutlichen eine grundlegende Schwäche in der Art und Weise, wie Webmail-Clients nicht vertrauenswürdige Inhalte rendern. Obwohl noch keine spezifische CVE zugewiesen wurde, sind die Auswirkungen schwerwiegend, und Organisationen, die auf Webmail angewiesen sind, sollten Updates im Auge behalten und zusätzliche Sicherheitsebenen in Betracht ziehen, um eine mögliche Ausnutzung zu verhindern.

{{< netrunner-insight >}}

Diese Forschung unterstreicht, dass E-Mail nicht nur ein Vektor für Malware ist, sondern auch eine Waffe gegen genau die Oberfläche sein kann, der Benutzer vertrauen. SOC-Analysten sollten verdächtige E-Mails als potenzielle UI-brechende Nutzlasten behandeln, nicht nur als Phishing-Köder. DevSecOps-Teams sollten überprüfen, wie ihre Webmail-Clients Inhalte sandboxen, und in Betracht ziehen, strenge Content Security Policy (CSP)-Header durchzusetzen, um CSS-basierte Ausbruchsversuche zu begrenzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html)**
