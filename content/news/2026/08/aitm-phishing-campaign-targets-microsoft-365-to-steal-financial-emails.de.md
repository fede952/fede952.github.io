---
title: "AitM-Phishing-Kampagne zielt auf Microsoft 365 ab, um Finanz-E-Mails zu stehlen"
date: "2026-08-08T07:47:42Z"
original_date: "2026-08-07T10:38:27"
lang: "de"
translationKey: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
slug: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "Weit verbreitetes E-Mail-Phishing nutzt Adversary-in-the-Middle, um Microsoft-365-Konten zu übernehmen und Gehalts- und Finanz-E-Mails zu sammeln."
original_url: "https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft-365-Konten"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Weit verbreitetes E-Mail-Phishing nutzt Adversary-in-the-Middle, um Microsoft-365-Konten zu übernehmen und Gehalts- und Finanz-E-Mails zu sammeln.

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft-365-Konten" >}}

Cybersecurity-Forscher haben eine aktive, weit verbreitete E-Mail-Phishing-Kampagne identifiziert, die Adversary-in-the-Middle-Techniken (AitM) nutzt, um Microsoft-365-Konten zu kompromittieren. Das Hauptziel der Kampagne ist es, wichtige Personen in Finanzabläufen zu identifizieren und zugehörige E-Mail-Kommunikation zu exfiltrieren, insbesondere solche, die Gehalts- und Finanzthemen betreffen.

{{< ad-banner >}}

Die Angreifer setzen Residential Proxies ein, um ihre bösartigen Anmeldungen als normalen Verbraucherverkehr zu tarnen und so der Erkennung durch Sicherheitskontrollen zu entgehen, die normalerweise verdächtige IP-Adressen markieren. Diese Technik ermöglicht es den Angreifern, die Kontrolle über die kompromittierten Konten aufrechtzuerhalten und darauf zuzugreifen, ohne sofortige Alarmmeldungen auszulösen.

Organisationen, die Microsoft 365 verwenden, sollten sich vor solchen AitM-Phishing-Versuchen in Acht nehmen, die oft die Multi-Faktor-Authentifizierung umgehen, indem sie Anmeldeinformationen und Sitzungstokens in Echtzeit weiterleiten. Der Fokus der Kampagne auf Finanzdaten deutet auf einen gezielten Versuch hin, Finanzbetrug oder Business-E-Mail-Kompromittierung (BEC) zu erleichtern.

{{< netrunner-insight >}}

Diese Kampagne unterstreicht die Notwendigkeit von phishing-resistenter MFA, wie z. B. FIDO2-Sicherheitsschlüsseln, sowie kontinuierlicher Überwachung auf anomale Anmeldungen, insbesondere solcher, die aus Residential-IP-Bereichen stammen. SOC-Teams sollten auch Erkennungsregeln für AitM-Toolkits priorisieren und Conditional-Access-Richtlinien durchsetzen, die den Zugriff basierend auf Risikosignalen einschränken. DevSecOps-Ingenieure sollten die Implementierung von Sitzungsbindung und Gerätekonformitätsprüfungen in Betracht ziehen, um Token-Relay-Angriffe zu entschärfen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html)**
