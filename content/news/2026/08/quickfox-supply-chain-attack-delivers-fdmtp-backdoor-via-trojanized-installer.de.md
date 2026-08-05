---
title: "QuickFox-Supply-Chain-Angriff liefert FDMTP-Backdoor über trojanisierten Installer aus"
date: "2026-08-05T09:34:12Z"
original_date: "2026-08-05T05:47:19"
lang: "de"
translationKey: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
slug: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
author: "NewsBot (Validated by Federico Sella)"
description: "Langwieriger Supply-Chain-Angriff auf QuickFox VPN trojanisiert Installer, um FDMTP-Backdoor zu verteilen, der seit August 2025 überseeische chinesische Nutzer angreift."
original_url: "https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html"
source: "The Hacker News"
severity: "High"
target: "QuickFox VPN-Nutzer"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Langwieriger Supply-Chain-Angriff auf QuickFox VPN trojanisiert Installer, um FDMTP-Backdoor zu verteilen, der seit August 2025 überseeische chinesische Nutzer angreift.

{{< cyber-report severity="High" source="The Hacker News" target="QuickFox VPN-Nutzer" >}}

Fortinet FortiGuard Labs hat einen langwierigen Supply-Chain-Angriff auf QuickFox offengelegt, ein VPN- und Netzwerkbeschleunigungstool, das bei überseeischen chinesischen Nutzern beliebt ist. Der Angriff, der seit mindestens August 2025 aktiv ist, beinhaltet eine trojanisierte Version des Windows-Installers der Anwendung, die eine Backdoor namens FDMTP ausliefert.

{{< ad-banner >}}

Der trojanisierte Installer wird über offizielle oder vertrauenswürdige Kanäle verteilt, was die Integrität der Software-Lieferkette gefährdet. Nach der Ausführung bietet FDMTP Angreifern Fernzugriff und Kontrolle über das System des Opfers, was potenziell zu Datendiebstahl, Überwachung oder weiterer Malware-Verbreitung führen kann.

Dieser Vorfall unterstreicht das wachsende Risiko von Supply-Chain-Angriffen auf Nischen-, aber vertrauenswürdige Tools, insbesondere solche, die bestimmte Gemeinschaften bedienen. Organisationen und Einzelpersonen, die QuickFox verwenden, sollten die Integrität ihrer Installationen überprüfen und auf Indikatoren für eine Kompromittierung im Zusammenhang mit FDMTP achten.

{{< netrunner-insight >}}

Dieser Angriff unterstreicht die Notwendigkeit einer robusten Software-Integritätsprüfung, selbst bei Tools von scheinbar seriösen Anbietern. SOC-Analysten sollten nach FDMTP-Indikatoren suchen und auf ungewöhnliche Netzwerkverbindungen von VPN-Clients achten. DevSecOps-Teams müssen Codesignierung und Hash-Verifizierung in ihren Software-Bereitstellungspipelines durchsetzen, um solche Supply-Chain-Risiken zu mindern.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html)**
