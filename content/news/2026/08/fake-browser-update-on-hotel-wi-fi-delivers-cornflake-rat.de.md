---
title: "Gefälschtes Browser-Update über Hotel-WLAN verteilt CornFlake-RAT"
date: "2026-08-01T09:04:02Z"
original_date: "2026-08-01T06:29:05"
lang: "de"
translationKey: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
slug: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft warnt vor der CaptiveCrunch-Operation, die gekaperte Hotel-WLAN-Netzwerke nutzt, um gefälschte Updates zu verbreiten und die CornFlake-Überwachungsmalware zu liefern."
original_url: "https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html"
source: "The Hacker News"
severity: "High"
target: "Hotel-WLAN-Nutzer"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft warnt vor der CaptiveCrunch-Operation, die gekaperte Hotel-WLAN-Netzwerke nutzt, um gefälschte Updates zu verbreiten und die CornFlake-Überwachungsmalware zu liefern.

{{< cyber-report severity="High" source="The Hacker News" target="Hotel-WLAN-Nutzer" >}}

Microsoft hat eine neue Kampagne namens CaptiveCrunch offengelegt, die gekaperte Hotel-WLAN-Netzwerke nutzt, um gefälschte Browser-Updates auszuliefern. Bei diesen Updates handelt es sich tatsächlich um einen Remote-Access-Trojaner (RAT) namens CornFlake, der in der Lage ist, Webcam-Bilder, Mikrofon-Audio und Tastatureingaben zu erfassen und infizierte Geräte effektiv in Überwachungswerkzeuge zu verwandeln.

{{< ad-banner >}}

Die Operation wird Storm-2945 zugeschrieben, das Microsoft als operativen Teilcluster der bekannten Bedrohungsgruppe Midnight Blizzard einstuft. Dies deutet auf ein hohes Maß an Raffinesse und Ressourcen hin, da die Angriffskette die Kompromittierung der Netzwerkinfrastruktur von Hotels umfasst, um den Benutzerverkehr abzufangen und auf bösartige Update-Seiten umzuleiten.

Obwohl der Bericht keine bestimmte CVE oder CVSS-Bewertung angibt, ist der Angriffsvektor bemerkenswert, da er eine vertrauenswürdige Umgebung (Hotel-WLAN) nutzt, um Malware zu verbreiten. Reisende und Geschäftsleute sind besonders gefährdet, da sie sich oft auf öffentliches WLAN verlassen und möglicherweise eher dazu neigen, Browser-Update-Aufforderungen ohne Prüfung zu akzeptieren.

{{< netrunner-insight >}}

Diese Kampagne unterstreicht, wie wichtig es ist, jede Browser-Update-Aufforderung über nicht vertrauenswürdige Netzwerke mit Misstrauen zu behandeln. SOC-Analysten sollten auf ungewöhnliche ausgehende Verbindungen von Endpunkten achten, die kürzlich mit Hotel- oder öffentlichem WLAN verbunden waren, und in Erwägung ziehen, Update-bezogene Domains zu blockieren oder zu kennzeichnen, die nicht auf der Whitelist der Organisation stehen. Für DevSecOps können strenge Update-Richtlinien und die Verwendung von Enterprise-VPNs für Remote-Mitarbeiter das Risiko solcher Watering-Hole-Angriffe mindern.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html)**
