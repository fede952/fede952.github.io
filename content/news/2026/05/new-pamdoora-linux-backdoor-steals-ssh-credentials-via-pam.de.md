---
title: "Neue PamDOORa Linux-Hintertür stiehlt SSH-Anmeldedaten über PAM"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "de"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine neue Linux-Hintertür namens PamDOORa, die auf einem russischen Cybercrime-Forum für 1.600 US-Dollar verkauft wird, nutzt PAM-Module, um mit einem magischen Passwort und einer TCP-Port-Kombination persistenten SSH-Zugriff zu gewähren."
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "Linux SSH-Server"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine neue Linux-Hintertür namens PamDOORa, die auf einem russischen Cybercrime-Forum für 1.600 US-Dollar verkauft wird, nutzt PAM-Module, um mit einem magischen Passwort und einer TCP-Port-Kombination persistenten SSH-Zugriff zu gewähren.

{{< cyber-report severity="High" source="The Hacker News" target="Linux SSH-Server" >}}

Cybersicherheitsforscher haben eine neue Linux-Hintertür namens PamDOORa entdeckt, die auf dem russischen Cybercrime-Forum Rehub von einem Bedrohungsakteur namens 'darkworm' für 1.600 US-Dollar beworben wird. Die Hintertür ist als PAM-basiertes Post-Exploitation-Toolkit konzipiert, das durch eine Kombination aus einem magischen Passwort und einem bestimmten TCP-Port persistenten SSH-Zugriff ermöglicht.

{{< ad-banner >}}

PamDOORa funktioniert, indem es die SSH-Authentifizierung über bösartige PAM-Module abfängt, sodass Angreifer normale Anmeldedaten umgehen und unbefugten Zugriff erhalten können. Die Verwendung von PAM-Modulen macht die Hintertür heimlich, da sie sich in den standardmäßigen Authentifizierungsablauf des Linux-Systems integriert.

Der Verkauf solcher Tools auf Cybercrime-Foren unterstreicht die zunehmende Kommodifizierung ausgefeilter Angriffswerkzeuge. Organisationen wird empfohlen, auf ungewöhnliche SSH-Authentifizierungsmuster zu achten und sicherzustellen, dass PAM-Konfigurationen regelmäßig überprüft werden.

{{< netrunner-insight >}}

Für SOC-Analysten erfordert die Erkennung von PamDOORa die Überwachung auf unerwartete SSH-Verbindungen auf nicht standardmäßigen Ports und die Korrelation mit PAM-Moduländerungen. DevSecOps-Teams sollten eine strenge PAM-Konfigurationsverwaltung durchsetzen und File-Integrity-Monitoring für /etc/pam.d/ und zugehörige Bibliotheken in Betracht ziehen. Diese Hintertür unterstreicht, wie wichtig es ist, PAM als kritische Sicherheitsgrenze zu behandeln.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
