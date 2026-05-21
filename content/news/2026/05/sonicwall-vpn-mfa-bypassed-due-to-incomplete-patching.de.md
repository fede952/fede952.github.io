---
title: "SonicWall VPN MFA aufgrund unvollständiger Patches umgangen"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "de"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "Bedrohungsakteure erzwingen VPN-Anmeldedaten per Brute-Force und umgehen MFA auf ungepatchten SonicWall Gen6 SSL-VPN Appliances, um Ransomware-Tools einzusetzen."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "SonicWall Gen6 SSL-VPN Appliances"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Bedrohungsakteure erzwingen VPN-Anmeldedaten per Brute-Force und umgehen MFA auf ungepatchten SonicWall Gen6 SSL-VPN Appliances, um Ransomware-Tools einzusetzen.

{{< cyber-report severity="High" source="BleepingComputer" target="SonicWall Gen6 SSL-VPN Appliances" >}}

Es wurde beobachtet, dass Bedrohungsakteure VPN-Anmeldedaten per Brute-Force erbeuten und die Multi-Faktor-Authentifizierung (MFA) auf SonicWall Gen6 SSL-VPN Appliances umgehen. Die Angriffe nutzen unvollständige Patches aus, sodass Angreifer Tools einsetzen können, die typischerweise bei Ransomware-Operationen verwendet werden.

{{< ad-banner >}}

Die Schwachstelle ermöglicht es Angreifern, nach der Kompromittierung von VPN-Anmeldedaten unbefugten Zugriff auf interne Netzwerke zu erlangen. Einmal im Netzwerk, können sie sich lateral bewegen und Ransomware-Payloads einsetzen, was ein erhebliches Risiko für Organisationen darstellt, die auf diese Appliances für den Fernzugriff angewiesen sind.

SonicWall hat Patches zur Behebung des Problems veröffentlicht, aber die unvollständige Anwendung dieser Updates lässt Systeme exponiert. Organisationen werden dringend aufgefordert, zu überprüfen, ob alle empfohlenen Patches vollständig installiert sind, und auf Anzeichen unbefugten VPN-Zugriffs zu achten.

{{< netrunner-insight >}}

Dieser Vorfall unterstreicht die entscheidende Bedeutung eines gründlichen Patch-Managements. SOC-Analysten sollten priorisieren, dass alle SonicWall Gen6 Appliances die neueste Firmware haben, und VPN-Logs auf anomale Authentifizierungsmuster überwachen. DevSecOps-Teams sollten in Betracht ziehen, zusätzliche MFA-Ebenen und Netzwerksegmentierung zu implementieren, um solche Umgehungen zu entschärfen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
