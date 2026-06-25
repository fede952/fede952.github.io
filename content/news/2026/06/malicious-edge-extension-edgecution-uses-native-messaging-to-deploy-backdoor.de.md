---
title: "Bösartige Edge-Erweiterung 'Edgecution' nutzt Native Messaging zur Hintertür-Installation"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "de"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine bösartige Microsoft Edge-Erweiterung namens 'Edgecution' umgeht die Browser-Sandbox über Native Messaging, um in Ransomware-Angriffen eine Python-basierte Hintertür zu installieren."
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Edge-Nutzer"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine bösartige Microsoft Edge-Erweiterung namens 'Edgecution' umgeht die Browser-Sandbox über Native Messaging, um in Ransomware-Angriffen eine Python-basierte Hintertür zu installieren.

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Edge-Nutzer" >}}

Eine bösartige Microsoft Edge-Erweiterung namens 'Edgecution' wurde in einem Ransomware-Angriff beobachtet, bei dem sie die Native Messaging API des Browsers nutzt, um die Sandbox zu umgehen und beliebigen Code auf dem Hostsystem auszuführen. Die Erweiterung fungiert als Brücke zur Installation einer Python-basierten Hintertür, die persistenten Zugriff und weitere schädliche Aktivitäten ermöglicht.

{{< ad-banner >}}

Die Angriffskette beginnt mit der Installation der schädlichen Erweiterung, die dann Native Messaging missbraucht, um mit einer nativen Anwendung außerhalb der Browser-Sandbox zu kommunizieren. Diese Technik umgeht typische Browser-Sicherheitsgrenzen und erlaubt es dem Angreifer, Befehle auszuführen und weitere Nutzlasten, einschließlich Ransomware, abzulegen.

Sicherheitsforscher betonen, dass diese Methode besonders heimtückisch ist, da sie eine legitime Browserfunktion ausnutzt, was die Erkennung durch herkömmliche Endpunktsicherheitslösungen erschwert. Organisationen wird empfohlen, auf nicht autorisierte Browsererweiterungen zu achten und Native Messaging-Berechtigungen nach Möglichkeit einzuschränken.

{{< netrunner-insight >}}

Dieser Angriff unterstreicht die Bedeutung der Überwachung von Browsererweiterungsinstallationen und Native Messaging-Aktivitäten. SOC-Analysten sollten auf anomale Erweiterungsverhalten und unerwartete native Host-Kommunikation achten, während DevSecOps-Teams strenge Erweiterungs-Whitelists durchsetzen und unnötige Native Messaging-Hosts deaktivieren sollten.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
