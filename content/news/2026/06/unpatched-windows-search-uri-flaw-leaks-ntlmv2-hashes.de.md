---
title: "Nicht gepatchter Windows-Search-URI-Fehler gibt NTLMv2-Hashes preis"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "de"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Forscher legen eine nicht gepatchte Sicherheitslücke im Windows-Search:-URI-Handler offen, die NTLMv2-Hashes preisgeben kann, ähnlich der Snipping-Tool-Schwachstelle CVE-2026-33829."
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Windows-Search:-URI-Handler"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Forscher legen eine nicht gepatchte Sicherheitslücke im Windows-Search:-URI-Handler offen, die NTLMv2-Hashes preisgeben kann, ähnlich der Snipping-Tool-Schwachstelle CVE-2026-33829.

{{< cyber-report severity="High" source="The Hacker News" target="Windows-Search:-URI-Handler" >}}

Cybersicherheitsforscher von Huntress haben Details zu einer nicht gepatchten Sicherheitslücke im Windows-Search:-URI-Handler veröffentlicht, die es Angreifern ermöglichen könnte, NTLMv2-Hashes zu stehlen. Das Problem erinnert an CVE-2026-33829, eine Spoofing-Schwachstelle im ms-screensketch:-URI-Handler des Windows-Snipping-Tools, die ebenfalls NTLM-Hashes preisgab.

{{< ad-banner >}}

Die neu identifizierte Schwachstelle befindet sich im search:-URI-Schema, das zum Starten von Windows-Suchabfragen verwendet wird. Durch das Erstellen eines bösartigen Links oder einer Datei, die den search:-URI-Handler auslöst, kann ein Angreifer das Zielsystem zwingen, sich bei einem entfernten Server zu authentifizieren, wodurch der NTLMv2-Hash des Benutzers preisgegeben wird. Dieser Hash kann dann offline geknackt oder in Relay-Angriffen verwendet werden.

Zum Zeitpunkt der Veröffentlichung wurde kein offizieller Patch von Microsoft veröffentlicht. Organisationen wird empfohlen, auf Updates zu achten und in Erwägung zu ziehen, den search:-URI-Handler über Gruppenrichtlinien oder Endpunktsicherheitstools zu blockieren, bis ein Fix verfügbar ist.

{{< netrunner-insight >}}

Dies ist ein klassischer NTLM-Relay-Vektor, auf den SOC-Analysten in Authentifizierungsprotokollen achten sollten. DevSecOps-Ingenieure sollten sofort die Verwendung von URI-Handlern in ihren Umgebungen überprüfen und in Erwägung ziehen, Maßnahmen wie die Deaktivierung von NTLMv2 oder die Erzwingung von SMB-Signierung anzuwenden. Bis Microsoft dies patcht, gehen Sie davon aus, dass der search:-URI ein potenzieller Einstiegspunkt für den Diebstahl von Anmeldeinformationen ist.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
