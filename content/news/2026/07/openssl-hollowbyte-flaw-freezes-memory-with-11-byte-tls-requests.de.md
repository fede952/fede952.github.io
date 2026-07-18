---
title: "OpenSSL HollowByte-Schwachstelle friert Speicher mit 11-Byte-TLS-Anfragen ein"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "de"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "Ein Denial-of-Service-Fehler in OpenSSL, genannt HollowByte, ermöglicht Angreifern, Serverspeicher mit winzigen TLS-Anfragen einzufrieren. Okta's Red Team meldete ihn; Fix wurde ohne CVE ausgeliefert."
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "OpenSSL-Server auf glibc-Systemen"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ein Denial-of-Service-Fehler in OpenSSL, genannt HollowByte, ermöglicht Angreifern, Serverspeicher mit winzigen TLS-Anfragen einzufrieren. Okta's Red Team meldete ihn; Fix wurde ohne CVE ausgeliefert.

{{< cyber-report severity="High" source="The Hacker News" target="OpenSSL-Server auf glibc-Systemen" >}}

Eine neu bekannt gewordene Denial-of-Service-Sicherheitslücke in OpenSSL, von Okta's Red Team HollowByte genannt, erlaubt einem Angreifer, den Serverspeicher mit nur 11 Bytes TLS-Handshake-Daten zu erschöpfen. Der Fehler führt dazu, dass ein ungepatchter OpenSSL-Server bis zu 131 KB Speicher für eine Nachricht reserviert, die nie ankommt, und auf Systemen mit glibc wird dieser Speicher erst freigegeben, wenn der Prozess neu gestartet wird.

{{< ad-banner >}}

OpenSSL lieferte den Fix im Juni 2026 aus, ohne eine CVE-Kennung zu vergeben, eine Sicherheitswarnung herauszugeben oder die Änderung im Changelog zu vermerken. Okta's Red Team, das den Fehler entdeckte und meldete, veröffentlichte Details nach der Veröffentlichung des Fixes. Die Sicherheitslücke betrifft OpenSSL-Server, die auf glibc-basierten Systemen laufen, und macht sie anfällig für Speichererschöpfungsangriffe.

Während der Angriff nur ein einziges TLS ClientHello von 11 Bytes erfordert, kann die Auswirkung in Umgebungen, in denen OpenSSL-Prozesse langlebig sind und viele gleichzeitige Verbindungen verwalten, schwerwiegend sein. Organisationen, die OpenSSL auf glibc betreiben, sollten die Anwendung des Updates vom Juni 2026 priorisieren, um potenzielle Denial-of-Service-Zustände zu verhindern.

{{< netrunner-insight >}}

Dies ist ein klassischer Ressourcenerschöpfungsvektor, der herkömmliches Raten-Limiting umgeht, da der bösartige Datenverkehr wie normale TLS-Handshakes aussieht. SOC-Analysten sollten auf plötzliche Anstiege der Speichernutzung auf OpenSSL-Servern achten, und DevSecOps-Teams sollten sicherstellen, dass das OpenSSL-Update vom Juni 2026 bereitgestellt wird, auch ohne CVE. Das Fehlen einer CVE verringert nicht das operationelle Risiko – behandeln Sie dies als Patch mit hoher Priorität.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
