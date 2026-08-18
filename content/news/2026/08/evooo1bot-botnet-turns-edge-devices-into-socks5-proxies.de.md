---
title: "Evooo1Bot-Botnetz macht Edge-Geräte zu SOCKS5-Proxys"
date: "2026-08-18T07:31:16Z"
original_date: "2026-08-17T09:29:55"
lang: "de"
translationKey: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
slug: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "Das neue Linux-Botnetz Evooo1Bot, abgeleitet von Mirai, nutzt bekannte Schwachstellen aus, um Edge-Geräte in SOCKS5-Proxys für heimliche Angriffe zu verwandeln."
original_url: "https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html"
source: "The Hacker News"
severity: "High"
target: "Internet-exponierte Edge-Geräte"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Das neue Linux-Botnetz Evooo1Bot, abgeleitet von Mirai, nutzt bekannte Schwachstellen aus, um Edge-Geräte in SOCKS5-Proxys für heimliche Angriffe zu verwandeln.

{{< cyber-report severity="High" source="The Hacker News" target="Internet-exponierte Edge-Geräte" >}}

Cybersecurity-Forscher haben eine bisher nicht dokumentierte Linux-Botnetz-Familie namens Evooo1Bot identifiziert, die ihre Kernfunktionalität aus dem öffentlich geleakten Mirai-Botnetz-Quellcode ableitet. Die Malware ist darauf ausgelegt, Internet-exponierte Geräte in SOCKS5-Proxys zu verwandeln, wodurch Angreifer bösartigen Datenverkehr über kompromittierte Geräte leiten können.

{{< ad-banner >}}

Während Evooo1Bot die DDoS-Engine von Mirai wiederverwendet, erweitert es das ursprüngliche Framework um zusätzliche Fähigkeiten, einschließlich der Möglichkeit, bekannte Schwachstellen in Edge-Geräten auszunutzen. Dies ermöglicht es dem Botnetz, seine Reichweite zu vergrößern und Persistenz auf kompromittierten Systemen aufrechtzuerhalten.

Die Entdeckung unterstreicht die kontinuierliche Weiterentwicklung von Mirai-basierten Botnetzen, die aufgrund ihrer Fähigkeit, anfällige IoT- und Edge-Geräte in groß angelegte Proxy-Netzwerke zu rekrutieren, weiterhin eine erhebliche Bedrohung darstellen. Organisationen wird empfohlen, bekannte Schwachstellen zu patchen und auf ungewöhnlichen Proxy-Datenverkehr zu achten.

{{< netrunner-insight >}}

Für SOC-Analysten unterstreicht dieses Botnetz die Bedeutung der Überwachung von ausgehendem Proxy-Datenverkehr und der Erkennung ungewöhnlicher SOCKS5-Verbindungen. DevSecOps-Teams sollten die Priorisierung von Patches für bekannte Schwachstellen in Edge-Geräten in Betracht ziehen und Netzwerksegmentierung in Betracht ziehen, um die Auswirkungen solcher Botnetze zu begrenzen. Die Wiederverwendung von Mirai-Code bedeutet, dass bestehende Erkennungssignaturen möglicherweise aktualisiert werden müssen, um diese neue Variante zu erkennen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html)**
