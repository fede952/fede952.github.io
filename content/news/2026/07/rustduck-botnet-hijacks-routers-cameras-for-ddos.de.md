---
title: "RustDuck-Botnetz kapert Router und Kameras für DDoS"
date: "2026-07-01T10:41:08Z"
original_date: "2026-06-30T17:45:25"
lang: "de"
translationKey: "rustduck-botnet-hijacks-routers-cameras-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine neue zweistufige Malware-Familie namens RustDuck kapert seit Februar 2026 Heimrouter, IP-Kameras, Android-Boxen und schlecht gesicherte Server, um ein DDoS-Netzwerk aufzubauen."
original_url: "https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html"
source: "The Hacker News"
severity: "High"
target: "Router, IP-Kameras, Android-Boxen, Server"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine neue zweistufige Malware-Familie namens RustDuck kapert seit Februar 2026 Heimrouter, IP-Kameras, Android-Boxen und schlecht gesicherte Server, um ein DDoS-Netzwerk aufzubauen.

{{< cyber-report severity="High" source="The Hacker News" target="Router, IP-Kameras, Android-Boxen, Server" >}}

Forscher von QiAnXins XLab verfolgen seit Februar 2026 eine neue zweistufige Malware-Familie namens RustDuck. Das Botnetz kapert Heimrouter, IP-Kameras, Android-Boxen und schlecht gesicherte Server und webt sie zu einem Netzwerk zusammen, das darauf ausgelegt ist, Websites und Online-Dienste durch DDoS-Angriffe offline zu nehmen.

{{< ad-banner >}}

Die Malware ist bemerkenswert, da sie in Rust neu geschrieben wurde, einer speichersicheren Sprache, die Analyse und Reverse Engineering erschwert. Obwohl die aktuelle Größe des Botnetzes nicht massiv ist, stellt seine schnelle Entwicklung und Anpassungsfähigkeit eine wachsende Bedrohung für die Internetinfrastruktur dar.

RustDuck repräsentiert einen Wandel in der Botnetz-Entwicklung, indem es die Leistungs- und Sicherheitsfunktionen von Rust nutzt, um widerstandsfähigere und schwerer zu erkennende Malware zu schaffen. Das Endziel ist der Aufbau eines robusten DDoS-Netzwerks, das große Ziele ausschalten kann.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf ungewöhnlichen ausgehenden Datenverkehr von IoT-Geräten und Routern, da RustDucks zweistufige Infektion traditionelle Signaturen umgehen kann. DevSecOps-Teams sollten strenge Netzwerksegmentierung durchsetzen und unnötige Dienste auf exponierten Geräten deaktivieren, um die Angriffsfläche zu reduzieren.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html)**
