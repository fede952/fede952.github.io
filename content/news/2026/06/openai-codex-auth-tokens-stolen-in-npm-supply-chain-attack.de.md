---
title: "OpenAI Codex Auth Tokens in npm-Supply-Chain-Angriff gestohlen"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "de"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Das bösartige npm-Paket codexui-android zielt auf Entwickler ab und stiehlt OpenAI Codex-Authentifizierungstoken mit über 29.000 wöchentlichen Downloads."
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "OpenAI Codex-Entwickler"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Das bösartige npm-Paket codexui-android zielt auf Entwickler ab und stiehlt OpenAI Codex-Authentifizierungstoken mit über 29.000 wöchentlichen Downloads.

{{< cyber-report severity="High" source="The Hacker News" target="OpenAI Codex-Entwickler" >}}

Cybersecurity-Forscher haben eine bösartige Supply-Chain-Kampagne aufgedeckt, die auf Entwickler abzielt, die OpenAI Codex verwenden. Der Angriff nutzt ein legitim aussehendes npm-Paket namens codexui-android, das sowohl auf GitHub als auch auf npm als Remote-Web-UI für OpenAI Codex beworben wird. Das Paket hat über 29.000 wöchentliche Downloads angezogen, was auf eine erhebliche Reichweite in der Entwicklergemeinschaft hindeutet.

{{< ad-banner >}}

Das bösartige Paket ist darauf ausgelegt, OpenAI Codex-Authentifizierungstoken von ahnungslosen Entwicklern zu stehlen. Zum Zeitpunkt des Berichts ist das Paket weiterhin zum Download verfügbar, was eine anhaltende Bedrohung darstellt. Entwickler, die codexui-android installiert haben, wird empfohlen, ihre Token sofort zu rotieren und ihre Systeme auf unbefugten Zugriff zu überprüfen.

Dieser Vorfall unterstreicht das anhaltende Risiko von Supply-Chain-Angriffen im Open-Source-Ökosystem. Die Verwendung von legitim klingenden Paketnamen und hohen Downloadzahlen kann Entwickler in eine falsche Sicherheit wiegen. Organisationen sollten strenge Paketprüfprozesse implementieren und den Einsatz von Tools in Betracht ziehen, die anomales Paketverhalten erkennen.

{{< netrunner-insight >}}

Für SOC-Analysten und DevSecOps-Ingenieure unterstreicht dieser Angriff die Notwendigkeit, npm-Paket-Downloads und -Verhalten zu überwachen. Implementieren Sie Laufzeiterkennung für unerwartete Token-Exfiltration und setzen Sie das Prinzip der geringsten Privilegien für API-Token durch. Überprüfen Sie regelmäßig Ihre Software-Lieferkette und erwägen Sie den Einsatz von Tools zur Paketintegritätsprüfung.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
