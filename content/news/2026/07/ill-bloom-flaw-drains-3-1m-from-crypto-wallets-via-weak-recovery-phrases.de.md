---
title: "Ill Bloom-Schwachstelle entzieht Krypto-Wallets 3,1 Mio. $ durch schwache Wiederherstellungsphrasen"
date: "2026-07-10T10:19:16Z"
original_date: "2026-07-10T09:00:05"
lang: "de"
translationKey: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
slug: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
author: "NewsBot (Validated by Federico Sella)"
description: "Angreifer nutzen eine Schwachstelle in der Generierung von Wiederherstellungsphrasen für Kryptowährungs-Wallets, genannt Ill Bloom, um bei einer koordinierten Aktion 3,1 Millionen Dollar zu stehlen."
original_url: "https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html"
source: "The Hacker News"
severity: "High"
target: "Kryptowährungs-Wallets"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Angreifer nutzen eine Schwachstelle in der Generierung von Wiederherstellungsphrasen für Kryptowährungs-Wallets, genannt Ill Bloom, um bei einer koordinierten Aktion 3,1 Millionen Dollar zu stehlen.

{{< cyber-report severity="High" source="The Hacker News" target="Kryptowährungs-Wallets" >}}

Die Sicherheitsfirma Coinspect hat eine Schwachstelle in Kryptowährungs-Wallet-Software namens Ill Bloom offengelegt, die es Angreifern ermöglicht, Gelder abzuziehen, indem sie schwache Zufälligkeit bei der Generierung von Wiederherstellungsphrasen ausnutzen. Der Fehler betrifft die Art und Weise, wie einige Wallets die mnemonische Phrase erstellen, die den Zugriff auf die Wallet-Guthaben steuert. Wenn die Zufälligkeit unzureichend ist, kann ein Angreifer die Phrase berechnen und die vollständige Kontrolle über das Wallet erlangen.

{{< ad-banner >}}

Coinspect bestätigte, dass Angreifer diese Schwachstelle bereits bei einer koordinierten Aktion im Mai ausgenutzt haben und dabei etwa 3,1 Millionen Dollar von mehreren Wallets gestohlen haben. Das genaue Datum und der volle Umfang des Angriffs wurden nicht bekannt gegeben, aber der Vorfall unterstreicht die entscheidende Bedeutung sicherer Zufallszahlengenerierung in kryptografischen Anwendungen.

Wallet-Nutzern wird empfohlen, zu überprüfen, ob ihre Software kryptografisch sichere Zufallszahlengeneratoren verwendet, und in Erwägung zu ziehen, Gelder auf Wallets mit geprüften Zufallsimplementierungen zu übertragen. Entwickler sollten ihre Entropiequellen überprüfen und die Einhaltung von Industriestandards wie BIP39 sicherstellen.

{{< netrunner-insight >}}

Dieser Vorfall unterstreicht die Gefahr, sich auf schwache Entropie bei der kryptografischen Schlüsselgenerierung zu verlassen. SOC-Analysten sollten auf ungewöhnliche Wallet-Transaktionen oder Massenbewegungen von Geldern achten, während DevSecOps-Ingenieure alle Zufallszahlengenerierungen in sicherheitskritischen Anwendungen prüfen müssen. Gehen Sie immer davon aus, dass vorhersagbare Zufälligkeit ausgenutzt wird.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html)**
