---
title: "Drei OpenClaw-Schwachstellen ermöglichen Angriffskette von WhatsApp auf den Host"
date: "2026-07-11T08:46:01Z"
original_date: "2026-07-10T14:19:50"
lang: "de"
translationKey: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
slug: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
author: "NewsBot (Validated by Federico Sella)"
description: "Ein Forscher beschreibt drei hochriskante OpenClaw-Sicherheitslücken, die Diebstahl von Anmeldedaten, Privilegieneskalation und Codeausführung auf dem Host ermöglichen könnten."
original_url: "https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html"
source: "The Hacker News"
severity: "High"
target: "OpenClaw KI-Assistent"
cve: null
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ein Forscher beschreibt drei hochriskante OpenClaw-Sicherheitslücken, die Diebstahl von Anmeldedaten, Privilegieneskalation und Codeausführung auf dem Host ermöglichen könnten.

{{< cyber-report severity="High" source="The Hacker News" target="OpenClaw KI-Assistent" cvss="8.8" >}}

Details zu drei inzwischen behobenen Sicherheitslücken im persönlichen KI-Assistenten OpenClaw sind bekannt geworden, die bei erfolgreicher Ausnutzung den Diebstahl von Anmeldedaten, Privilegieneskalation und beliebige Codeausführung auf dem Host ermöglichen könnten. Die Schwachstellen wurden von einem Forscher offengelegt, der eine Angriffskette beschrieb, die von WhatsApp-Nachrichten ausgeht.

{{< ad-banner >}}

Eine der Schwachstellen, verfolgt als GHSA-hjr6-g723-hmfm mit einem CVSS-Score von 8.8, wird als hochriskant eingestuft. Die genaue Art der anderen beiden Schwachstellen wurde nicht vollständig beschrieben, aber sie stellen gemeinsam ein erhebliches Risiko für Benutzer dar, die OpenClaw mit Messaging-Plattformen wie WhatsApp integrieren.

Die Angriffskette nutzt die Fähigkeit des KI-Assistenten, Nachrichten zu verarbeiten, was es einem Angreifer möglicherweise ermöglicht, Privilegien zu eskalieren und beliebigen Code auf dem Host-System auszuführen. Benutzer werden aufgefordert, die neuesten Patches anzuwenden, um diese Risiken zu mindern.

{{< netrunner-insight >}}

Diese Angriffskette verdeutlicht die Risiken der Integration von KI-Assistenten mit Messaging-Plattformen. SOC-Analysten sollten auf ungewöhnliche Prozessausführungen achten, die von KI-Assistenten-Komponenten ausgehen, während DevSecOps-Teams sicherstellen müssen, dass solche Integrationen in einer Sandbox ausgeführt und zeitnah gepatcht werden.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html)**
