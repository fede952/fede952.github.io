---
title: "Isolated-vm Sandbox-Escape-Schwachstelle ermöglicht RCE in beliebter JavaScript-Bibliothek"
date: "2026-08-21T07:37:09Z"
original_date: "2026-08-20T13:48:24"
lang: "de"
translationKey: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
slug: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
author: "NewsBot (Validated by Federico Sella)"
description: "Kritischer Fehler in isolated-vm ermöglicht es sandboxed JavaScript, auf den Host auszubrechen und potenzielle Remote-Codeausführung zu ermöglichen. Alle Versionen bis einschließlich 7.0.0 sind betroffen."
original_url: "https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html"
source: "The Hacker News"
severity: "Critical"
target: "isolated-vm JavaScript-Sandbox-Bibliothek"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Kritischer Fehler in isolated-vm ermöglicht es sandboxed JavaScript, auf den Host auszubrechen und potenzielle Remote-Codeausführung zu ermöglichen. Alle Versionen bis einschließlich 7.0.0 sind betroffen.

{{< cyber-report severity="Critical" source="The Hacker News" target="isolated-vm JavaScript-Sandbox-Bibliothek" >}}

Eine kritische Sicherheitslücke wurde in isolated-vm, einer weit verbreiteten Open-Source-JavaScript-Sandbox-Bibliothek mit über 2.900 GitHub-Sternen und 190 Forks, aufgedeckt. Der Fehler, der als GHSA-864f-rcv7-6rh4 verfolgt wird, ermöglicht es Angreifern, die Sandbox-Umgebung zu verlassen und potenziell beliebigen Code auf dem Host-System auszuführen. Alle Versionen der Bibliothek bis einschließlich 7.0.0 sind betroffen.

{{< ad-banner >}}

Die Schwachstelle ist besonders besorgniserregend, da isolated-vm entwickelt wurde, um eine sichere Grenze für die Ausführung von nicht vertrauenswürdigem JavaScript-Code zu bieten. Ein erfolgreicher Sandbox-Escape könnte die Host-Anwendung und die zugrunde liegende Infrastruktur gefährden. Obwohl noch keine CVE-Kennung vergeben wurde, unterstreicht das Advisory die Notwendigkeit sofortiger Aufmerksamkeit für Entwickler, die diese Bibliothek verwenden.

Organisationen, die auf isolated-vm angewiesen sind, sollten Patches überwachen und mitigierende Kontrollen in Betracht ziehen, wie z. B. die Einschränkung der Ausführung von nicht vertrauenswürdigem Code oder die Anwendung zusätzlicher Isolationsschichten. Das Fehlen einer CVE zu diesem Zeitpunkt mindert den Schweregrad nicht, da Proof-of-Concept-Exploits möglicherweise bereits in der Sicherheitsgemeinschaft kursieren.

{{< netrunner-insight >}}

Dieser Sandbox-Escape ist eine deutliche Erinnerung daran, dass selbst speziell entwickelte Isolationstools kritische Schwachstellen aufweisen können. SOC-Analysten sollten alle Anwendungen inventarisieren, die isolated-vm verwenden, und das Patchen priorisieren, sobald ein Fix verfügbar ist. DevSecOps-Teams sollten auch ihre Sandboxing-Strategien überprüfen und Defense-in-Depth in Betracht ziehen, z. B. die Ausführung von Sandboxes in separaten Containern oder VMs, um den Blast-Radius zu begrenzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html)**
