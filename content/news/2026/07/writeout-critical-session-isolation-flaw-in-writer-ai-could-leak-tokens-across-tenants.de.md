---
title: "WriteOut: Kritischer Fehler in der Sitzungsisolierung von Writer AI könnte Tokens über Mandanten hinweg preisgeben"
date: "2026-07-08T09:23:55Z"
original_date: "2026-07-07T13:27:09"
lang: "de"
translationKey: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
slug: "writeout-critical-session-isolation-flaw-in-writer-ai-could-leak-tokens-across-tenants"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine Ein-Klick-Sicherheitslücke in Writer AI, mit dem Codenamen WriteOut, könnte eine mandantenübergreifende Preisgabe von Sitzungstokens ermöglichen. Der Fehler wurde inzwischen behoben."
original_url: "https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html"
source: "The Hacker News"
severity: "Critical"
target: "Writer AI Enterprise-Plattform"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine Ein-Klick-Sicherheitslücke in Writer AI, mit dem Codenamen WriteOut, könnte eine mandantenübergreifende Preisgabe von Sitzungstokens ermöglichen. Der Fehler wurde inzwischen behoben.

{{< cyber-report severity="Critical" source="The Hacker News" target="Writer AI Enterprise-Plattform" >}}

Cybersicherheitsforscher von Sand Security haben eine kritische Schwachstelle in der Sitzungsisolierung von Writer, einer generativen KI-Plattform für Unternehmen, offengelegt. Der als WriteOut bezeichnete Fehler könnte es einem Angreifer ermöglichen, Sitzungstokens über Mandanten hinweg preiszugeben, was mit einem einzigen Klick zu einer mandantenübergreifenden Kompromittierung führt.

{{< ad-banner >}}

Die Schwachstelle beruht auf einer unzureichenden Sitzungsisolierung in der Agentenvorschaufunktion, die es einem Außenstehenden ermöglicht, von keinem Zugriff zur vollständigen Übernahme eines beliebigen Writer AI-Mandanten zu gelangen. Writer hat das Problem inzwischen behoben, aber die Entdeckung unterstreicht die Risiken von Multi-Tenant-KI-Plattformen.

Organisationen, die Writer AI nutzen, sollten sicherstellen, dass die neuesten Patches angewendet wurden, und die Konfiguration der Sitzungsverwaltung überprüfen. Die WriteOut-Sicherheitslücke dient als Erinnerung daran, der Mandantenisolierung in cloudbasierten KI-Diensten Priorität einzuräumen.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf anomale Nutzung von Sitzungstokens und mandantenübergreifende Zugriffsmuster in den Writer AI-Protokollen. DevSecOps-Teams sollten eine strenge Sitzungsisolierung durchsetzen und in Multi-Tenant-KI-Bereitstellungen zusätzliche Mandantengrenzprüfungen in Betracht ziehen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/writer-ai-flaw-could-let-agent-previews.html)**
