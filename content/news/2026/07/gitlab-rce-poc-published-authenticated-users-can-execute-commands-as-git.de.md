---
title: "GitLab RCE PoC veröffentlicht: Authentifizierte Benutzer können Befehle als Git ausführen"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "de"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "Ein Proof-of-Concept-Exploit für eine GitLab-Schwachstelle zur Remote-Codeausführung wurde veröffentlicht, der sich gegen ungepatchte selbstverwaltete 18.11.3-Server richtet. Authentifizierte Benutzer können Befehle als der Git-Benutzer ausführen."
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab selbstverwaltet 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ein Proof-of-Concept-Exploit für eine GitLab-Schwachstelle zur Remote-Codeausführung wurde veröffentlicht, der sich gegen ungepatchte selbstverwaltete 18.11.3-Server richtet. Authentifizierte Benutzer können Befehle als der Git-Benutzer ausführen.

{{< cyber-report severity="High" source="The Hacker News" target="GitLab selbstverwaltet 18.11.3" >}}

Am 24. Juli 2026 veröffentlichten Sicherheitsforscher von depthfirst einen funktionierenden Proof-of-Concept-Exploit für eine GitLab-Schwachstelle zur Remote-Codeausführung. Der Fehler, den GitLab am 10. Juni 2026 behob, erlaubt jedem authentifizierten Benutzer mit Push-Zugriff auf ein Projekt, beliebige Befehle als der Git-Benutzer auf selbstverwalteten GitLab 18.11.3-Servern auszuführen, die das Update nicht angewendet haben.

{{< ad-banner >}}

Der Exploit nutzt ein präpariertes Jupyter-Notebook, das in ein Projekt eingecheckt wird. Wenn der Angreifer den Commit-Diff öffnet, löst das bösartige Notebook einen Heap-Leck aus, der die Befehlsausführung ermöglicht. Diese Technik umgeht typische Authentifizierungskontrollen und erfordert keine speziellen Berechtigungen über den normalen Projektzugriff hinaus.

Organisationen, die selbstverwaltete GitLab-Instanzen betreiben, sollten sofort überprüfen, ob sie den Patch vom 10. Juni angewendet haben. Die öffentliche Verfügbarkeit von Exploit-Code erhöht das Risiko aktiver Ausnutzung, insbesondere für Instanzen, die dem Internet ausgesetzt sind. Blaue Teams sollten auf ungewöhnliche Jupyter-Notebook-Commits und unerwartete Git-Benutzeraktivitäten achten.

{{< netrunner-insight >}}

Dieser Exploit unterstreicht die Gefahr verzögerter Patches in selbstverwalteten CI/CD-Plattformen. SOC-Analysten sollten die Erkennung anomaler Git-Benutzerprozesse und unerwarteter Jupyter-Notebook-Uploads priorisieren. DevSecOps-Teams müssen ein striktes Patch-Fenster für GitLab durchsetzen und Netzwerksegmentierung in Betracht ziehen, um die Exposition selbstverwalteter Instanzen zu begrenzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
