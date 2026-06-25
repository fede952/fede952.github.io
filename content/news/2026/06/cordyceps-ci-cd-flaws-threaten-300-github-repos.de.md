---
title: "Cordyceps CI/CD-Schwachstellen bedrohen über 300 GitHub-Repos"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "de"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine neue Schwachstelle in CI/CD-Workflows mit dem Codenamen Cordyceps ermöglicht Angreifern, Workflows zu kapern und Open-Source-Lieferketten großer Organisationen zu kompromittieren."
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "CI/CD-Workflows auf GitHub"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine neue Schwachstelle in CI/CD-Workflows mit dem Codenamen Cordyceps ermöglicht Angreifern, Workflows zu kapern und Open-Source-Lieferketten großer Organisationen zu kompromittieren.

{{< cyber-report severity="Critical" source="The Hacker News" target="CI/CD-Workflows auf GitHub" >}}

Cybersicherheitsforscher von Novee Security haben ein kritisches ausnutzbares Muster in CI/CD-Workflows identifiziert, das als Cordyceps bezeichnet wird und Angreifern ermöglicht, Workflows zu kapern und Open-Source-Lieferketten zu kompromittieren. Die Schwachstelle betrifft über 300 GitHub-Repositories großer Organisationen, darunter Microsoft, Google und Apache.

{{< ad-banner >}}

Das Cordyceps-Muster ermöglicht die vollständige Kontrolle über Repositories durch Angreifer, was zu unbefugten Codeänderungen, Einschleusen von Hintertüren und nachgelagerten Lieferkettenangriffen führen kann. Die Schwachstelle resultiert aus unsicheren Workflow-Konfigurationen, die Eingaben nicht ordnungsgemäß isolieren oder validieren.

Organisationen, die GitHub Actions oder ähnliche CI/CD-Plattformen verwenden, werden dringend aufgefordert, ihre Workflow-Definitionen auf das Cordyceps-Muster zu überprüfen und Berechtigungen nach dem Prinzip der geringsten Privilegien, Eingabebereinigung und Umgebungsisolierung zu implementieren, um das Risiko zu mindern.

{{< netrunner-insight >}}

Dies ist ein klassischer Angriffsvektor auf die Lieferkette. SOC-Analysten sollten auf anomale Workflow-Ausführungen und unerwartete Repository-Änderungen achten. DevSecOps-Teams müssen CI/CD-Pipeline-Konfigurationen sofort überprüfen, mit Fokus auf die Behandlung nicht vertrauenswürdiger Eingaben und die Eingrenzung von Berechtigungen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
