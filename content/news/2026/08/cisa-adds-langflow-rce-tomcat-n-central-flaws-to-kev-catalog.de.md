---
title: "CISA nimmt Langflow-RCE-, Tomcat- und N-central-Schwachstellen in den KEV-Katalog auf"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "de"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA kennzeichnet drei aktiv ausgenutzte Schwachstellen, darunter Langflow RCE (CVE-2026-9198) mit CVSS 9.8, und drängt auf sofortiges Patchen."
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow, Apache Tomcat, N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA kennzeichnet drei aktiv ausgenutzte Schwachstellen, darunter Langflow RCE (CVE-2026-9198) mit CVSS 9.8, und drängt auf sofortiges Patchen.

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow, Apache Tomcat, N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

Die US-amerikanische Behörde für Cybersicherheit und Infrastruktursicherheit (CISA) hat drei Schwachstellen in ihren Katalog bekannter ausgenutzter Schwachstellen (KEV) aufgenommen und verweist auf Beweise für aktive Ausnutzung. Darunter ist CVE-2026-9198, ein kritischer Code-Injection-Fehler in Langflow, der es nicht authentifizierten Angreifern ermöglicht, vollständige Remote-Codeausführung zu erreichen. Die Schwachstelle hat einen CVSS-Score von 9.8, was auf ein schwerwiegendes Risiko hinweist.

{{< ad-banner >}}

Die anderen beiden Fehler betreffen Apache Tomcat und N-central, wobei in der Zusammenfassung keine spezifischen Details genannt werden. Der KEV-Katalog von CISA ist eine priorisierte Liste von Schwachstellen, von denen bekannt ist, dass sie ausgenutzt werden, und Bundesbehörden sind verpflichtet, diese innerhalb bestimmter Fristen zu beheben. Organisationen werden aufgefordert, den Katalog zu überprüfen und Patches sofort anzuwenden.

Die Aufnahme dieser Schwachstellen unterstreicht die Bedeutung eines zeitnahen Patch-Managements und von Bedrohungsinformationen. Sicherheitsteams sollten auf Indikatoren für eine Kompromittierung im Zusammenhang mit diesen CVEs achten und sicherstellen, dass ihre Systeme nicht bekannten Angriffsvektoren ausgesetzt sind.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie die Überwachung auf Ausnutzungsversuche gegen Langflow, Tomcat und N-central, da diese nun bestätigte aktive Ziele sind. DevSecOps sollte das Patchen beschleunigen, insbesondere bei internetexponierten Instanzen, und erwägen, zusätzliche Erkennungsregeln für Aktivitäten nach der Ausnutzung zu implementieren. Angesichts des kritischen CVSS-Scores behandeln Sie CVE-2026-9198 als Risiko der höchsten Stufe und validieren Sie, dass kein unbefugter Zugriff erfolgt ist.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
