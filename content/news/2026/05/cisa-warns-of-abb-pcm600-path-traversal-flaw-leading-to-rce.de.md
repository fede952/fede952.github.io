---
title: "CISA warnt vor Path-Traversal-Schwachstelle in ABB PCM600, die zu RCE führen kann"
date: "2026-05-01T08:59:15Z"
original_date: "2026-04-30T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-abb-pcm600-path-traversal-flaw-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB PCM600 Versionen 1.5 bis 2.13 sind anfällig für eine Path-Traversal-Schwachstelle (CVE-2018-1002208), die eine beliebige Codeausführung ermöglichen könnte. Aktualisieren Sie auf Version 2.14."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02"
source: "CISA"
severity: "Medium"
target: "ABB PCM600"
cve: "CVE-2018-1002208"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB PCM600 Versionen 1.5 bis 2.13 sind anfällig für eine Path-Traversal-Schwachstelle (CVE-2018-1002208), die eine beliebige Codeausführung ermöglichen könnte. Aktualisieren Sie auf Version 2.14.

{{< cyber-report severity="Medium" source="CISA" target="ABB PCM600" cve="CVE-2018-1002208" >}}

CISA hat eine Warnung (ICSA-26-120-02) zu einer Schwachstelle in ABB PCM600, einem Schutz- und Steuerungs-IED-Manager, veröffentlicht. Der als CVE-2018-1002208 identifizierte Fehler existiert in der Bibliothek SharpZip.dll und beinhaltet eine unzureichende Beschränkung eines Pfadnamens auf ein eingeschränktes Verzeichnis (Path Traversal). Eine erfolgreiche Ausnutzung könnte es einem Angreifer ermöglichen, speziell gestaltete Nachrichten an den Systemknoten zu senden, was zu einer beliebigen Codeausführung führt.

{{< ad-banner >}}

Die betroffenen Produktversionen sind PCM600 von 1.5 bis einschließlich 2.13. ABB hat Version 2.14 zur Behebung des Problems veröffentlicht. Beachten Sie jedoch, dass RE_630-Schutzrelais nicht mit PCM600 2.14 kompatibel sind. Benutzer früherer Versionen mit RE_630 müssen daher auf systemseitige Schutzmaßnahmen gemäß den allgemeinen Sicherheitsempfehlungen von ABB zurückgreifen.

Die Warnung hebt hervor, dass das Produkt weltweit im Bereich der Kritischen Fertigungsindustrie eingesetzt wird. Obwohl in der Warnung kein CVSS-Score angegeben ist, rechtfertigt das Potenzial der Schwachstelle für Codeausführung eine schnelle Behebung, wo möglich. Organisationen sollten die Aktualisierung auf PCM600 2.14 priorisieren und Netzwerksegmentierung sowie Zugriffskontrollen für Systeme implementieren, die nicht sofort aktualisiert werden können.

{{< netrunner-insight >}}

Diese Path-Traversal-Schwachstelle in ABB PCM600 erinnert daran, dass Legacy-Abhängigkeiten wie SharpZip.dll ein Risiko darstellen können. Für SOC-Analysten: Überwachen Sie den Netzwerkverkehr zu PCM600-Knoten auf Anomalien, insbesondere auf speziell gestaltete Nachrichten, die auf Ausnutzungsversuche hindeuten könnten. DevSecOps-Ingenieure sollten alle Instanzen von PCM600 inventarisieren und Upgrades auf Version 2.14 planen, während die Kompatibilität mit RE_630-Relais durch kompensierende Kontrollen sichergestellt wird.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02)**
