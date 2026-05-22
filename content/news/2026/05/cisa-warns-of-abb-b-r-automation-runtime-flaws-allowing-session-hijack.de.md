---
title: "CISA warnt vor Schwachstellen in ABB B&R Automation Runtime, die Session-Hijacking ermöglichen"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "Mehrere Schwachstellen in ABB B&R Automation Runtime vor Version 6.4 könnten Angreifern erlauben, Sitzungen zu übernehmen oder Code auszuführen. Die CISA-Warnung ICSA-26-141-04 beschreibt die Korrekturen."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Mehrere Schwachstellen in ABB B&R Automation Runtime vor Version 6.4 könnten Angreifern erlauben, Sitzungen zu übernehmen oder Code auszuführen. Die CISA-Warnung ICSA-26-141-04 beschreibt die Korrekturen.

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

CISA hat die Warnung ICSA-26-141-04 veröffentlicht, die mehrere Schwachstellen in ABB B&R Automation Runtime beschreibt, einer Softwareplattform für die industrielle Automatisierung. Die von B&Rs interner Sicherheitsanalyse identifizierten Fehler betreffen Versionen vor 6.4 und umfassen CVE-2025-3449 (vorhersagbare Sitzungskennungen), CVE-2025-3448 (Cross-Site-Scripting) und CVE-2025-11498 (unzureichende Neutralisierung von Formelelementen in CSV-Dateien). Ein nicht authentifizierter Angreifer könnte diese ausnutzen, um entfernte Sitzungen zu übernehmen oder Code im Kontext des Browsers eines Benutzers auszuführen.

{{< ad-banner >}}

Die schwerwiegendste Schwachstelle, CVE-2025-3449, befindet sich in der Komponente System Diagnostic Manager (SDM) und hat einen CVSS v3-Score von 6,1. Sie ermöglicht es einem nicht authentifizierten netzwerkbasierten Angreifer, bereits bestehende Sitzungen zu übernehmen, da vorhersagbare Zahlen oder Kennungen generiert werden. Der SDM ist in Automation Runtime 6 standardmäßig deaktiviert, was die Gefährdung reduziert, aber Organisationen sollten überprüfen, ob er ausgeschaltet bleibt, es sei denn, er wird explizit benötigt.

ABB hat die Version 6.4 von Automation Runtime veröffentlicht, um diese Probleme zu beheben. Angesichts der weltweiten Verbreitung des Produkts im Energiesektor fordert CISA die Betreiber auf, das Update umgehend einzuspielen. Die Warnung weist darauf hin, dass eine erfolgreiche Ausnutzung zu Remote-Codeausführung oder Session-Übernahme führen kann, was ein erhebliches Risiko für industrielle Steuerungsumgebungen darstellt.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie das Patchen von Automation Runtime-Instanzen, insbesondere solchen mit aktiviertem SDM. Der Fehler mit vorhersagbaren Sitzungs-IDs (CVE-2025-3449) ist trivial über das Netzwerk ausnutzbar. DevSecOps-Teams sollten sicherstellen, dass SDM in der Produktion deaktiviert bleibt, und überprüfen, dass keine exponierten Instanzen aus nicht vertrauenswürdigen Netzwerken erreichbar sind. Überwachen Sie auf anomale Sitzungsaktivitäten als Erkennungssignal.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
