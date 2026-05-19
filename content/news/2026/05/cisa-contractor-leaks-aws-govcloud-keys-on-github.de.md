---
title: "CISA-Auftragnehmer gibt AWS GovCloud-Schlüssel auf GitHub preis"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "de"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "Ein Auftragnehmer der CISA hat AWS GovCloud-Anmeldedaten und interne Build-Details in einem öffentlichen GitHub-Repository offengelegt – einer der schwerwiegendsten Regierungsdatenlecks."
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "CISA AWS GovCloud-Konten"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ein Auftragnehmer der CISA hat AWS GovCloud-Anmeldedaten und interne Build-Details in einem öffentlichen GitHub-Repository offengelegt – einer der schwerwiegendsten Regierungsdatenlecks.

{{< cyber-report severity="Critical" source="Krebs on Security" target="CISA AWS GovCloud-Konten" >}}

Bis zum vergangenen Wochenende unterhielt ein Auftragnehmer der Cybersecurity & Infrastructure Security Agency (CISA) ein öffentliches GitHub-Repository, das Anmeldedaten für mehrere hochprivilegierte AWS GovCloud-Konten und eine große Anzahl interner CISA-Systeme offenlegte. Sicherheitsexperten erklärten, dass das öffentliche Archiv Dateien enthielt, die detailliert beschreiben, wie CISA Software intern erstellt, testet und bereitstellt, und dass es eines der schwerwiegendsten Regierungsdatenlecks der letzten Jahre darstellt.

{{< ad-banner >}}

Die offengelegten Anmeldedaten könnten es einem Angreifer ermöglichen, auf sensible Regierungs-Cloud-Umgebungen und interne Systeme zuzugreifen, was potenziell zu Datendiebstahl oder weiteren Kompromittierungen führen könnte. Der Vorfall unterstreicht die Risiken hartcodierter Geheimnisse in öffentlichen Repositories, selbst bei Regierungsauftragnehmern.

{{< netrunner-insight >}}

Dieses Leck verdeutlicht die dringende Notwendigkeit automatisierter Secret-Scans und strenger Zugriffskontrollen für Repositories. SOC-Analysten sollten die Überwachung auf offengelegte Anmeldedaten in öffentlichen Code-Repositories priorisieren, während DevSecOps-Teams Richtlinien zur Geheimnisverwaltung durchsetzen und potenziell kompromittierte Schlüssel sofort rotieren müssen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf Krebs on Security lesen ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
