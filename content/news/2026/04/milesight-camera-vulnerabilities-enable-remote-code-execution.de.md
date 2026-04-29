---
title: "Milesight-Kamera-Sicherheitslücken ermöglichen Remote-Codeausführung"
date: "2026-04-29T07:21:59Z"
original_date: "2026-04-23T12:00:00"
lang: "de"
translationKey: "milesight-camera-vulnerabilities-enable-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor mehreren Milesight-Kameramodellen, die von kritischen Sicherheitslücken (CVE-2026-28747 usw.) betroffen sind, die zu Geräteabstürzen oder Remote-Codeausführung führen können."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03"
source: "CISA"
severity: "Critical"
target: "Milesight IP-Kameras"
cve: "CVE-2026-28747"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor mehreren Milesight-Kameramodellen, die von kritischen Sicherheitslücken (CVE-2026-28747 usw.) betroffen sind, die zu Geräteabstürzen oder Remote-Codeausführung führen können.

{{< cyber-report severity="Critical" source="CISA" target="Milesight IP-Kameras" cve="CVE-2026-28747" >}}

CISA hat eine Sicherheitsmeldung (ICSA-26-113-03) veröffentlicht, die mehrere Sicherheitslücken in einer Vielzahl von Milesight-Kameramodellen detailliert beschreibt. Die als CVE-2026-28747, CVE-2026-27785, CVE-2026-32644, CVE-2026-32649 und CVE-2026-20766 identifizierten Schwachstellen betreffen Firmware-Versionen mehrerer Produktlinien, darunter MS-Cxx63-PD, MS-Cxx64-xPD und andere. Eine erfolgreiche Ausnutzung könnte es einem Angreifer ermöglichen, das Gerät zum Absturz zu bringen oder Remote-Codeausführung zu erreichen.

{{< ad-banner >}}

Die betroffenen Modelle erstrecken sich über mehrere Serien mit Firmware-Versionen bis zu 51.7.0.77-r12, 3x.8.0.3-r11, 63.8.0.4-r3 und anderen. Angesichts der kritischen Natur der Remote-Codeausführung stellen diese Sicherheitslücken ein erhebliches Risiko für Organisationen dar, die Milesight-Kameras in Überwachungs- oder IoT-Bereitstellungen einsetzen. CISA empfiehlt Benutzern, verfügbare Patches anzuwenden und die Anleitungen des Herstellers zu befolgen, um die Gefährdung zu verringern.

Obwohl in der Sicherheitsmeldung keine CVSS-Werte oder Hinweise auf aktive Ausnutzung angegeben sind, erfordert das Potenzial für Gerätekompromittierung und Netzwerkeinbruch sofortige Aufmerksamkeit. Sicherheitsteams sollten betroffene Kameramodelle inventarisieren, IoT-Geräte von kritischen Netzwerken trennen und Firmware-Updates priorisieren.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf anomalen Datenverkehr aus Kamera-Subnetzen und stellen Sie sicher, dass diese Geräte isoliert sind. DevSecOps-Ingenieure sollten das Patchen aller Milesight-Kameras beschleunigen, da Remote-Codeausführungsschwachstellen in Edge-Geräten oft zu Einstiegspunkten für laterale Bewegungen werden. Behandeln Sie diese CVEs als kritisch, bis Hersteller-Patches verifiziert sind.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03)**
