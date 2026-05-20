---
title: "Sicherheitslücke in ZKTeco-Überwachungskameras legt Anmeldedaten über nicht authentifizierten Port offen"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "de"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor CVE-2026-8598 in ZKTeco-Überwachungskameras, die Diebstahl von Anmeldedaten über einen undokumentierten Port ermöglicht. Patch verfügbar in Firmware V5.0.1.2.20260421."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "ZKTeco CCTV Cameras"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor CVE-2026-8598 in ZKTeco-Überwachungskameras, die Diebstahl von Anmeldedaten über einen undokumentierten Port ermöglicht. Patch verfügbar in Firmware V5.0.1.2.20260421.

{{< cyber-report severity="Critical" source="CISA" target="ZKTeco CCTV Cameras" cve="CVE-2026-8598" cvss="9.1" >}}

CISA hat eine Sicherheitswarnung (ICSA-26-139-04) veröffentlicht, die eine kritische Authentifizierungsumgehungsschwachstelle in ZKTeco-Überwachungskameras beschreibt. Die als CVE-2026-8598 erfasste Schwachstelle betrifft einen undokumentierten Konfigurationsexport-Port, der ohne Authentifizierung zugänglich ist. Ein erfolgreicher Angriff könnte zur Offenlegung von Informationen führen, einschließlich des Abgreifens von Kamera-Anmeldedaten.

{{< ad-banner >}}

Die Schwachstelle betrifft ZKTeco SSC335-GC2063-Face-0b77 Solution Firmware-Versionen vor V5.0.1.2.20260421. Der CVSS v3-Basiswert beträgt 9,1, was auf kritischen Schweregrad hinweist. Die betroffenen Geräte sind weltweit in gewerblichen Einrichtungen im Einsatz, der Hersteller hat seinen Sitz in China.

ZKTeco hat eine gepatchte Firmware-Version V5.0.1.2.20260421 veröffentlicht, um das Problem zu beheben. Benutzer werden dringend aufgefordert, sofort zu aktualisieren. Die Schwachstelle wird unter CWE-288 (Authentifizierungsumgehung über einen alternativen Pfad oder Kanal) klassifiziert.

{{< netrunner-insight >}}

Dies ist ein Paradebeispiel dafür, wie eine freigelegte Debug-Schnittstelle zu einer Hintertür wird. SOC-Analysten sollten sofort nach ZKTeco-Kameras in ihrem Netzwerk suchen und die Firmware-Versionen überprüfen. Für DevSecOps unterstreicht dies die Notwendigkeit, undokumentierte Ports in IoT-Firmware-Builds zu deaktivieren oder durch Firewalls zu schützen. Behandeln Sie jede Kamera mit einer Firmware unter V5.0.1.2.20260421 als kompromittiert, bis das Gegenteil bewiesen ist.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
