---
title: "7-Zip 26.02 behebt RCE-Schwachstelle in bösartigen Archiven"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "de"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "7-Zip hat Version 26.02 veröffentlicht, um eine Remote-Codeausführung-Schwachstelle zu beheben, die durch Öffnen speziell präparierter komprimierter Dateien ausgelöst werden kann. Sofort aktualisieren."
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "7-Zip-Benutzer"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

7-Zip hat Version 26.02 veröffentlicht, um eine Remote-Codeausführung-Schwachstelle zu beheben, die durch Öffnen speziell präparierter komprimierter Dateien ausgelöst werden kann. Sofort aktualisieren.

{{< cyber-report severity="High" source="BleepingComputer" target="7-Zip-Benutzer" >}}

7-Zip Version 26.02 wurde veröffentlicht, um eine Schwachstelle zur Remote-Codeausführung (RCE) zu beheben, die es Angreifern ermöglichen könnte, beliebigen Code auf dem System eines Opfers auszuführen. Der Fehler ist ausnutzbar, indem Benutzer dazu gebracht werden, speziell präparierte komprimierte Dateien zu öffnen, wie Archive mit schädlichen Nutzlasten.

{{< ad-banner >}}

Die Schwachstelle betrifft alle früheren Versionen des beliebten Dateiarchivierers. Obwohl in der Ankündigung keine CVE-Kennung offengelegt wurde, wird der Schweregrad aufgrund des Potenzials für eine vollständige Systemkompromittierung als hoch eingestuft. Benutzern wird dringend empfohlen, sofort auf die neueste Version zu aktualisieren.

Angesichts der weiten Verbreitung von 7-Zip in Unternehmens- und Verbraucherumgebungen ist dieses Update entscheidend, um die Angriffsfläche zu reduzieren. Organisationen sollten die Bereitstellung über automatisierte Update-Mechanismen oder manuelle Installation priorisieren.

{{< netrunner-insight >}}

SOC-Analysten sollten auf ungewöhnliche Archivdateiaktivitäten achten und sicherstellen, dass 7-Zip auf allen Endpunkten aktualisiert wird. DevSecOps-Teams sollten dieses Update in ihre Patch-Management-Pipelines integrieren und erwägen, ältere Versionen von 7-Zip vom Zugriff auf sensible Systeme auszuschließen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
