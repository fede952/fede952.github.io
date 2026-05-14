---
title: "Windows BitLocker Zero-Day-Bypass-PoC veröffentlicht: YellowKey und GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "de"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "Proof-of-Concept-Exploits für zwei ungepatchte Windows-Sicherheitslücken – YellowKey (BitLocker-Bypass) und GreenPlasma (Privilegieneskalation) – wurden veröffentlicht und gefährden verschlüsselte Laufwerke."
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "Durch Windows BitLocker geschützte Laufwerke"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Proof-of-Concept-Exploits für zwei ungepatchte Windows-Sicherheitslücken – YellowKey (BitLocker-Bypass) und GreenPlasma (Privilegieneskalation) – wurden veröffentlicht und gefährden verschlüsselte Laufwerke.

{{< cyber-report severity="High" source="BleepingComputer" target="Durch Windows BitLocker geschützte Laufwerke" >}}

Ein Cybersicherheitsforscher hat Proof-of-Concept (PoC)-Exploits für zwei ungepatchte Microsoft Windows-Sicherheitslücken veröffentlicht, die als YellowKey und GreenPlasma bezeichnet werden. YellowKey ist ein BitLocker-Bypass, der Angreifern den Zugriff auf Daten auf geschützten Laufwerken ohne ordnungsgemäße Authentifizierung ermöglicht, während GreenPlasma ein Privilegieneskalationsfehler ist, der es einem Angreifer ermöglichen könnte, erhöhte Berechtigungen auf einem kompromittierten System zu erlangen.

{{< ad-banner >}}

Die Veröffentlichung dieser PoCs erhöht das Risiko einer Ausnutzung, da Bedrohungsakteure die Techniken nun bewaffnen können. Organisationen, die BitLocker für die vollständige Festplattenverschlüsselung verwenden, sollten ihre Gefährdung bewerten und zusätzliche Sicherheitskontrollen in Betracht ziehen, wie die Aktivierung von TPM+PIN-Schutz oder die Verwendung von Pre-Boot-Authentifizierung.

Microsoft hat noch keine Patches für diese Sicherheitslücken veröffentlicht, sodass Systeme bis zur Bereitstellung von Fixes exponiert bleiben. Sicherheitsteams sollten auf ungewöhnliche Zugriffsmuster auf verschlüsselte Laufwerke achten und wo möglich Workarounds anwenden, wie das Deaktivieren unnötiger Startoptionen oder die Durchsetzung strenger PIN-Richtlinien.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie die Überwachung auf unbefugte Zugriffsversuche auf BitLocker-geschützte Laufwerke und Privilegieneskalationsereignisse. DevSecOps-Ingenieure sollten ihre Umgebungen gegen die veröffentlichten PoCs testen, um anfällige Konfigurationen zu identifizieren und kompensierende Kontrollen wie Secure Boot und gemessene Boot-Protokolle zu implementieren.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
