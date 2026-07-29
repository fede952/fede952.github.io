---
title: "„Certighost“-Sicherheitslücke bedroht Microsoft Active Directory-Zertifikate"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "de"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft hat eine Schwachstelle mit hohem Schweregrad behoben, die eine Privilegienausweitung in Active Directory-Umgebungen ermöglicht. SOC-Analysten sollten das Patchen priorisieren."
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Microsoft Active Directory Certificate Services"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft hat eine Schwachstelle mit hohem Schweregrad behoben, die eine Privilegienausweitung in Active Directory-Umgebungen ermöglicht. SOC-Analysten sollten das Patchen priorisieren.

{{< cyber-report severity="High" source="Dark Reading" target="Microsoft Active Directory Certificate Services" >}}

Microsoft hat eine Schwachstelle mit hohem Schweregrad in Active Directory Certificate Services behoben, die als „Certighost“ bezeichnet wird und es einem Angreifer ermöglichen könnte, Privilegien auszuweiten und eine Active Directory-Umgebung zu kompromittieren. Die Sicherheitslücke wurde am 28. Juli 2026 von Dark Reading offengelegt.

{{< ad-banner >}}

Die Schwachstelle betrifft den Zertifikatsregistrierungsprozess und ermöglicht es einem Bedrohungsakteur mit niedrigen Zugriffsrechten, seine Privilegien auf Domänenadministrator auszuweiten. Dies könnte zur vollständigen Kompromittierung der AD-Infrastruktur führen, einschließlich der Möglichkeit, Zertifikate zu fälschen und jeden Benutzer oder jedes Gerät zu impersonieren.

Organisationen, die Microsoft Active Directory Certificate Services verwenden, werden dringend aufgefordert, die neuesten Sicherheitsupdates sofort anzuwenden. Die Schwachstelle unterstreicht die kritische Bedeutung von Zertifikatsdiensten für die Aufrechterhaltung des Vertrauens in AD-Umgebungen.

{{< netrunner-insight >}}

Dies ist ein klassischer Angriffsvektor auf AD-Zertifikatsdienste. Stellen Sie sicher, dass Ihre Zertifikatsvorlagen gehärtet sind und die Registrierungsberechtigungen streng kontrolliert werden. Patchen Sie sofort und überwachen Sie auf ungewöhnliche Zertifikatsanfragen oder Privilegienausweitungen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf Dark Reading lesen ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
