---
title: "GigaWiper Backdoor kombiniert Festplattenlöschung, Fake-Ransomware und Spyware"
date: "2026-07-10T10:21:21Z"
original_date: "2026-07-09T18:08:07"
lang: "de"
translationKey: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
slug: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft deckt GigaWiper auf, eine modulare Windows-Backdoor, die drei zerstörerische Werkzeuge bündelt: Festplattenlöscher, Fake-Ransomware und Spyware, was eine ernsthafte Bedrohung für Endpunkte darstellt."
original_url: "https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html"
source: "The Hacker News"
severity: "High"
target: "Windows-Endpunkte"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft deckt GigaWiper auf, eine modulare Windows-Backdoor, die drei zerstörerische Werkzeuge bündelt: Festplattenlöscher, Fake-Ransomware und Spyware, was eine ernsthafte Bedrohung für Endpunkte darstellt.

{{< cyber-report severity="High" source="The Hacker News" target="Windows-Endpunkte" >}}

Microsoft hat eine neue zerstörerische Windows-Backdoor namens GigaWiper identifiziert, die drei ältere Schadprogramme in ein einziges modulares Framework integriert. Die Backdoor bietet Betreibern ein Menü mit Befehlen zur Auswahl, die jeweils eine andere Art von Schaden anrichten sollen: vollständige Festplattenlöschung, Überschreiben des Windows-Systemlaufwerks oder Ausführen von Fake-Ransomware, die Dateien mit einem Schlüssel verschlüsselt, der nie gespeichert wird.

{{< ad-banner >}}

Das modulare Design von GigaWiper ermöglicht es Angreifern, ihre zerstörerischen Aktionen an die Zielumgebung anzupassen. Die Einbeziehung von Festplattenlöschfähigkeiten und Fake-Ransomware deutet darauf hin, dass das Hauptziel darin besteht, maximale Störungen und Datenverluste zu verursachen, anstatt finanziellen Gewinn zu erzielen. Diese Kombination von Techniken macht GigaWiper zu einem vielseitigen und gefährlichen Werkzeug für destruktive Cyber-Operationen.

Während der spezifische Verteilungsvektor nicht bekannt gegeben wird, deutet die Fähigkeit der Backdoor, ganze Festplatten zu löschen und Ransomware-Angriffe zu simulieren, auf ein hohes Maß an Raffinesse hin. Organisationen sollten Endpunkt-Erkennungs- und Reaktionslösungen (EDR) priorisieren und robuste Backup-Strategien sicherstellen, um die Auswirkungen solcher Bedrohungen zu mildern.

{{< netrunner-insight >}}

Für SOC-Analysten unterstreicht GigaWiper die Notwendigkeit von Verhaltenserkennungsregeln, die Massendateioperationen und Festplattenzugriffe auf niedriger Ebene kennzeichnen. DevSecOps-Teams sollten die Integrität von Backups validieren und Wiederherstellungsverfahren regelmäßig testen, da Fake-Ransomware traditionelle Entschlüsselungsansätze umgehen kann. Behandeln Sie jeden unbestätigten Ransomware-Vorfall als potenziellen Wiper-Angriff, bis das Gegenteil bewiesen ist.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)**
