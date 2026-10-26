---
title: "CVSS-4.0-Rechner (mit CVSS 3.1)"
description: "CVSS-4.0-Punktzahl nach der offiziellen MacroVector-Methode von FIRST berechnen, oder CVSS 3.1 mit Basis-, Zeit- und Umgebungswert. Vektor einfügen."
intro: "Wählen Sie die Metriken oder fügen Sie einen Vektor-String ein und erhalten Sie Punktzahl, Schweregrad, Nomenklatur (CVSS-B, BT, BE oder BTE) und MacroVector nach **CVSS 4.0**, berechnet mit **der offiziellen Bewertungslogik und Tabelle von FIRST**. Ein zweiter Tab bewertet **CVSS-3.1**-Vektoren einschließlich zeitlicher und Umgebungswerte. Teilen Sie ein Ergebnis mit einem `?vector=`-Link. Alles läuft im Browser."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["cvss 4.0 rechner", "cvss rechner", "cvss score berechnen", "cvss 3.1 rechner", "cvss punktzahl schwachstelle", "cvss vektor", "cvss 4 macrovector", "schweregrad schwachstelle cvss"]
tags: ["security", "vulnerability", "cvss", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/cvss-calculator/"
tool_title: "CVSS-4.0- und 3.1-Rechner"
tool_height: 1400
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Wählen Sie über die Tabs **CVSS 4.0** oder **CVSS 3.1**."
  - "Fügen Sie einen **Vektor-String** ein (zum Beispiel aus einem Security Advisory) oder klicken Sie den Wert jeder Basismetrik an."
  - "Öffnen Sie bei Bedarf die **Bedrohungs-**, **Umgebungs-** oder in 4.0 die **ergänzenden** Metriken, um die Bewertung an Ihre Umgebung anzupassen."
  - "Lesen Sie **Punktzahl**, **Schweregrad** und in 4.0 die **Nomenklatur**, die zeigt, welche Metrikgruppen genutzt wurden."
  - "Klicken Sie auf **Vektor kopieren** für Berichte oder **Link kopieren**, um eine Seite mit demselben Vektor zu teilen."
faq:
  - q: "Ist die Punktzahl dieselbe wie beim offiziellen FIRST-Rechner?"
    a: "Sie wird mit derselben Methode berechnet: Der CVSS-4.0-Code dieses Tools ist eine Portierung der Bewertungsfunktion des offiziellen FIRST-Rechners und nutzt dessen MacroVector-Tabelle unverändert. Die Tests prüfen alle Beispielvektoren der CVSS-4.0-Beispielseite von FIRST und vergleichen 20.000 Zufallsvektoren mit dem offiziellen Code; CVSS 3.1 wird ebenso mit dem 3.1-Rechner von FIRST verglichen. Diese Website ist nicht mit FIRST verbunden."
  - q: "Warum nutzt CVSS 4.0 keine Formel wie 3.1?"
    a: "CVSS 4.0 fasst die Metriken in sechs Äquivalenzgruppen zusammen und ordnet jeder Kombination, einem MacroVector, eine von Fachleuten festgelegte Punktzahl zu. Die endgültige Punktzahl geht von diesem Wert aus und wird danach angepasst, wie weit der Vektor vom schwersten Vektor desselben MacroVectors entfernt ist. Deshalb zeigt das Tool den MacroVector neben der Punktzahl."
  - q: "Was bedeuten CVSS-B, CVSS-BT, CVSS-BE und CVSS-BTE?"
    a: "Sie geben an, welche Metrikgruppen eine CVSS-4.0-Punktzahl enthält: B nur Basis, T ergänzt die Bedrohungsmetriken (Exploit-Reife), E die Umgebungsmetriken. Die Basispunktzahl aus einem Advisory ist CVSS-B; mit Exploit-Informationen und Ihrer eigenen Umgebung wird sie zu CVSS-BTE."
  - q: "Welche Schweregradstufen gibt es?"
    a: "Die qualitative Skala ist in CVSS 3.1 und 4.0 gleich: Keine 0.0, Niedrig 0.1–3.9, Mittel 4.0–6.9, Hoch 7.0–8.9, Kritisch 9.0–10.0."
  - q: "Ändern die ergänzenden Metriken die Punktzahl?"
    a: "Nein. Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort und Provider Urgency liefern Kontext für Entscheidungen, beeinflussen die CVSS-4.0-Punktzahl aber nicht. Im Vektor erscheinen sie trotzdem."
  - q: "Wird etwas an einen Server gesendet?"
    a: "Nein. Die Berechnung läuft im Browser, und das Tool stellt keine Netzwerkanfragen. Ein geteilter Link enthält nur den Vektor-String."
---

## So funktioniert es

### CVSS 4.0: MacroVectors und die offizielle Tabelle

Die 11 Basismetriken sowie Exploit-Reife und Umgebungsanforderungen werden in sechs Äquivalenzgruppen (EQ1–EQ6) eingeteilt, etwa „wie erreichbar ist das System“ (Angriffsvektor, erforderliche Rechte, Benutzerinteraktion) oder „wie schwer ist die Auswirkung auf das verwundbare System“. Die Stufe jeder Gruppe ergibt einen sechsstelligen **MacroVector**, und die FIRST-Tabelle ordnet jedem der 270 möglichen Werte eine Punktzahl zu. Die Punktzahl des Vektors ist dieser Wert minus einer Anpassung nach seinem Abstand zum schwersten Vektor desselben MacroVectors, auf eine Nachkommastelle gerundet. Die Umsetzung folgt Schritt für Schritt dem offiziellen FIRST-Rechner und nutzt dessen Tabelle wie veröffentlicht (BSD-2-Clause-Lizenz, im Quelltext genannt).

### Umgebungs- und Bedrohungsmetriken

Ohne Angabe gilt für die **Exploit-Reife** der schlimmste Fall (Attacked) und für die Sicherheitsanforderungen High, wie in der Spezifikation. **Modifizierte** Metriken ersetzen die passende Basismetrik für Ihre Umgebung — ein System, das nur aus dem internen Netz erreichbar ist, kann etwa Modified Attack Vector: Adjacent verwenden.

### CVSS 3.1

Der zweite Tab wendet die Gleichungen der CVSS-3.1-Spezifikation an: die Basispunktzahl aus Auswirkung und Ausnutzbarkeit (mit Scope-Anpassung), die zeitliche Punktzahl aus Exploit-Code-Reife, Behebungsstand und Vertrauen in die Meldung, und die Umgebungspunktzahl mit den modifizierten Metriken und der Rundungsfunktion von 3.1.

## Anwendungsfälle

- **Advisories einordnen** — den Vektor aus einem CVE-Eintrag oder Herstellerbulletin einfügen und sehen, was die Punktzahl bestimmt.
- **Eigene Befunde bewerten** — für einen Penetrationstest-Bericht oder eine Bug-Bounty-Meldung, mit einem Vektor, den andere prüfen können.
- **An die eigene Umgebung anpassen** — mit Umgebungsmetriken dieselbe Schwachstelle auf internetnahen und internen Systemen unterschiedlich einstufen.
- **3.1 und 4.0 vergleichen** — viele Datenbanken veröffentlichen noch beides; bewerten Sie dasselbe Problem in jedem Tab.
- **Die Metriken lernen** — jeder Wert ist beschriftet, und die Punktzahl aktualisiert sich bei jedem Klick.
