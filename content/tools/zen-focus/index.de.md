---
title: "Fokus-Timer & Rauschgenerator"
description: "Mischen Sie weißes, rosa und braunes Rauschen, Regen, Kamin, Tastatur und Café und starten Sie einen Pomodoro-Timer. Klänge live im Browser erzeugt."
intro: "**ZenFocus** kombiniert einen Fokus-Timer mit einem Achtkanal-Mischpult für Umgebungsgeräusche. Wählen Sie ein Preset oder mischen Sie selbst aus Rauschen, Regen, Kamin, Tastenklicks und Café-Gemurmel, und starten Sie eine 25-Minuten-Sitzung. Jeder Klang wird live im Browser erzeugt – ohne Audiodateien und ohne Konto."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["fokus timer", "pomodoro timer online", "umgebungsgeräusche mixer", "braunes rauschen", "weißes rauschen online", "rosa rauschen", "regengeräusche zum lernen", "hintergrundgeräusche konzentration"]
tags: ["produktivität", "fokus", "audio", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/zen-focus/"
tool_title: "ZenFocus Timer und Rauschmixer"
tool_height: 800
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
tool_allow: "clipboard-write; web-share"
howto:
  - "Wählen Sie ein Preset: **Deep Work** (braunes Rauschen und Regen), **Coffee Break** (Café-Gemurmel und Kamin) oder **Silence**, um alle Kanäle stummzuschalten."
  - "Oder mischen Sie selbst mit dem Regler jeder Karte. Die Taste 🔊 auf einer Karte schaltet den Kanal stumm, ohne seinen Pegel zu verlieren."
  - "Stellen Sie die Gesamtlautstärke mit dem Regler **Master** ein. Fangen Sie leise an: Maskierendes Rauschen wirkt am besten, wenn es Ablenkungen gerade so überdeckt."
  - "Legen Sie die Dauer mit **−5**, **−1**, **+1** und **+5** fest (1 bis 90 Minuten, Standard 25) und drücken Sie **Start**."
  - "Arbeiten Sie bis zum Gong. **Pause** hält die Uhr an, **Reset** stellt die volle Dauer wieder her. Für eine Pause 5 Minuten einstellen und neu starten."
faq:
  - q: "Was unterscheidet weißes, rosa und braunes Rauschen?"
    a: "Die Verteilung der Energie über die Frequenzen. Weißes Rauschen hat auf allen Frequenzen gleiche Leistung und klingt zischend. Rosa Rauschen fällt um etwa 3 dB pro Oktave ab und klingt weicher, wie gleichmäßiger Regen. Braunes (Brownsches) Rauschen fällt um etwa 6 dB pro Oktave ab und klingt wie tiefes Grollen oder ein ferner Wasserfall. Viele empfinden rosa und braunes Rauschen bei langen Sitzungen als weniger ermüdend."
  - q: "Verbessert Hintergrundrauschen wirklich die Konzentration?"
    a: "Die Studienlage ist gemischt. Gleichmäßiges Rauschen überdeckt zuverlässig unvorhersehbare Geräusche wie Gespräche und Benachrichtigungen, die die Konzentration meist unterbrechen. Manche Studien berichten von Vorteilen für die Aufmerksamkeit, besonders bei Menschen mit ADHS; andere finden keinen Effekt oder Nachteile beim anspruchsvollen Lesen. Sehen Sie es als persönliches Experiment: Probieren Sie eine Mischung eine Woche lang und behalten Sie sie, wenn sie hilft."
  - q: "Was ist die Pomodoro-Technik?"
    a: "Eine Zeitmanagement-Methode von Francesco Cirillo: 25 Minuten an einer Aufgabe arbeiten, 5 Minuten Pause, nach vier Runden eine längere Pause von 15–30 Minuten. ZenFocus startet mit 25 Minuten; für Pausen stellen Sie 5 ein. Es wechselt nicht automatisch, damit Sie selbst bestimmen, wann die nächste Runde beginnt."
  - q: "Läuft der Timer in einem Hintergrund-Tab weiter?"
    a: "Ja. Der Countdown wird aus einem festen Endzeitpunkt berechnet, nicht durch Zählen von Ticks, und bleibt daher genau, auch wenn der Browser Timer in versteckten Tabs drosselt. Der Gong ertönt bei Ablauf, solange der Tab geöffnet ist."
  - q: "Warum ist nichts zu hören, bis ich klicke?"
    a: "Browser blockieren Audio, bis Sie mit der Seite interagieren. ZenFocus startet seine Audio-Engine beim ersten Klick auf einen Regler, ein Preset oder Start und blendet die Kanäle dann ein."
  - q: "Sind die Klänge Aufnahmen?"
    a: "Nein. Jeder Kanal wird mit der Web Audio API synthetisiert: Rauschpuffer, die durch Filter geformt werden (Regen ist zum Beispiel hochpassgefiltertes weißes Rauschen, Donner tiefpassgefiltertes braunes Rauschen), und die Tastatur ist eine Folge kurzer, zufälliger Klicks. Nichts wird heruntergeladen oder gestreamt; nach dem Laden funktioniert es auch offline."
  - q: "Ist stundenlanges Hören unbedenklich?"
    a: "Halten Sie die Lautstärke moderat. Eine gängige Faustregel: so leise, dass Sie jemanden neben sich noch sprechen hören, und regelmäßig Pausen machen. Lange Belastung mit lautem Schall über Kopfhörer kann das Gehör schädigen."
---

## So funktioniert es

ZenFocus ist eine einzelne Seite auf Basis der **Web Audio API**. Bei der ersten Interaktion erzeugt sie einen `AudioContext` und berechnet einige Sekunden Rohrauschen im Speicher:

- **Weißes Rauschen**: gleichverteilte Zufallswerte zwischen −1 und 1, also ein flaches Spektrum.
- **Rosa Rauschen**: der bekannte Filter von Paul Kellet, eine Bank von Filtern erster Ordnung, die eine Steigung von −3 dB/Oktave annähert.
- **Braunes Rauschen**: ein „leckender Integrator“, der Zufallsschritte aufsummiert, mit −6 dB/Oktave.
- **Tastaturklicks**: etwa fünf kurze, exponentiell abklingende Impulse pro Sekunde mit zufälliger Lautstärke.

Die rosa und braunen Puffer werden so korrigiert, dass das letzte Sample auf das erste trifft, damit die Schleifenstelle nicht knackt. Jeder der acht Kanäle ist eine Schleifenquelle, optional durch einen Biquad-Filter geführt, dann ein Gain-Knoten (der Regler der Karte) und schließlich der Master-Gain:

| Kanal | Quelle | Filter |
|---|---|---|
| White Noise | weiß | keiner |
| Pink Noise | rosa | keiner |
| Brown Noise | braun | keiner |
| Rain | weiß | Hochpass 1,2 kHz |
| Thunder | braun | Tiefpass 100 Hz |
| Fireplace | weiß | Bandpass 700 Hz |
| Keyboard | Klicks | Bandpass 2,2 kHz |
| Coffee Shop | rosa | breiter Bandpass 1 kHz |

Alle Kanäle laufen von Anfang an; ein Regler ändert nur den Gain, mit einer 50-ms-Rampe, damit nichts knackt. Stummschalten fährt den Gain auf null, merkt sich aber den Reglerwert.

**Der Timer** speichert den Zeitpunkt, an dem die Sitzung enden soll, und berechnet die Restzeit viermal pro Sekunde neu. Browser können `setInterval` in Hintergrund-Tabs verlangsamen, doch weil die Anzeige aus der Uhr und nicht aus gezählten Ticks abgeleitet wird, endet eine 25-Minuten-Sitzung nach 25 Minuten. Bei null erklingen drei Sinustöne (ein A-Dur-Arpeggio: 880, 1109 und 1319 Hz) als sanfter Gong.

Die Share-Taste nutzt das native Teilen-Menü des Geräts, falls vorhanden, und kopiert sonst den Seitenlink. Sonst verlässt nichts die Seite: Einstellungen und Nutzung werden nicht gespeichert.

## Anwendungsfälle

- **Deep-Work-Blöcke.** Deep Work starten, 50 Minuten einstellen, alles andere schließen: Das gleichmäßige Grollen überdeckt Bürogespräche und Straßenlärm.
- **Lernen mit der Pomodoro-Methode.** 25-Minuten-Sitzungen und 5-Minuten-Pausen abwechseln, nach vier Runden länger pausieren.
- **Großraumbüros und WGs.** Rosa oder braunes Rauschen leise über Kopfhörer überdeckt verständliche Sprache, das für die meisten störendste Geräusch.
- **Schreiben und Lesen.** Eine leichte Mischung aus Coffee Shop + Fireplace schafft Café-Atmosphäre, ohne dass Liedtexte um Aufmerksamkeit konkurrieren.
- **Abschalten.** Regen und braunes Rauschen sind ein ruhiger Hintergrund zum Lesen vor dem Schlafen; der Timer hilft, das Scrollen zu beenden.
- **Timeboxing für Aufgaben und Meetings.** 10 oder 15 Minuten für eine Aufgabe einstellen, die Sie ständig aufschieben – der Gong sagt Ihnen, wann Schluss ist.
