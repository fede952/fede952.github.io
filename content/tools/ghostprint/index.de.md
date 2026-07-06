---
title: "GhostPrint: Browser-Fingerprint-Test — Wie verfolgbar bist du?"
description: "Sieh den unsichtbaren Fingerabdruck, den dein Browser jeder Website übergibt — GPU, Canvas, Schriften, Audio und mehr — mit einem Einzigartigkeits-Score. 100% im Browser: nichts wird hochgeladen."
date: 2026-07-06
tags: ["privacy", "security", "developer-tools", "fingerprinting"]
keywords: ["browser fingerprint test", "bin ich einzigartig", "geräte-fingerabdruck", "canvas fingerprint", "wie verfolgbar bin ich", "browser fingerprinting", "webgl fingerabdruck", "audio fingerabdruck", "online privatsphäre test", "anti-tracking test"]
layout: "tool"
draft: false
tool_file: "/tools/ghostprint/"
tool_height: "2200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "GhostPrint — Browser-Fingerprint-Test", "description": "Kostenloser clientseitiger Browser-Fingerprinting-Test, der bewertet, wie einzigartig und verfolgbar dein Browser über GPU, Canvas, Audio, Schriften und mehr ist.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Warum ein Fingerabdruck einen Cookie schlägt

Cookies lassen sich leicht blockieren. Dein **Browser-Fingerabdruck** nicht. Die genaue Art, wie Gerät, GPU, Schriften, Bildschirm und Einstellungen zusammenwirken, bildet eine Kennung, die dir über Websites hinweg folgt — und sie **übersteht den Inkognito-Modus, gelöschte Cookies und die meisten "privaten" Sitzungen.** GhostPrint zeigt dir deinen in Sekunden, mit einem Einzigartigkeits-Score und einer vollständigen Aufschlüsselung jedes Signals, das durchsickert.

Der Haken, der den Punkt macht: jedes Signal unten wird **in deinem Browser** gelesen und **nirgendwohin** gesendet — kein Upload, kein Logging, kein Server. Aber jede Website, die du besuchst, kann diese Werte still auslesen, ohne Erlaubnisdialog, und Werbe- und Betrugsnetzwerke tun genau das. Lade die Seite neu und deine Daten sind weg; die Tracker bieten diesen Knopf nicht.

## Was GhostPrint ausliest

- **Hardware & GPU** — deine Grafikkarte (über WebGL), CPU-Kerne, Speicher und Bildschirmwerte
- **Rendering-Fingerabdrücke** — Canvas- und Audio-Hashes: Eigenheiten auf Pixel- und Sample-Ebene, einzigartig für dein System
- **Umgebung** — installierte Schriften, Zeitzone, Sprachen, Plattform und Anzeigeeinstellungen
- **Datenschutz-Signale** — Status von Cookies, Do-Not-Track und Global Privacy Control

## So verblasst der Geist

- **Tor Browser** ist der Goldstandard — jeder Nutzer wird bewusst identisch gemacht.
- **Firefox** bietet `privacy.resistFingerprinting`; **Brave** randomisiert Canvas und Audio standardmäßig.
- Anti-Fingerprint-Erweiterungen und das Deaktivieren von WebGL helfen — und paradoxerweise machen dich exotische Hardware und seltene Schriften *identifizierbarer*, nicht weniger.

Starte oben den Scan für deinen Einzigartigkeits-Score, lade dann eine teilbare Karte herunter und vergleiche deine anderen Browser.
