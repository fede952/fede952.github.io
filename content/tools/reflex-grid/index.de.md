---
title: "Aim Trainer & Reaktionstest online"
description: "Trainieren Sie Ihr Zielen mit der Maus in 60-Sekunden-Runden: leuchtende Ziele anklicken, dann Treffer, Genauigkeit, Reaktionszeit und Rang sehen."
intro: "**ReflexGrid** ist ein 60-Sekunden-Aim-Trainer: Ziele tauchen irgendwo auf dem Raster auf, Sie klicken oder tippen sie so schnell wie möglich an und erhalten am Ende Treffer, Genauigkeit, durchschnittliche Zeit bis zum Ziel und einen Rang von *Potato* bis *Pro*."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["aim trainer", "reaktionstest", "reaktionszeit testen", "zielen trainieren", "maus genauigkeit test", "aim trainer online", "fps training", "klick geschwindigkeit test"]
tags: ["spiele", "gaming", "reflexe", "tool"]
app_category: "GameApplication"
tool_file: "/tools/reflex-grid/"
tool_title: "ReflexGrid Aim-Trainer"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Klicken Sie auf **Start Training**. Der 60-Sekunden-Timer startet, und das erste Ziel erscheint."
  - "Klicken (oder tippen Sie auf Touchscreens) jeden leuchtenden Kreis so schnell und genau wie möglich an. Sobald Sie treffen, erscheint der nächste."
  - "Behalten Sie die obere Leiste im Blick: Restzeit, Treffer und Live-Genauigkeit. Fehlklicks senken die Genauigkeit."
  - "Wenn die Zeit abgelaufen ist, lesen Sie die Ergebnisse: **Targets Hit**, **Accuracy**, **Avg Reaction** und **Total Clicks**, dazu Ihren Rang."
  - "Mit **Play Again** versuchen Sie, Ihren Wert zu schlagen. Wärmen Sie sich mit ein paar Runden auf, bevor Sie Ergebnisse vergleichen."
faq:
  - q: "Was ist eine gute Reaktionszeit in diesem Test?"
    a: "Der Durchschnitt hier ist die Zeit vom Erscheinen eines Ziels bis zum Treffer – also inklusive Mausbewegung, nicht nur Reaktion. Unter 300 ms (Rang *Gamer*) ist gut, unter 200 ms (*Pro*) hervorragend. Die einfache visuelle Reaktionszeit Erwachsener liegt meist bei etwa 200–250 ms, die Werte von ReflexGrid sind daher naturgemäß etwas höher."
  - q: "Wie werden die Ränge berechnet?"
    a: "Aus der durchschnittlichen Zeit bis zum Ziel: unter 200 ms *Pro*, unter 300 ms *Gamer*, unter 400 ms *Casual*, unter 500 ms *Novice*, alles darüber *Potato*. Die Genauigkeit wird separat angezeigt; für echten Fortschritt sollte sie über etwa 80 % bleiben, während die Zeit sinkt."
  - q: "Spielen Mausempfindlichkeit oder DPI eine Rolle?"
    a: "Ja, eine große. Aim-Training bringt nur etwas mit derselben Empfindlichkeit, mit der Sie spielen, also behalten Sie DPI und Zeigereinstellungen bei. Das Deaktivieren von „Zeigerbeschleunigung verbessern“ unter Windows macht Bewegungen gleichmäßiger und besser trainierbar."
  - q: "Warum sind manche Ziele rot?"
    a: "Etwa 40 % der Ziele sind rot statt cyan – nur als visuelle Abwechslung, damit Sie nicht vorausahnen. Beide zählen gleich."
  - q: "Kann ich auf dem Handy spielen?"
    a: "Ja. Das Canvas reagiert auf Touch- wie auf Mausereignisse, Antippen zählt also als Klick. Touch-Zeiten sind nicht mit Mauszeiten vergleichbar – vergleichen Sie sich mit sich selbst auf demselben Gerät."
  - q: "Werden meine Ergebnisse gespeichert oder hochgeladen?"
    a: "Nein. Jede Runde existiert nur in der Seite; es wird nichts gespeichert oder gesendet. Notieren Sie sich Ihren Bestwert, wenn Sie Fortschritte verfolgen möchten."
---

## So funktioniert es

Das Spiel wird auf ein HTML-`<canvas>` gezeichnet, das an die Pixeldichte Ihres Bildschirms angepasst ist, mit animiertem Hintergrundraster und einer HUD-Leiste oben.

**Ziele.** Jedes Ziel erhält einen zufälligen Radius zwischen 20 und 35 Pixeln und eine zufällige Position mit Abstand zu Rändern und HUD. Es pulsiert um ±12 % und steht so nie ganz still. Der Zeitpunkt seines Erscheinens wird mit `performance.now()`, der hochauflösenden Uhr des Browsers, gespeichert.

**Treffer und Fehlklicks.** Bei jedem `mousedown` oder `touchstart` wird per Pythagoras der Abstand vom Zeiger zur Zielmitte berechnet. Alles innerhalb des 1,3-fachen Radius gilt als Treffer – ein kleiner Spielraum für Leuchten und Pulsieren. Ein Treffer speichert die Reaktionszeit (jetzt − Erscheinungszeitpunkt), spielt einen kurzen ansteigenden Rechteckton aus der Web Audio API, lässt Partikel sprühen und erzeugt sofort das nächste Ziel. Ein Fehlklick spielt einen fallenden Sägezahnton und erhöht nur die Klickzahl.

**Wertung.** Nach den 60 Sekunden gilt:

- **Targets Hit** ist die Zahl erfolgreicher Klicks;
- **Accuracy** ist Treffer ÷ Klicks insgesamt;
- **Avg Reaction** ist der Mittelwert aller erfassten Reaktionszeiten in Millisekunden;
- der **Rang** hängt von diesem Mittelwert ab.

| Mittlere Zeit bis zum Ziel | Rang |
|---|---|
| unter 200 ms | Pro |
| 200–299 ms | Gamer |
| 300–399 ms | Casual |
| 400–499 ms | Novice |
| ab 500 ms | Potato |

Da jedes Ziel genau in dem Moment erscheint, in dem das vorige getroffen wird, misst der Test die *Flick*-Geschwindigkeit: neues Ziel sehen, hinbewegen, klicken. Das entspricht den Anforderungen von Shootern besser als ein „Warte, bis der Bildschirm grün wird“-Reaktionstest.

## Anwendungsfälle

- **Aufwärmen vor Shootern** wie Valorant, CS2, Apex Legends oder Overwatch: zwei, drei Runden bringen Hand und Auge in Einklang.
- **Neue Maus oder Empfindlichkeit testen.** Spielen Sie mit jeder Einstellung ein paar Runden und vergleichen Sie Genauigkeit und Zeit bis zum Ziel.
- **Fortschritte verfolgen.** Notieren Sie täglich Durchschnitt und Genauigkeit; regelmäßiges Üben zeigt sich in kürzeren Zeiten bei gleicher Genauigkeit.
- **Eine kurze Pause.** Eine Minute konzentriertes Klicken ist ein guter Reset zwischen langen Arbeitsphasen.
- **Ergonomie im Blick.** Ein plötzlicher Einbruch der Genauigkeit kann ein Zeichen von Ermüdung sein – Pause machen.
