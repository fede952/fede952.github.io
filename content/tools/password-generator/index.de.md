---
title: "Passwort-Generator für sichere Passwörter"
description: "Erzeugen Sie starke Zufallspasswörter bis 64 Zeichen mit dem Krypto-Zufallsgenerator Ihres Browsers. Live-Entropie, Kopieren per Klick, kein Server."
intro: "Ein **Passwort-Generator** mit einem Klick: Länge und Zeichengruppen wählen und ein Zufallspasswort aus dem kryptografischen Zufallsgenerator Ihres Browsers erhalten – mit der Stärke in Bit."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["passwort generator", "sicheres passwort generieren", "zufallspasswort generator", "starkes passwort erstellen", "passwort erstellen online", "16 stelliges passwort", "passwort generieren"]
tags: ["sicherheit", "passwörter", "tool"]
app_category: "SecurityApplication"
tool_partial: "password-generator"
howto:
  - "Ziehen Sie den Regler **Länge** (8 bis 64 Zeichen). Bei jeder Bewegung wird sofort ein neues Passwort erzeugt."
  - "Entfernen Sie Häkchen bei Zeichengruppen, die die Zielseite nicht akzeptiert: Großbuchstaben **A–Z**, Kleinbuchstaben **a–z**, Ziffern **0–9** oder Sonderzeichen **!@#**."
  - "Prüfen Sie die Zeile unter dem Passwort: Sie zeigt die Entropie in Bit und eine Einstufung (Schwach, Gut, Stark)."
  - "Klicken Sie auf **Passwort generieren** für ein neues; die Kopier-Schaltfläche neben dem Feld legt es in die Zwischenablage."
  - "Fügen Sie es in Ihren Passwortmanager ein, *bevor* Sie die Seite schließen. Der Generator speichert keinen Verlauf."
faq:
  - q: "Ist dieser Passwort-Generator wirklich zufällig?"
    a: "Ja. Jedes Zeichen wird mit `crypto.getRandomValues()` gewählt, dem kryptografisch sicheren Zufallszahlengenerator des Browsers, und zwar mit Rejection Sampling, sodass jedes Zeichen der Menge exakt gleich wahrscheinlich ist. `Math.random()` wird nicht verwendet; es ist vorhersagbar und nicht für Geheimnisse gedacht."
  - q: "Kann die Website die erzeugten Passwörter sehen?"
    a: "Nein. Der Generator besteht aus wenigen Zeilen JavaScript, die in Ihrem Browser laufen: keine Anfrage an einen Server, keine Protokolle, keine Speicherung. Trennen Sie nach dem Laden der Seite die Internetverbindung – er funktioniert weiter. Das ist der einfachste Beweis."
  - q: "Welche Länge sollte ich wählen?"
    a: "Mit allen vier Zeichengruppen ergeben 16 Zeichen etwa 104 Bit Entropie – weit jenseits dessen, was ein Brute-Force-Angriff erreichen kann. Nehmen Sie für sehr sensible Konten 20 oder mehr, wenn die Seite es erlaubt. Unter 12 nur, wenn ein Altsystem Sie dazu zwingt."
  - q: "Warum enthält mein Passwort kein Sonderzeichen, obwohl sie aktiviert sind?"
    a: "Jedes Zeichen wird unabhängig aus der gesamten Menge gezogen; das Passwort muss also nicht von jeder Art ein Zeichen enthalten. Bei 16 Zeichen ist das fast immer der Fall. Lehnt eine Seite das Passwort wegen eines fehlenden Sonderzeichens oder einer Ziffer ab, generieren Sie einfach neu."
  - q: "Was bedeuten Schwach, Gut und Stark?"
    a: "Es sind Entropie-Stufen: unter 60 Bit Schwach, 60 bis 90 Bit Gut, ab 90 Bit Stark. Da das Passwort zufällig erzeugt wird, ist dieser Wert exakt – anders als bei Stärke-Anzeigen, die die Entropie eines selbst ausgedachten Passworts schätzen müssen."
  - q: "Muss ich mir diese Passwörter merken?"
    a: "Nein. Speichern Sie sie in einem Passwortmanager und lassen Sie ihn ausfüllen. Für die ein, zwei Passwörter, die Sie wirklich auswendig wissen müssen, etwa das Master-Passwort, ist eine lange zufällige Passphrase angenehmer – die erzeugt PassFort auf dieser Website."
---

## So funktioniert es

Der Generator bildet eine Zeichenmenge aus den gewählten Gruppen: 26 Großbuchstaben, 26 Kleinbuchstaben, 10 Ziffern und 29 Sonderzeichen (`` !@#$%^&*()_+~`|}{[]:;?><,./-= ``), bis zu **91 Zeichen**. Für jede Stelle fordert er über `crypto.getRandomValues()` eine zufällige 32-Bit-Zahl von der Web Crypto API an und ordnet sie einem Zeichen zu.

Diese Zuordnung nutzt **Rejection Sampling**. 2³² ist kein Vielfaches von 91, daher würde das einfache `zufall % 91` einige wenige Zeichen minimal bevorzugen. Stattdessen wird jeder Wert im unvollständigen obersten Abschnitt des 32-Bit-Bereichs verworfen und neu gezogen – jedes Zeichen hat danach exakt dieselbe Wahrscheinlichkeit.

Die Stärke-Zeile ist keine Schätzung. Da jedes Zeichen gleichverteilt zufällig ist, beträgt die Entropie genau **Länge × log₂(Größe der Zeichenmenge)**:

| Einstellungen | Bit pro Zeichen | 12 Z. | 16 Z. | 24 Z. |
|---|---|---|---|---|
| Alle vier Gruppen (91) | 6,51 | 78 | 104 | 156 |
| Buchstaben + Ziffern (62) | 5,95 | 71 | 95 | 143 |
| Kleinbuchstaben + Ziffern (36) | 5,17 | 62 | 83 | 124 |
| Nur Ziffern (10) | 3,32 | 40 | 53 | 80 |

Die Einstufung lautet **Schwach** unter 60 Bit, **Gut** von 60 bis 90 Bit und **Stark** ab 90 Bit; der Balken ist bei 128 Bit voll. Jede Änderung der Länge oder eines Kästchens erzeugt sofort ein neues Passwort, sodass das Angezeigte immer zu den Einstellungen passt.

Kopiert wird über die asynchrone Clipboard API, wenn die Seite per HTTPS ausgeliefert wird, mit einem Fallback für ältere Browser. Das Passwort existiert nur im Eingabefeld: Seite neu laden, und es ist weg.

### Warum Entropie das richtige Maß ist

Ein Angreifer, der diesen Generator samt Zeichenmenge und Länge genau kennt, muss trotzdem im Schnitt die Hälfte aller 2^Bit Kombinationen durchprobieren. Bei 104 Bit sind das rund 10³¹ Versuche: Selbst mit 10 Milliarden pro Sekunde bräuchte er weit länger als das Alter des Universums. Deshalb ist ein Passwort aus einem guten Generator *konstruktionsbedingt* stark, während ein ausgedachtes nur so stark ist, wie das Wörterbuch des Angreifers klein ist.

## Anwendungsfälle

- **Anmeldung bei einem neuen Dienst.** 16+ Zeichen erzeugen, im Passwortmanager speichern, fertig.
- **Passwortwechsel nach einem Datenleck.** Ersetzen Sie ein mehrfach genutztes oder geleaktes Passwort durch ein einzigartiges Zufallspasswort – zuerst beim E-Mail-Konto, denn darüber lassen sich alle anderen zurücksetzen.
- **API-Schlüssel, Datenbankbenutzer und Dienstkonten.** Deaktivieren Sie Sonderzeichen, wenn ein Connection-String oder ein Shell-Skript damit Probleme hat, und erhöhen Sie die Länge, damit die Entropie über 100 Bit bleibt.
- **WLAN.** Erzeugen Sie einen Schlüssel mit 20–30 Zeichen für den Router; Sie tippen ihn nur einmal pro Gerät.
- **Temporäre Zugangsdaten.** Legen Sie ein Einmalpasswort für ein Gastkonto oder ein geteiltes Dokument an und löschen Sie das Konto danach.

Für Passphrasen und zum Prüfen eines bereits genutzten Passworts gibt es [PassFort](/de/tools/pass-fort/).
