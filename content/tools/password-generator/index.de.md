---
title: "Passwort- und Passphrase-Generator"
description: "Erzeugen Sie starke Zufallspasswörter bis 64 Zeichen oder Diceware-Passphrasen aus Wortlisten in 6 Sprachen. Exakte Entropie, nichts wird gesendet."
intro: "Ein **Passwort-Generator** mit einem Klick: Länge und Zeichengruppen für ein Zufallspasswort wählen, oder auf **Passphrase** umschalten für eine Folge zufälliger Wörter (auf Deutsch, Englisch, Italienisch, Spanisch, Französisch oder Portugiesisch). Alles stammt aus dem kryptografischen Zufallsgenerator Ihres Browsers, die genaue Stärke wird in Bit angezeigt."
date: 2026-02-03
lastmod: 2026-10-26
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
  - "Für etwas, das Sie tippen oder sich merken müssen, wählen Sie **Passphrase**: Anzahl der Wörter, Wortliste (folgt der Sprache der Seite) und Trennzeichen einstellen. Sechs Wörter aus der deutschen Liste ergeben etwa 77 Bit."
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
    a: "Nein, speichern Sie sie in einem Passwortmanager und lassen Sie sie automatisch ausfüllen. Für die ein, zwei Geheimnisse, die Sie sich merken müssen, etwa das Master-Passwort des Managers, nutzen Sie den Modus **Passphrase**: Sechs oder sieben zufällige Wörter sind viel leichter zu tippen und zu merken als 16 zufällige Zeichen, bei ähnlicher Stärke."
  - q: "Welche Wortlisten nutzt der Passphrase-Modus?"
    a: "Deutsch nutzt die Liste de-7776 von dys2p (7.776 Wörter, etwa 12,9 Bit pro Wort, unter CC0 und gleichwertigen Gemeinfreiheits-Lizenzen veröffentlicht). Englisch nutzt die EFF Large Wordlist (7.776 Wörter, CC BY 4.0). Italienisch, Spanisch, Französisch und Portugiesisch nutzen die BIP-39-Listen (2.048 Wörter, 11 Bit pro Wort), wie sie in Trezors Bibliothek python-mnemonic unter MIT-Lizenz veröffentlicht sind. Alle werden von dieser Website ausgeliefert; Akzente entfernen senkt die Entropie nie, weil die BIP-39-Wörter auch ohne Akzente verschieden bleiben."
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

## Passphrasen: zufällige Wörter statt zufälliger Zeichen

Eine Passphrase besteht aus einigen Wörtern, die **zufällig** aus einer festen Liste gezogen werden — das sogenannte *Diceware*-Verfahren. Die Stärke hängt nur von der Größe der Liste und der Zahl der Wörter ab, nie davon, wie originell die Wörter wirken: Jedes Wort aus einer Liste mit 7.776 Wörtern bringt log₂(7776) ≈ **12,9 Bit**, jedes Wort aus einer Liste mit 2.048 Wörtern genau **11 Bit**.

| Wörter | EFF- / deutsche Liste (7.776) | BIP-39-Listen (2.048) |
|---|---|---|
| 4 | 51,7 Bit | 44 Bit |
| 5 | 64,6 Bit | 55 Bit |
| 6 | 77,5 Bit | 66 Bit |
| 7 | 90,5 Bit | 77 Bit |
| 8 | 103,4 Bit | 88 Bit |

Die Wörter werden mit derselben verzerrungsfreien Auswahl über `crypto.getRandomValues()` gezogen wie die Passwörter. **Großer Anfangsbuchstabe** ist deterministisch und bringt keine Entropie; **Eine Ziffer anhängen** setzt eine zufällige Ziffer hinter ein zufälliges Wort und bringt log₂(10 × Wörter) Bit. Die Standardliste folgt der Sprache der Seite, jede Liste lässt sich aber auf jeder Seite wählen.

## Anwendungsfälle

- **Anmeldung bei einem neuen Dienst.** 16+ Zeichen erzeugen, im Passwortmanager speichern, fertig.
- **Passwortwechsel nach einem Datenleck.** Ersetzen Sie ein mehrfach genutztes oder geleaktes Passwort durch ein einzigartiges Zufallspasswort – zuerst beim E-Mail-Konto, denn darüber lassen sich alle anderen zurücksetzen.
- **API-Schlüssel, Datenbankbenutzer und Dienstkonten.** Deaktivieren Sie Sonderzeichen, wenn ein Connection-String oder ein Shell-Skript damit Probleme hat, und erhöhen Sie die Länge, damit die Entropie über 100 Bit bleibt.
- **WLAN.** Erzeugen Sie einen Schlüssel mit 20–30 Zeichen für den Router; Sie tippen ihn nur einmal pro Gerät.
- **Temporäre Zugangsdaten.** Legen Sie ein Einmalpasswort für ein Gastkonto oder ein geteiltes Dokument an und löschen Sie das Konto danach.

Um ein bereits genutztes Passwort auf Stärke und bekannte Datenlecks zu prüfen, gibt es [PassFort](/de/tools/pass-fort/).
