---
title: "Caesar-Verschlüsselung online (ROT13)"
description: "Text mit der Caesar-Verschiebung ver- und entschlüsseln, jede Verschiebung von 1 bis 25 inklusive ROT13. So funktioniert sie, und so wird sie geknackt."
intro: "Verschieben Sie jeden Buchstaben Ihres Textes um eine feste Anzahl von Stellen im Alphabet – die Verschlüsselung, die Julius Caesar nutzte. Wählen Sie eine Verschiebung von 1 bis 25 (13 ergibt **ROT13**) und ver- oder entschlüsseln Sie. Ein Klassiker für Rätsel, CTFs und um zu verstehen, warum einfache Chiffren scheitern."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["caesar verschlüsselung", "caesar chiffre entschlüsseln", "caesar code", "rot13", "verschiebechiffre", "text verschlüsseln", "klassische kryptografie", "caesar verschlüsselung online"]
tags: ["kryptografie", "chiffre", "ctf", "tool"]
app_category: "EducationalApplication"
tool_partial: "caesar-cipher"
howto:
  - "Geben Sie Ihre Nachricht in **Eingabetext** ein oder fügen Sie sie ein."
  - "Stellen Sie die **Verschiebung** mit dem Regler ein (1–25). Caesar nahm 3; 13 ist ROT13."
  - "Klicken Sie auf **Verschlüsseln**, um die Buchstaben vorwärts zu verschieben, oder auf **Entschlüsseln**, um sie um denselben Wert zurückzuschieben."
  - "Lesen Sie das Ergebnis unter **Ergebnis** ab und legen Sie es mit **Kopieren** in die Zwischenablage."
  - "Um eine unbekannte Nachricht zu knacken, entschlüsseln Sie mit jeder Verschiebung, bis lesbare Wörter erscheinen – es gibt nur 25 Möglichkeiten."
faq:
  - q: "Wie funktioniert die Caesar-Verschlüsselung?"
    a: "Jeder Buchstabe wird durch den Buchstaben ersetzt, der eine feste Anzahl von Stellen weiter im Alphabet steht; nach Z geht es mit A weiter. Bei Verschiebung 3 wird A zu D, B zu E und Z zu C. Zum Entschlüsseln wird um denselben Wert zurückverschoben."
  - q: "Was ist ROT13?"
    a: "ROT13 ist die Caesar-Verschlüsselung mit Verschiebung 13. Da das Alphabet 26 Buchstaben hat, ergibt zweimaliges Anwenden wieder den Originaltext – dieselbe Operation ver- und entschlüsselt. In Foren diente sie zum Verstecken von Spoilern und Pointen, nie zur Sicherheit."
  - q: "Ist die Caesar-Verschlüsselung sicher?"
    a: "Nein. Es gibt nur 25 sinnvolle Schlüssel, die jeder in Sekunden von Hand durchprobieren kann. Häufigkeitsanalyse knackt sie noch schneller: Im Deutschen ist E der häufigste Buchstabe und taucht im Geheimtext um den Schlüssel verschoben auf. Nutzen Sie sie nur für Rätsel und Unterricht."
  - q: "Was passiert mit Zahlen, Leerzeichen und Umlauten?"
    a: "Sie bleiben unverändert. Das Tool verschiebt nur die 26 lateinischen Grundbuchstaben A–Z und a–z und erhält Groß- und Kleinschreibung. Ziffern, Satzzeichen, Leerzeichen und Buchstaben wie ä, ö, ü oder ß bleiben, wie sie sind."
  - q: "Wie entschlüsselt man eine Caesar-Chiffre ohne Schlüssel?"
    a: "Per Brute Force: Mit den Verschiebungen 1 bis 25 entschlüsseln und die suchen, die lesbaren Text ergibt. Bei längeren Nachrichten Buchstaben zählen: Der häufigste steht im Deutschen meist für E, und der Abstand zwischen beiden ist die Verschiebung."
  - q: "Wird mein Text irgendwohin gesendet?"
    a: "Nein. Die Verschiebung berechnen ein paar Zeilen JavaScript in dieser Seite; es wird nichts hochgeladen."
---

## So funktioniert es

Das Tool geht Ihren Text Zeichen für Zeichen durch und prüft den Zeichencode:

- Großbuchstaben `A–Z` (Codes 65–90) werden innerhalb des Großbuchstaben-Alphabets verschoben;
- Kleinbuchstaben `a–z` (Codes 97–122) innerhalb des Kleinbuchstaben-Alphabets;
- alles andere (Ziffern, Leerzeichen, Satzzeichen, Umlaute und nichtlateinische Buchstaben) wird unverändert übernommen.

Die Verschiebung ist modulare Arithmetik auf der Position *p* des Buchstabens (0 für A, 25 für Z) und dem Schlüssel *k*:

**verschlüsselt = (p + k) mod 26**, beim Entschlüsseln mit −k.

Da `%` in JavaScript negative Zahlen liefern kann, rechnet der Code `((p + k) % 26 + 26) % 26`; so bleibt das Ergebnis in beide Richtungen zwischen 0 und 25. Anschließend wird die Position mit der ursprünglichen Groß- oder Kleinschreibung zurück in ein Zeichen umgewandelt.

| Klartext | Verschiebung 3 | Verschiebung 13 (ROT13) |
|---|---|---|
| `HELLO` | `KHOOR` | `URYYB` |
| `Attack at dawn` | `Dwwdfn dw gdzq` | `Nggnpx ng qnja` |
| `Zebra` | `Cheud` | `Mroen` |

### Warum sie so leicht zu knacken ist

Die Caesar-Verschlüsselung hat einen Schlüsselraum von 25. Ein Computer – oder ein geduldiger Mensch – probiert jeden Schlüssel in kürzester Zeit. Und weil jeder Buchstabe immer auf denselben Buchstaben abgebildet wird, behält der Geheimtext den statistischen Fingerabdruck der Sprache: Das häufigste Zeichen eines deutschen Geheimtexts ist fast immer ein verschobenes E. Genau diese beiden Schwächen – winziger Schlüsselraum und erhaltene Häufigkeiten – sollen moderne Verfahren wie AES vermeiden.

## Anwendungsfälle

- **CTF-Aufgaben und Rätsel.** Caesar und ROT13 tauchen ständig in Einsteiger-CTFs, Escape Rooms und beim Geocaching auf.
- **Kryptografie lehren.** Zeigen Sie Verschlüsselung, Schlüssel und Brute Force mit etwas, das auch auf Papier funktioniert, und erklären Sie dann, warum es scheitert.
- **Spoiler verstecken.** ROT13 verbirgt noch immer eine Pointe oder Lösung vor versehentlichem Lesen.
- **Programmierübungen.** Vergleichen Sie Ihre eigene Implementierung mit dieser – modulare Arithmetik und Groß-/Kleinschreibung sind die typischen Stolpersteine.
- **Historische Neugier.** Verschlüsseln Sie eine Nachricht wie die römischen Feldherren, mit Verschiebung 3 – Sueton berichtet, dass Caesar genau diese Verschiebung für seine Briefe verwendete.
