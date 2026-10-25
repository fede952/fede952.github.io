---
title: "Passwort-Check: Stärke und Datenlecks"
description: "Prüfen Sie, wie sicher ein Passwort ist (Entropie, Brute-Force-Knackzeit) und ob es in bekannten Datenlecks vorkommt – mit k-Anonymität, im Browser."
intro: "**PassFort** prüft ein Passwort, das Sie bereits verwenden: seine Entropie, wie lange ein Brute-Force-Angriff bräuchte, Muster, die Sie meiden sollten, und – auf Wunsch – ob es in einem bekannten **Datenleck** aufgetaucht ist. Die Stärkeanalyse verlässt diese Seite nie; die optionale Leak-Prüfung sendet nur 5 Zeichen des Passwort-Hashes. Sie brauchen ein neues Passwort? Nutzen Sie den [Zufalls-Passwort-Generator](/de/tools/password-generator/)."
date: 2026-02-03
lastmod: 2026-10-25
reviewed: false
keywords: ["passwort stärke testen", "passwort check", "passwort geleakt prüfen", "wurde mein passwort gehackt", "passwort entropie berechnen", "wie lange dauert es mein passwort zu knacken", "passwort sicherheit prüfen", "have i been pwned passwort"]
tags: ["sicherheit", "passwörter", "datenschutz", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/pass-fort/"
tool_title: "PassFort: Passwort-Stärke- und Datenleck-Prüfung"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-top-navigation-by-user-activation"
tool_allow: "clipboard-write"
howto:
  - "Tippen Sie das zu prüfende Passwort in den Reiter **Auditor**, der sich zuerst öffnet, oder fügen Sie es ein. Das Augen-Symbol blendet es ein oder aus."
  - "Lesen Sie Entropie-Anzeige, geschätzte Knackzeit und Checkliste: Alles Rote sollten Sie beheben, bevor Sie dieses Passwort weiterverwenden."
  - "Optional prüft **Check against known breaches**, ob genau dieses Passwort in einem Datenleck aufgetaucht ist. Bis Sie darauf klicken, wird nichts gesendet."
  - "Um eine Passphrase oder ein neues Passwort zu erzeugen, öffnen Sie den Reiter **Generator**. Wählen Sie die Länge (8–128 Zeichen) und die Zeichengruppen: Großbuchstaben, Kleinbuchstaben, Ziffern, Sonderzeichen."
  - "Für etwas, das Sie tippen und sich merken können, aktivieren Sie **Passphrase Mode** und wählen 3–8 Wörter. Für ein Master-Passwort mindestens 6."
  - "Klicken Sie auf **Generate Password**, bis Ihnen das Ergebnis gefällt; die Zwischenablage-Schaltfläche kopiert es. Fügen Sie es direkt in Ihren Passwortmanager ein."
faq:
  - q: "Ist es sicher, mein echtes Passwort hier einzugeben?"
    a: "Ja. Der Auditor ist JavaScript, das innerhalb dieser Seite läuft: Er sendet Ihre Eingabe nie über das Netzwerk, und der Wert ist weg, sobald Sie das Feld leeren oder den Tab schließen. Das können Sie in den Entwicklerwerkzeugen des Browsers (Reiter „Netzwerk“) beim Tippen überprüfen. Wenn Ihnen das lieber ist, testen Sie ein Passwort, das *demselben Muster* folgt wie Ihr echtes. Einzige Ausnahme ist die optionale Leak-Prüfung, und nur wenn Sie ihre Schaltfläche anklicken: Sie sendet 5 Zeichen des SHA-1-Hashes, nie das Passwort (siehe nächste Frage)."
  - q: "Wie funktioniert die Leak-Prüfung, ohne mein Passwort preiszugeben?"
    a: "Sie nutzt das k-Anonymitätsverfahren des Dienstes Pwned Passwords von Have I Been Pwned. PassFort berechnet im Browser den SHA-1-Hash des Passworts und sendet nur dessen erste 5 Hexadezimalzeichen an `api.pwnedpasswords.com`. Der Dienst antwortet mit den rund 1.000 Hash-Enden, die dieses Präfix teilen, samt Anzahl der Leaks, und PassFort sucht den Treffer lokal. Die Anfrage verlangt außerdem Auffüllung (`Add-Padding: true`), damit jede Antwort unabhängig vom Ergebnis ähnlich groß ist. Der Dienst sieht weder das Passwort noch den vollständigen Hash; er sieht wie bei jeder Webanfrage Ihre IP-Adresse. Die Prüfung läuft nur, wenn Sie die Schaltfläche anklicken."
  - q: "Wie viele Bit Entropie braucht ein sicheres Passwort?"
    a: "Für Konten, die mit einem langsamen, gesalzenen Hash geschützt sind, halten 60–70 Bit *zufälliger* Entropie einem Offline-Brute-Force-Angriff sehr lange stand. Für das Master-Passwort des Passwortmanagers oder die Festplattenverschlüsselung sollten es 80–100 Bit sein. Ein zufälliges 16-Zeichen-Passwort aus allen vier Gruppen bringt etwa 103 Bit, eine PassFort-Passphrase mit 7 Wörtern etwa 72 Bit."
  - q: "Passphrase oder Zufallspasswort – was ist besser?"
    a: "Beides ist stark, wenn eine Maschine die Wörter oder Zeichen zufällig wählt. Zufällige Zeichenpasswörter haben mehr Entropie pro Zeichen und sind ideal, wenn der Passwortmanager sie eintippt. Passphrasen lassen sich leichter tippen und merken – damit sind sie die bessere Wahl für die wenigen Passwörter, die Sie von Hand eingeben, sofern Sie genug Wörter verwenden."
  - q: "Warum zeigt der Test „Jahrhunderte“ für ein Passwort, von dem ich weiß, dass es schwach ist?"
    a: "Die Schätzung geht davon aus, dass jedes Zeichen zufällig gewählt wurde. Echte Angreifer beginnen mit Wörterbüchern, Listen geleakter Passwörter und Regeln wie „Großbuchstabe am Anfang, Jahreszahl am Ende“ – `Sommer2024!` fällt daher in Sekunden, obwohl die reine Entropie ordentlich aussieht. PassFort erkennt nur einige offensichtliche Muster (Beginn mit 123, abc, password, qwerty, 111 oder aaa). Bei selbst ausgedachten Passwörtern ist die Bewertung also eine Obergrenze."
  - q: "Was bedeuten „10 Milliarden Versuche pro Sekunde“?"
    a: "Das ist die angenommene Angriffsgeschwindigkeit: ungefähr eine moderne GPU gegen einen schnellen, ungesalzenen Hash wie MD5 oder NTLM. Gegen bcrypt, scrypt oder Argon2 ist ein Angreifer tausendfach langsamer, die realen Knackzeiten sind also meist länger. Gegen ein Online-Login mit Begrenzung der Versuche noch viel länger."
  - q: "Speichert oder protokolliert PassFort die erzeugten Passwörter?"
    a: "Nein. Erzeugte Passwörter existieren nur im Speicher der Seite, bis Sie sie kopieren. Es gibt kein Konto, keine Speicherung und keinen Server hinter dem Tool. Speichern Sie das Passwort in einem Passwortmanager – nach dem Schließen des Tabs lässt es sich nicht wiederherstellen."
  - q: "Wie lang sollte ein Passwort 2026 sein?"
    a: "Wenn ein Passwortmanager es erzeugt und speichert: mindestens 16 Zufallszeichen, das kostet Sie nichts. Wenn Sie es sich merken müssen: eine Passphrase aus 6 oder mehr zufälligen Wörtern. Länge schlägt Komplexitätsregeln – ein langes Zufallspasswort nur aus Kleinbuchstaben ist stärker als ein kurzes voller Sonderzeichen."
---

## So funktioniert es

### Der Generator

Jedes Zeichen stammt aus `crypto.getRandomValues()`, dem kryptografisch sicheren Zufallszahlengenerator der Web Crypto API, den der Browser aus der Entropiequelle des Betriebssystems speist. `Math.random()` wird nie verwendet.

Um eine zufällige 32-Bit-Zahl in eine Position im Zeichensatz umzuwandeln, nutzt PassFort **Rejection Sampling**: Werte, die in den unvollständigen obersten „Block“ des 32-Bit-Bereichs fallen, werden verworfen und neu gezogen. Das einfachere `zufall % größe` würde die ersten Zeichen des Satzes minimal bevorzugen. Die Verzerrung ist winzig, aber es gibt keinen Grund, sie hinzunehmen.

Die vier Gruppen sind 26 Großbuchstaben, 26 Kleinbuchstaben, 10 Ziffern und 26 Sonderzeichen (`!@#$%^&*()_+-=[]{}|;:,.<>?`), insgesamt 88 Zeichen. Jedes Zeichen fügt daher log₂(88) ≈ **6,46 Bit** Entropie hinzu:

| Länge | Alle vier Gruppen | Nur Kleinbuchstaben |
|---|---|---|
| 12 | ≈ 77 Bit | ≈ 56 Bit |
| 16 | ≈ 103 Bit | ≈ 75 Bit |
| 20 (Standard) | ≈ 129 Bit | ≈ 94 Bit |

Die Zeichen werden unabhängig voneinander gezogen; ein kurzes Passwort enthält also nicht *garantiert* jede gewählte Gruppe. Erzeugen Sie ein neues, wenn eine Website zum Beispiel eine Ziffer verlangt.

### Der Passphrase-Modus

Der Passphrase-Modus wählt Wörter aus einer eingebauten Liste von **1.207 englischen Wörtern** mit demselben unverzerrten Zufallsindex, schreibt jedes groß und verbindet sie mit Bindestrichen (zum Beispiel `Harbor-Canyon-Crisp-Velvet`). Jedes Wort bringt log₂(1207) ≈ **10,24 Bit**: 4 Wörter ergeben etwa 41 Bit, 6 Wörter etwa 61 Bit und das Maximum von 8 Wörtern etwa 82 Bit.

Das ist weniger pro Wort als bei einer vollständigen Diceware-Liste mit 7.776 Wörtern (12,9 Bit). Deshalb empfiehlt diese Seite mindestens 6 Wörter für alles Wichtige. Großschreibung und Bindestriche sind fest vorgegeben und fügen keine Entropie hinzu.

### Der Auditor

Der Auditor schätzt die Größe des „Alphabets“, aus dem Ihr Passwort stammt: 26, wenn ein Kleinbuchstabe vorkommt, +26 für Großbuchstaben, +10 für Ziffern und +33 für alle anderen Zeichen. Die Entropie ist dann `Länge × log₂(Alphabet)`.

Die Knackzeit ist die Zeit, um alle 2^Entropie Kombinationen bei **10¹⁰ Versuchen pro Sekunde** durchzuprobieren, angezeigt in verständlichen Einheiten bis „Jahrhunderte“. Die Anzeige ist bei 100 Bit voll und wechselt bei 25, 50 und 75 Bit von Rot zu Orange, Gelb und Grün. Darunter stehen acht Prüfungen: mindestens 8 und 12 Zeichen, jede Zeichenklasse, kein gängiges Anfangsmuster und mindestens 60 Bit.

Das ist das klassische Brute-Force-Modell. Es ist genau für Zufallspasswörter wie die des Generators und **zu optimistisch für Passwörter, die Menschen sich ausdenken**, weil es Wörterbuchwörter, Namen oder Daten nicht erkennt.

### Die optionale Leak-Prüfung

Ein Passwort kann hohe Entropie haben und trotzdem wertlos sein, weil es geleakt wurde: Angreifer probieren geleakte Passwörter zuerst. **Check against known breaches** fragt bei Have I Been Pwned an, ob genau dieses Passwort in dessen Liste von Passwörtern aus echten Datenlecks steht – per k-Anonymität: Nur die ersten 5 der 40 Hexadezimalzeichen des SHA-1-Hashes verlassen die Seite (`5BAA6` für `password`), der Abgleich mit den zurückgegebenen Suffixen geschieht im Browser, und die Antworten sind aufgefüllt, damit ihre Größe nichts verrät. Die Prüfung ist aus, bis Sie die Schaltfläche anklicken, und ein neu eingegebenes Passwort löscht das vorige Ergebnis.

## Anwendungsfälle

- **Neue Konten.** Erzeugen Sie ein Passwort mit 16–20 Zeichen und speichern Sie es im Passwortmanager. Sie müssen es nie wieder sehen.
- **Passwörter, die Sie sich merken müssen.** Master-Passwort des Passwortmanagers, Computer-Login, Festplattenverschlüsselung: Nehmen Sie eine Passphrase aus 6–8 Wörtern, die Sie zuverlässig tippen können.
- **Alte Gewohnheiten prüfen.** Fügen Sie ein Passwort ein, das Sie seit Jahren nutzen, sehen Sie sich die Bewertung an und ersetzen Sie schwache Passwörter – zuerst bei E-Mail und Bank.
- **WLAN-Schlüssel und geteilte Geheimnisse.** WPA2/WPA3-Passphrasen dürfen bis zu 63 Zeichen lang sein; eine lange, zufällige kostet nichts und verhindert das Offline-Knacken eines mitgeschnittenen Handshakes.
- **Schulungen und Richtlinien.** Die Tabelle oben und die Live-Anzeige machen Entropie greifbar, wenn Sie Kollegen erklären, warum „8 Zeichen mit Sonderzeichen“ keine gute Richtlinie mehr ist.
