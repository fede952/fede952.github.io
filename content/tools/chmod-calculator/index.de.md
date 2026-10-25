---
title: "Chmod-Rechner: Linux-Dateirechte"
description: "Lesen, Schreiben und Ausführen für Besitzer, Gruppe und andere setzen und die chmod-Zahl (755, 644…), den rwx-String und den fertigen Befehl erhalten."
intro: "Klicken Sie die Rechte-Schalter an und erhalten Sie die **chmod**-Zahl, den String `rwxr-xr-x`, den Sie aus `ls -l` kennen, und einen ausführbereiten Befehl. Die Schnellauswahl deckt die üblichen Fälle ab: 755, 644, 600, 444 und den zu vermeidenden, 777."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["chmod rechner", "chmod 755", "linux dateirechte", "chmod 644", "oktale rechte", "rwx rechte", "unix berechtigungen", "chmod befehl generator"]
tags: ["linux", "sysadmin", "berechtigungen", "tool"]
app_category: "DeveloperApplication"
tool_partial: "chmod-calculator"
howto:
  - "Schalten Sie für jede Klasse (**Besitzer**, **Gruppe**, **Andere**) **Lesen**, **Schreiben** und **Ausführen** ein oder aus. Voreingestellt ist 755."
  - "Lesen Sie die Oktalzahl hinter `chmod` und den symbolischen String darunter ab – dieselbe Schreibweise, die `ls -l` ausgibt."
  - "Tragen Sie den Dateinamen ein; Namen mit Leerzeichen oder Shell-Sonderzeichen werden im kopierten Befehl automatisch in Anführungszeichen gesetzt."
  - "Oder starten Sie mit der **Schnellauswahl**: 755 für Skripte und Verzeichnisse, 644 für normale Dateien, 600 für private Schlüssel, 444 für schreibgeschützte Dateien."
  - "Klicken Sie auf **Befehl kopieren** und fügen Sie ihn im Terminal ein."
faq:
  - q: "Was bedeutet chmod 755?"
    a: "7 für den Besitzer (Lesen 4 + Schreiben 2 + Ausführen 1), 5 für die Gruppe (Lesen 4 + Ausführen 1) und 5 für alle anderen. Der Besitzer darf alles; alle anderen dürfen lesen und ausführen, aber nicht ändern. Das ist der Standard für Skripte, Programme und Verzeichnisse."
  - q: "Was ist der Unterschied zwischen 644 und 755?"
    a: "644 (`rw-r--r--`) hat kein Ausführungsbit: richtig für Dokumente, Konfigurationen und Web-Dateien. 755 (`rwxr-xr-x`) ergänzt Ausführen für alle: nötig für Skripte und Programme sowie für Verzeichnisse, bei denen „Ausführen“ das Betreten bedeutet."
  - q: "Warum ist chmod 777 gefährlich?"
    a: "Damit darf jeder Benutzer des Systems die Datei oder das Verzeichnis ändern. Auf einem geteilten Server oder im Web-Root kann jeder kompromittierte Prozess dann Ihren Code ersetzen oder Dateien ablegen. Funktioniert etwas nur mit 777, liegt die eigentliche Lösung meist bei Besitzer oder Gruppe der Datei (`chown`), nicht bei weiteren Rechten."
  - q: "Welche Rechte braucht ein privater SSH-Schlüssel?"
    a: "600 (`rw-------`): lesbar und schreibbar nur für Sie. OpenSSH verweigert private Schlüssel, die andere lesen können, und meldet „UNPROTECTED PRIVATE KEY FILE“. Das Verzeichnis `~/.ssh` selbst sollte 700 haben."
  - q: "Was bedeutet Ausführen bei einem Verzeichnis?"
    a: "Es ist das Recht, das Verzeichnis zu durchqueren: mit `cd` hineinzuwechseln und auf Dateien darin per Name zuzugreifen. Lesen erlaubt, die Namen aufzulisten; ohne Ausführen sehen Sie die Namen, können die Dateien aber nicht öffnen. Deshalb haben Verzeichnisse meist 755 oder 700."
  - q: "Werden setuid, setgid oder das Sticky-Bit unterstützt?"
    a: "Nein. Der Rechner deckt die neun Grundbits ab, den dreistelligen Modus fast aller `chmod`-Befehle. Die Sonderbits sind eine vierte, vorangestellte Ziffer (4 setuid, 2 setgid, 1 Sticky, wie in `chmod 1777 /tmp`); ergänzen Sie sie bei Bedarf von Hand."
---

## So funktioniert es

Unix-Rechte sind neun Bits in drei Gruppen zu je drei. Jede Gruppe beantwortet dieselben drei Fragen – Lesen, Schreiben, Ausführen – für eine Benutzerklasse: den **Besitzer** der Datei (`u`), ihre **Gruppe** (`g`) und alle **anderen** (`o`).

Jedes Recht hat einen festen Wert; eine Ziffer ist einfach deren Summe:

| Recht | Wert | Symbol |
|---|---|---|
| Lesen | 4 | `r` |
| Schreiben | 2 | `w` |
| Ausführen | 1 | `x` |

Also 7 = 4 + 2 + 1 = `rwx`, 6 = 4 + 2 = `rw-`, 5 = 4 + 1 = `r-x` und 4 = `r--`. Der Rechner addiert die aktiven Schalter je Klasse, schreibt die drei Ziffern nebeneinander und wandelt jede Ziffer per Bittest (`ziffer & 4`, `& 2`, `& 1`) zurück in `r`, `w`, `x` oder `-`. Das führende `-` im symbolischen String ist das Dateityp-Zeichen, das `ls -l` für eine normale Datei zeigt (`d` für ein Verzeichnis).

Die Schnellauswahl macht das Gegenteil: Jede Ziffer von `644` wird in ihre Bits zerlegt, um die neun Schalter zu setzen.

Der kopierte Befehl lautet `chmod <oktal> <datei>`. Enthält der Name etwas anderes als Buchstaben, Ziffern und `._/@%+=:,-`, wird er in einfache Anführungszeichen gesetzt (`'meine datei.sh'`), eingebettete Anführungszeichen werden POSIX-konform maskiert – so lässt sich der Befehl gefahrlos in bash oder zsh einfügen.

### Übliche Modi

| Modus | Symbolisch | Typische Verwendung |
|---|---|---|
| 755 | `rwxr-xr-x` | Skripte, Programme, Verzeichnisse |
| 644 | `rw-r--r--` | Normale Dateien, Konfigurationen, Web-Assets |
| 700 | `rwx------` | Private Verzeichnisse wie `~/.ssh` |
| 600 | `rw-------` | Private Schlüssel, `.env`-Dateien, Zugangsdaten |
| 444 | `r--r--r--` | Dateien, die niemand ändern soll |
| 777 | `rwxrwxrwx` | Fast nie: Jeder kann sie ändern |

## Anwendungsfälle

- **„Permission denied“ beim Ausführen eines Skripts.** Ausführungsbit setzen: `chmod 755 deploy.sh`, oder `chmod u+x`, wenn nur Sie es ausführen.
- **Geheimnisse absichern.** Setzen Sie `.env`-Dateien, Dateien mit API-Keys und SSH-Schlüssel auf 600, damit andere Benutzer der Maschine sie nicht lesen können.
- **Webserver.** Übliche Setups nutzen 644 für Dateien und 755 für Verzeichnisse, im Besitz des Deploy-Benutzers und für den Webserver lesbar.
- **Docker und CI.** In Images kopierte oder von der CI ausgecheckte Dateien verlieren manchmal ihr Ausführungsbit; der Rechner liefert die exakte `RUN chmod`-Zeile.
- **Die Schreibweise lernen.** Übersetzen Sie zwischen `ls -l`-Ausgabe und Oktalzahlen, bis Sie `drwxr-x---` auf einen Blick lesen.
