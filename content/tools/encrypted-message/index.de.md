---
title: "Verschlüsselte Nachricht per Link senden"
description: "Eine Nachricht im Browser mit AES-256 und einer Passphrase verschlüsseln und als Link teilen. Der Text wird nie hochgeladen: Er steckt nur im Link."
intro: "Schreiben Sie eine Nachricht, wählen Sie eine Passphrase und erhalten Sie einen **Link**, der die Nachricht **mit AES-256-GCM verschlüsselt** enthält. Senden Sie Link und Passphrase **über verschiedene Kanäle**; der Empfänger öffnet den Link und entschlüsselt ihn im eigenen Browser. Nichts wird hochgeladen oder gespeichert: Der verschlüsselte Text steckt im Link selbst, im Teil nach `#`, den Browser nie an einen Server senden."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["verschlüsselte nachricht link", "verschlüsselte nachricht senden", "text online verschlüsseln", "passwortgeschützte nachricht", "passwort sicher teilen", "geheime notiz senden", "nachricht mit passwort verschlüsseln", "privater nachrichtenlink"]
tags: ["security", "privacy", "encryption", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/encrypted-message/"
tool_title: "Verschlüsselter Nachrichtenlink"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Schreiben Sie die **Nachricht** — ein WLAN-Passwort, einen Türcode, eine kurze private Notiz."
  - "Geben Sie eine **Passphrase** mit mindestens 8 Zeichen ein oder klicken Sie auf **Erzeugen** für eine zufällige."
  - "Klicken Sie auf **Verschlüsselten Link erstellen** und **Link kopieren**."
  - "Senden Sie den Link über einen Kanal (zum Beispiel E-Mail) und die **Passphrase über einen anderen** (Anruf, anderer Messenger). Nie beides in derselben Nachricht."
  - "Der Empfänger öffnet den Link, gibt die Passphrase ein und liest die Nachricht im eigenen Browser."
faq:
  - q: "Wird meine Nachricht irgendwo hochgeladen?"
    a: "Nein. Die Verschlüsselung läuft im Browser mit der Web Crypto API. Die verschlüsselte Nachricht steht im Link nach dem #-Zeichen, und Browser senden diesen Teil beim Öffnen des Links nicht an den Server. Diese Website erhält weder die Nachricht noch die Passphrase noch das Fragment des Links; es ist also nichts gespeichert, das abfließen oder gelöscht werden könnte."
  - q: "Zerstört sich der Link nach dem Lesen selbst?"
    a: "Nein, und kein Tool ohne Server kann das versprechen. Der Link ist die verschlüsselte Nachricht, er funktioniert also, solange jemand eine Kopie hat — im Postfach, in einem Chatverlauf, in einem Backup. Behandeln Sie ihn wie das Geheimnis selbst: Wer Link und Passphrase hat, kann ihn lesen. Brauchen Sie eine Nachricht, die verschwindet, nutzen Sie einen Dienst, der sie auf einem Server speichert und nach dem Lesen löscht — und vertrauen Sie damit diesem Server."
  - q: "Wie stark ist die Verschlüsselung?"
    a: "Die Nachricht wird mit AES-256 im GCM-Modus verschlüsselt, der zudem jede Änderung am Link erkennt. Der Schlüssel wird aus Ihrer Passphrase mit PBKDF2-HMAC-SHA-256 und 600.000 Iterationen abgeleitet, mit zufälligem Salt und zufälligem IV für jede Nachricht. Die Schwachstelle ist die Passphrase: Eine kurze oder erratbare kann jeder mit dem Link per Brute Force knacken, also nutzen Sie eine lange oder die Schaltfläche Erzeugen."
  - q: "Was, wenn die Passphrase falsch oder der Link abgeschnitten ist?"
    a: "Das Entschlüsseln schlägt mit einer klaren Meldung fehl. Authentifizierte Verschlüsselung kann eine falsche Passphrase nicht von einem veränderten Link unterscheiden, prüfen Sie also beides. Manche Apps schneiden sehr lange Links ab: Das Tool warnt ab etwa 2.000 Zeichen."
  - q: "Warum die Passphrase getrennt senden?"
    a: "Weil der Link allein ohne sie nutzlos ist. Gehen beide in derselben E-Mail oder demselben Chat, kann jeder, der dieses Gespräch lesen kann — jetzt oder später, etwa nach einem gehackten Konto —, auch die Nachricht lesen."
  - q: "Kann ich sehen, was das Tool tut?"
    a: "Ja. Der Code läuft in Ihrem Browser und lässt sich mit den Entwicklertools lesen. Im Netzwerk-Tab können Sie auch prüfen, dass Erstellen und Öffnen eines Links keine Anfrage mit Ihrer Nachricht senden."
---

## So funktioniert es

### Verschlüsselung im Browser

Beim Klick auf **Verschlüsselten Link erstellen** erzeugt die Seite einen zufälligen 16-Byte-Salt und einen zufälligen 12-Byte-IV, leitet aus Ihrer Passphrase mit **PBKDF2-HMAC-SHA-256** (600.000 Iterationen) einen 256-Bit-Schlüssel ab und verschlüsselt die Nachricht mit **AES-256-GCM**. Salt, IV und Geheimtext mit Authentifizierungs-Tag werden zusammengefügt, Base64url-kodiert und nach `#v1.` in den Link gesetzt.

### Warum die Nachricht nie einen Server erreicht

Der Teil einer URL nach `#` ist das **Fragment**. Browser behalten es auf dem Gerät: Es wird weder mit der Seitenanfrage gesendet noch in den `Referer`-Header übernommen. Der Link öffnet eine minimale Seite dieser Website ohne Werbung und ohne Statistik, die das Fragment liest, aus der Adressleiste entfernt und nach der Passphrase fragt. Entschlüsselt wird auf dem Gerät des Empfängers.

### Wovor es nicht schützt

- **Vor jemandem mit Link und Passphrase** — so liest der Empfänger die Nachricht, und so könnte es jeder andere.
- **Vor einer schwachen Passphrase** — wer den Link hat, kann offline Passphrasen so schnell durchprobieren, wie seine Hardware erlaubt; die 600.000 Iterationen machen jeden Versuch langsam, nicht unmöglich.
- **Vor einem kompromittierten Gerät** — Schadsoftware beim Absender oder Empfänger kann die Nachricht vor der Verschlüsselung oder nach der Entschlüsselung lesen.
- **Vor Kopien des Links** — Postfächer, Chatverläufe und Backups bewahren ihn auf. Er lässt sich nicht widerrufen.

## Anwendungsfälle

- **Ein Passwort oder den WLAN-Schlüssel teilen** mit Kollegen oder Gästen, ohne dass es im Chatverlauf lesbar bleibt.
- **Einen Türcode oder Alarm-PIN senden** an Lieferdienst oder Haussitter.
- **Einen Wiederherstellungscode oder API-Schlüssel weitergeben** per E-Mail, mit der Passphrase am Telefon.
- **Eine private Notiz hinterlassen** an einem öffentlichen Ort — Ticket, Forum, geteiltes Dokument —, die nur Leute mit der Passphrase lesen können.
- **Vor dem Senden** mit [PassFort](../pass-fort/) prüfen, wie schwer Ihre Passphrase zu erraten ist.
