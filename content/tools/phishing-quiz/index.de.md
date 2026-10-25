---
title: "Phishing-Test: Erkennen Sie die Falle?"
description: "Kostenloser Phishing-Test: 10 realistische E-Mails, SMS, Login-Seiten, QR-Codes und Links. Falle erkennen, Warnsignale sehen, Ergebnis teilen."
intro: "Zehn realistische Szenarien – **E-Mails, SMS, Anmeldeseiten, QR-Codes und Links** – zufällig aus 32 ausgewählt. Entscheiden Sie jeweils: **Phishing oder echt?** Nach jeder Antwort werden die Warnsignale direkt in der Nachbildung markiert und in einem Satz erklärt. Alle Marken und Domains sind erfunden, und nichts, was Sie tun, verlässt Ihren Browser."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["phishing test", "phishing quiz", "phishing erkennen", "phishing simulation", "phishing mail erkennen", "smishing quiz", "security awareness schulung", "betrugs mails erkennen"]
tags: ["sicherheit", "phishing", "awareness", "tool"]
app_category: "EducationalApplication"
tool_file: "/tools/phishing-quiz/"
tool_title: "Phishing-Quiz"
tool_height: 980
tool_sandbox: "allow-scripts allow-same-origin allow-top-navigation-by-user-activation"
tool_allow: "clipboard-write; web-share"
share_scores: 10
share_card_title: "Ich habe {score}/10 im Phishing-Quiz"
howto:
  - "Klicken Sie auf **Quiz starten**. Sie erhalten 10 Szenarien; drei oder vier davon sind echt, „alles ist Phishing“ funktioniert also nicht."
  - "Lesen Sie die Kontextzeile und prüfen Sie die Nachbildung wie das Original: die Absenderadresse, wohin der Link wirklich führt (mit der Maus darüberfahren oder die Schaltfläche fokussieren), die Adressleiste, den Namen des Anhangs."
  - "Antworten Sie mit **Phishing** oder **Echt**. Die Warnsignale (oder die Merkmale einer echten Nachricht) werden in der Nachbildung nummeriert und darunter erklärt."
  - "Am Ende sehen Sie Punktzahl, Stufe und die Themen zum Wiederholen, mit Links zu passenden Tools."
  - "Mit **Ergebnis teilen** senden Sie das Resultat weiter: Der geteilte Text enthält nur die Punktzahl und einen Link."
faq:
  - q: "Sind die Firmen im Quiz echt?"
    a: "Nein. Alle Marken, Personen, Telefonnummern und Domains sind erfunden, und alle Webadressen nutzen für Dokumentation reservierte Domains (.example, .test) oder den Dokumentations-IP-Bereich 192.0.2.x – nichts im Quiz verweist auf eine echte Organisation."
  - q: "Werden meine Punktzahl oder meine Klicks irgendwohin gesendet?"
    a: "Nein. Das Quiz läuft vollständig in Ihrem Browser und stellt keine Netzwerkanfragen. Es wird nichts gespeichert. Teilen entscheiden Sie selbst: Die Schaltfläche übergibt nur Punktzahl und Quiz-Adresse an das Teilen-Menü Ihres Smartphones oder kopiert sie."
  - q: "Wie werden die Fragen ausgewählt?"
    a: "Jede Runde zieht zufällig 10 von 32 Szenarien, darunter drei oder vier echte und mindestens drei verschiedene Arten (E-Mail, SMS, Anmeldeseite, QR-Code, Link). Beim nächsten Spiel erhalten Sie eine andere Mischung."
  - q: "Was sind Smishing und Quishing?"
    a: "Smishing ist Phishing per SMS oder Messenger. Quishing ist Phishing über einen QR-Code – auf einem Aufkleber, einem Plakat oder in einer E-Mail. Ein QR-Code verbirgt die Adresse, bis Sie ihn scannen, und verlagert Sie aufs Smartphone, wo Sie einen Link nicht vor dem Öffnen prüfen können."
  - q: "Was tue ich mit einer echten Phishing-Nachricht?"
    a: "Nicht klicken, nicht antworten, keine Anhänge öffnen. Melden Sie sie – bei der Arbeit an die IT oder das Sicherheitsteam, sonst über die Funktion „Phishing melden“ Ihres E-Mail-Anbieters – und löschen Sie sie dann. Haben Sie schon ein Passwort eingegeben, ändern Sie es sofort auf der echten Website und aktivieren Sie die Zwei-Faktor-Authentifizierung."
  - q: "Kann ich das Quiz für Security-Awareness-Schulungen nutzen?"
    a: "Ja, es ist kostenlos und braucht keine Anmeldung. Unter „Im Team-Training einsetzen“ finden Sie einen einfachen Ablauf für ein Meeting."
---

## So funktioniert es

Jedes Szenario ist eine Nachbildung aus echten Seitenelementen, kein Bild: Sie lässt sich mit einem Screenreader lesen und nur per Tastatur spielen. Dazu gibt es eine Kontextzeile („Sie erwarten eine Lieferung…“), denn ob eine Nachricht verdächtig ist, hängt oft davon ab, was Sie gerade getan haben.

Die Szenarien decken die Muster hinter dem meisten Phishing ab:

- **Absender und Doppelgänger-Domains** – `velorabank-alerts.test` statt `velorabank.example`, eine Ziffer 1 statt eines l.
- **Wohin ein Link wirklich führt** – der sichtbare Text sagt das eine, das Ziel etwas anderes; ein bekannter Name nur als Subdomain einer fremden Domain; der `@`-Trick.
- **Druck** – Fristen, Sperrandrohungen, Geheimhaltung, „Ich kann gerade nicht telefonieren“.
- **Anfragen, die kein echter Dienst stellt** – Karten-PIN, Geschenkkarten, Gebühren für ein Paket.
- **Anhänge und QR-Codes** – getarnte Dateitypen, QR-Codes, die Sie aufs Smartphone verlagern.

Im Pool sind auch echte Nachrichten, denn übertriebenes Misstrauen hat seinen Preis: echte Sicherheitswarnungen, Belege und Passwort-Zurücksetzungen, die Sie selbst angefordert haben. Nach Ihrer Antwort werden die entscheidenden Elemente in der Nachbildung nummeriert.

Die Ergebnisseite ordnet Sie einer Stufe zu und listet die Themen hinter Ihren Fehlern auf, mit Links zu hilfreichen Tools: [Link Hazmat](../link-hazmat/) zum Prüfen verdächtiger Links und die E-Mail-Header-Analyse zum Prüfen des Absenders.

## Im Team-Training einsetzen

Das Quiz eignet sich gut als 15-minütiger Block in einem Team-Meeting:

1. **Teilen Sie Ihren Bildschirm** und öffnen Sie diese Seite. Starten Sie das Quiz.
2. **Lesen Sie jedes Szenario laut vor** und geben Sie dem Raum 30 Sekunden. Lassen Sie abstimmen, per Handzeichen oder im Chat, bevor jemand klickt.
3. **Antworten Sie wie die Mehrheit** und gehen Sie die nummerierten Warnsignale gemeinsam durch. Fragen Sie, wem welches aufgefallen ist.
4. **Nach der Runde** spielen alle einmal allein und teilen ihre Punktzahl im Chat. Die geteilte Nachricht enthält nur Punktzahl und Link.
5. **Schließen Sie mit Ihrem eigenen Meldeweg ab**: wem man es sagt, wie, und was nach einer Meldung passiert.

Jede Runde ist anders, dieselben Personen können also in einer späteren Sitzung erneut spielen. Es wird nichts erfasst: Das Quiz ist eine Lernübung, keine Bewertung einzelner Personen.

## Anwendungsfälle

- **Security Awareness** für Teams, Schulen und Familien, ohne Konten und ohne Datenerhebung.
- **Onboarding**: eine schnelle, praktische Einführung in die Nachrichten, die neue Kolleginnen und Kollegen bekommen.
- **Selbstcheck**, bevor Sie die unerwartete Nachricht von Bank oder Paketdienst öffnen.
- **Unterricht** über den Unterschied zwischen verdächtigen und echten Nachrichten, mit den Nachbildungen als Diskussionsgrundlage.
