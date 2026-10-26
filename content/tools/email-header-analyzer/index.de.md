---
title: "E-Mail-Header analysieren: Absender prüfen"
description: "E-Mail-Header einfügen, den Weg jeder Station nachverfolgen, SPF, DKIM und DMARC prüfen und gefälschte Absender erkennen. Kostenlos, privat, im Browser."
intro: "Fügen Sie die **rohen Header** einer verdächtigen E-Mail ein, um zu sehen, woher sie wirklich kommt. Die Analyse rekonstruiert den **Weg Server für Server** mit der Verzögerung jeder Station, liest die von Ihrem Anbieter vermerkten **SPF-, DKIM-, DMARC- und ARC-Ergebnisse** und zeigt **Widersprüche** zwischen From, Reply-To und Return-Path. Alles wird im Browser ausgewertet: Die Header werden nirgendwohin gesendet."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["e-mail header analysieren", "e-mail header auslesen", "e-mail absender prüfen", "gefälschte e-mail erkennen", "gmail original anzeigen header", "spf dkim dmarc prüfen e-mail", "e-mail herkunft verfolgen", "e-mail spoofing erkennen"]
tags: ["security", "email", "phishing", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/email-header-analyzer/"
tool_title: "E-Mail-Header-Analyse"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Kopieren Sie die rohen Header aus Ihrem Mailprogramm (siehe **So finden Sie die Header** unten) — oder den ganzen Quelltext der Nachricht, der Inhalt wird ignoriert."
  - "Fügen Sie sie in das Feld ein. Die Analyse startet beim Einfügen; mit **Analysieren** wiederholen Sie sie."
  - "Lesen Sie das **Urteil** und die **Signale**, das schwerwiegendste zuerst. Jedes erklärt, was es bedeutet und wann es harmlos ist."
  - "Prüfen Sie die Tabelle **Absender-Identität**: Die Domains von From, Reply-To und Return-Path gehören normalerweise zur selben Organisation."
  - "Verfolgen Sie den **Weg** vom ersten Server bis in Ihr Postfach. Lange Verzögerungen und unerwartete Server verdienen einen zweiten Blick."
faq:
  - q: "Werden meine Header hochgeladen?"
    a: "Nein. Die Header werden vom JavaScript dieser Seite ausgewertet, und das Tool stellt keine Netzwerkanfragen. Sie können die Seite öffnen, die Internetverbindung trennen, und es funktioniert weiter."
  - q: "Kann die Analyse sicher sagen, ob eine E-Mail Phishing ist?"
    a: "Kein Tool kann das. Header zeigen, wie die Nachricht gereist ist und ob die Absenderdomain für sie bürgt. Eine Nachricht kann alle Prüfungen bestehen und trotzdem Betrug sein, gesendet von einer ähnlich aussehenden Domain des Betrügers. Prüfen Sie also auch die From-Domain selbst und die Links (das Tool Link Hazmat auf dieser Website prüft sie)."
  - q: "Warum gelten manche Header als nicht vertrauenswürdig?"
    a: "Alles unterhalb der Received-Zeilen Ihres Anbieters kann jeder unterwegs schreiben, auch der Absender. Die Analyse vertraut dem Authentication-Results-Header Ihres Anbieters und behandelt den Rest als Behauptung. Wenn Sie eine als Anhang weitergeleitete Nachricht haben, analysieren Sie das angehängte Original, nicht die Weiterleitung."
  - q: "Was bedeuten SPF, DKIM und DMARC?"
    a: "SPF legt fest, welche Server für eine Domain senden dürfen. DKIM ist eine kryptografische Signatur der sendenden Domain. DMARC ist bestanden, wenn SPF oder DKIM für dieselbe Domain wie im From bestanden ist, und sagt Empfängern, was zu tun ist, wenn keines davon besteht. ARC hält die ursprünglichen Ergebnisse fest, wenn eine Liste oder Weiterleitung die Nachricht verändert."
  - q: "Warum hat ein echter Newsletter einen anderen Return-Path?"
    a: "Versanddienste senden im Auftrag von Unternehmen und sammeln Unzustellbarkeitsmeldungen auf einer eigenen Domain oder Subdomain. Deshalb wird ein Return-Path oder eine Message-ID auf einer anderen Domain nur als gering eingestuft: Wichtig wird es zusammen mit einem fehlgeschlagenen DMARC oder einem Reply-To auf einer fremden Domain."
  - q: "Warum laufen manche Zeiten rückwärts?"
    a: "Jeder Server stempelt die Zeit seiner eigenen Uhr, und manche Uhren gehen falsch. Die Analyse meldet das als Zeitabweichung und zeigt den Weg trotzdem in der richtigen Reihenfolge."
---

## So finden Sie die Header

Die meisten Mailprogramme verstecken die Header. Öffnen Sie zuerst die Nachricht, dann:

- **Gmail (Web)** — Nachricht öffnen, neben „Antworten“ auf **⋮ Mehr** klicken und **Original anzeigen** wählen. **In Zwischenablage kopieren** drücken. Die Gmail-App auf dem Handy zeigt keine Header; nutzen Sie einen Browser.
- **Outlook für Windows (klassisch)** — Nachricht per Doppelklick im eigenen Fenster öffnen, dann **Datei → Eigenschaften**. Die Header stehen unten im Feld **Internetkopfzeilen**: hineinklicken, Strg+A und Strg+C drücken.
- **Neues Outlook und Outlook im Web** — Nachricht öffnen, auf **… Weitere Aktionen → Ansicht → Nachrichtendetails anzeigen** klicken und den Text kopieren.
- **Apple Mail (Mac)** — Nachricht auswählen und **Darstellung → E-Mail → Alle Header** (⇧⌘H) wählen, oder **Darstellung → E-Mail → Rohformat** (⌥⌘U) für die ganze Nachricht. Mail auf iPhone und iPad zeigt keine Header.
- **Thunderbird** — Nachricht auswählen und **Ansicht → Nachrichtenquelltext** (Strg+U, ⌘U auf dem Mac) wählen. Alles oberhalb der ersten Leerzeile kopieren, oder einfach alles.

Die Menünamen können je nach Version leicht abweichen. Leiten Sie die verdächtige E-Mail nicht an sich selbst weiter, um die Header zu sehen: Eine Weiterleitung erzeugt eine neue Nachricht mit neuen Headern.

## So funktioniert es

### Der Weg: Received-Zeilen von unten lesen

Jeder Mailserver, der eine Nachricht bearbeitet, fügt oben eine **Received**-Zeile hinzu, die älteste steht also ganz unten. Die Analyse kehrt sie zu einer Zeitleiste vom ersten Server bis in Ihr Postfach um und zeigt die Zeit zwischen den Stationen. Vertrauenswürdig sind nur die Zeilen Ihres eigenen Anbieters: Ein Absender kann darunter gefälschte Received-Zeilen schreiben. Deshalb stützt sich die Analyse auf die Authentifizierungsergebnisse und nicht auf die behauptete Herkunft.

### Authentifizierung: Was Ihr Anbieter schon geprüft hat

Beim Eingang prüft Ihr Anbieter **SPF**, **DKIM** und **DMARC** und vermerkt die Ergebnisse im Header **Authentication-Results**. Die Analyse liest diesen Header und prüft zusätzlich die **Ausrichtung** (Alignment): Eine DKIM-Signatur oder ein bestandenes SPF schützt Sie nur, wenn sie zur selben Organisation gehören wie die From-Adresse. DNS-Abfragen oder eigene Signaturprüfungen macht das Tool nicht, denn Ihr Anbieter hat das bei der Zustellung bereits getan, mit den damals gültigen Schlüsseln.

### Widersprüche bei der Identität

Der Anzeigename ist freier Text, daher setzen Betrüger oft eine vertrauenswürdige Adresse hinein (`"hilfe@ihrebank.example" <x@random.test>`). Die Analyse vergleicht die Domains von **From**, **Reply-To**, **Return-Path** und der **Message-ID** und erklärt, welche Unterschiede bei Versanddiensten normal sind und welche auf einen Betrüger hindeuten.

## Anwendungsfälle

- **Eine verdächtige E-Mail** — prüfen, ob die Nachricht der „Bank“ oder des „Paketdienstes“ wirklich von dieser Domain kommt, bevor Sie etwas anklicken.
- **Helpdesk und Sicherheitsteams** — gemeldetes Phishing schnell einordnen und die Zeitleiste in ein Ticket kopieren.
- **Zustellbarkeit** — herausfinden, warum Ihre eigenen Newsletter an DMARC scheitern oder im Spam landen und welche Station die Zustellung verzögert.
- **Zum Lernen** — SPF, DKIM und DMARC an realistischen Beispielen verstehen und sich dann im [Phishing-Quiz](../phishing-quiz/) testen.
