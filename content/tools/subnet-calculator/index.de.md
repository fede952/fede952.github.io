---
title: "Subnetzrechner IPv4/IPv6, CIDR und VLSM"
description: "Netz, Broadcast, Hostbereich, Maske und Wildcard für jedes IPv4- oder IPv6-CIDR berechnen und Blöcke in gleiche oder VLSM-Subnetze teilen. Im Browser."
intro: "Ein **Subnetzrechner** für IPv4 und IPv6: Geben Sie eine Adresse mit Präfix oder Maske ein und Sie sehen sofort Netz, Broadcast, nutzbaren Hostbereich, Netzmaske, Wildcard und Hostanzahl, dazu eine Binäransicht. Ein dritter Tab teilt einen Block in gleich große Subnetze oder in VLSM-Subnetze nach Hostanzahl."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["subnetzrechner", "subnetz rechner", "cidr rechner", "subnetzmaske berechnen", "ipv6 subnetz rechner", "vlsm rechner", "wildcard maske", "netzadresse berechnen"]
tags: ["netzwerk", "entwickler-tools", "ipv4", "ipv6", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/subnet-calculator/"
tool_title: "Subnetzrechner für IPv4, IPv6 und VLSM"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Geben Sie im Tab **IPv4** eine Adresse mit Präfix (`10.0.0.5/8`), mit Netzmaske in Punktschreibweise (`172.16.5.4 255.255.240.0`) oder mit Wildcard im Cisco-Stil (`192.168.1.1 0.0.0.255`) ein. Eine Adresse ohne Präfix gilt als `/32`."
  - "Die Ergebnisse erscheinen beim Tippen: Netz, Broadcast, erster und letzter nutzbarer Host, Netzmaske, Wildcard, nutzbare und gesamte Adressen sowie der Adresstyp (privat, öffentlich, CGNAT, Link-Local …)."
  - "In der Tabelle **Binär** sind die Netzbits hervorgehoben und die Hostbits abgeblendet: So sehen Sie genau, wo das Präfix die Adresse teilt."
  - "Fügen Sie im Tab **IPv6** eine volle oder komprimierte Adresse mit Präfix ein: Sie erhalten die nach RFC 5952 komprimierte und die ausgeschriebene Form, die erste und letzte Adresse des Präfixes und die Anzahl der enthaltenen /64-Netze."
  - "Geben Sie unter **Aufteilen (VLSM)** den Block ein und wählen Sie **In gleich große Subnetze** (Anzahl) oder **Nach Hosts pro Subnetz (VLSM)** (eine Liste wie `100, 50, 20, 2`). Jeder Wert lässt sich mit **Kopieren** übernehmen, der ganze Plan mit **Tabelle kopieren**."
faq:
  - q: "Warum hat ein /24 nur 254 nutzbare Hosts statt 256?"
    a: "Ein /24 hat 256 Adressen, aber die erste ist die Netzadresse und die letzte die Broadcast-Adresse. Keine der beiden kann einem Host zugewiesen werden, es bleiben 254. Dieselbe Regel (gesamt minus zwei) gilt für alle Präfixe bis /30."
  - q: "Wie behandelt der Rechner /31 und /32?"
    a: "Ein /31 gilt als Punkt-zu-Punkt-Verbindung nach RFC 3021: Beide Adressen sind nutzbar, es gibt keinen Broadcast. Ein /32 ist ein einzelner Host, verwendet für Loopbacks, Host-Routen und Firewallregeln. Ältere Geräte ohne RFC-3021-Unterstützung brauchen für eine Verbindung ein /30."
  - q: "Was ist eine Wildcard-Maske?"
    a: "Die bitweise Umkehrung der Netzmaske: Aus 255.255.255.0 wird 0.0.0.255. Cisco-ACLs und OSPF-network-Anweisungen verwenden Wildcards, bei denen ein 0-Bit „muss übereinstimmen“ und ein 1-Bit „beliebiger Wert“ bedeutet. Sie können eine Wildcard direkt ins IPv4-Feld eingeben; der Rechner wandelt sie in das Präfix um."
  - q: "Was bedeutet VLSM und warum werden die größten Subnetze zuerst vergeben?"
    a: "Variable Length Subnet Masking gibt jedem Subnetz ein eigenes Präfix: Ein LAN mit 100 Hosts erhält ein /25, eine Punkt-zu-Punkt-Verbindung ein /31. Wird von der größten zur kleinsten Anforderung vergeben, bleibt jedes Subnetz an seiner Grenze ausgerichtet, ohne verschwendete Lücken; angezeigt werden die Ergebnisse dann in Ihrer Eingabereihenfolge."
  - q: "Warum erhalte ich 4 Subnetze, wenn ich in 3 aufteile?"
    a: "Beim gleichmäßigen Aufteilen werden Hostbits entliehen, und jedes Bit verdoppelt die Anzahl der Subnetze: 1 Bit ergibt 2, 2 Bits ergeben 4. Drei Subnetze brauchen also 2 Bits und damit 4 Subnetze. Mit dem VLSM-Modus erhalten Sie genau so viele Subnetze wie gewünscht, jedes passend zu seiner Hostanzahl."
  - q: "Welches IPv6-Präfix sollte ein LAN verwenden?"
    a: "Ein /64. Die zustandslose Autokonfiguration (SLAAC) und viele IPv6-Funktionen setzen eine 64-Bit-Interface-ID voraus. Standorte erhalten meist ein /48 oder /56 und teilen es in /64-Netze; der Rechner zeigt, wie viele /64-Netze in das eingegebene Präfix passen."
  - q: "Wird meine Eingabe an einen Server gesendet?"
    a: "Nein. Alle Berechnungen erledigt ein kleines JavaScript-Modul in Ihrem Browser; die Seite stellt keine Anfrage mit Ihren Daten. Sie können sie also auch mit internen Adressplänen verwenden."
---

## So funktioniert es

### IPv4-Arithmetik

Eine IPv4-Adresse ist eine 32-Bit-Zahl. Der Rechner liest die vier Oktette (Werte über 255 und mehrdeutige führende Nullen wie `010` werden abgelehnt), bildet die Netzmaske aus der Präfixlänge, indem er die oberen *n* Bits setzt, und rechnet dann mit einfachen Bitoperationen:

- **Netzadresse** = Adresse AND Maske.
- **Wildcard** = NOT Maske.
- **Broadcast-Adresse** = Netz OR Wildcard.
- **Nutzbare Hosts** = 2^(32 − Präfix) − 2, mit den zwei Ausnahmen aus den FAQ: Ein /31 hat zwei nutzbare Adressen (RFC 3021), ein /32 eine.

Eine Maske in Punktschreibweise muss *zusammenhängend* sein: erst Einsen, dann Nullen. `255.255.240.0` wird als /20 akzeptiert, `255.0.255.0` abgelehnt. Ist der Wert keine gültige Netzmaske, aber eine gültige Wildcard (erst Nullen, dann Einsen), wird er als Wildcard gelesen – auch `0.0.15.255` bedeutet also /20.

Der Adresstyp stammt aus den IANA-Registern für besondere Zwecke: private Bereiche nach RFC 1918 (10/8, 172.16/12, 192.168/16), gemeinsamer Adressraum für Carrier-Grade-NAT (100.64/10, RFC 6598), Loopback (127/8), Link-Local (169.254/16), die drei Dokumentationsbereiche, Multicast (224/4) und reservierter Raum.

### IPv6

IPv6-Adressen sind 128-Bit-Zahlen und werden als JavaScript-`BigInt` verarbeitet, damit keine Genauigkeit verloren geht. Der Parser akzeptiert die volle Form, die `::`-Kompression (einmal pro Adresse) und einen IPv4-Anhang wie `::ffff:192.0.2.1`. Die Ausgabe folgt **RFC 5952**, der kanonischen Textform: Hexadezimal in Kleinbuchstaben, keine führenden Nullen in einer Gruppe, und die längste Folge von mindestens zwei Nullgruppen wird durch `::` ersetzt (bei gleich langen Folgen die linke). Eine einzelne Nullgruppe wird nie komprimiert.

Bei einem Präfix ist die erste Adresse die Adresse AND die Maske, die letzte setzt alle Hostbits auf eins, die Größe beträgt 2^(128 − Präfix). IPv6 kennt keinen Broadcast, deshalb gibt es kein „minus zwei“.

### Einen Block aufteilen

*In gleich große Subnetze* hängt ⌈log₂ n⌉ Bits an das Präfix und listet alle entstehenden Subnetze (bis zu 1.024 Zeilen). *VLSM* berechnet für jede Hostanzahl das kleinste passende Präfix, sortiert die Anforderungen von groß nach klein und vergibt jede an der nächsten Adresse, die zu ihrer Größe ausgerichtet ist. Passt eine Anforderung nicht mehr in den Rest, erhalten Sie eine Fehlermeldung, die sie benennt, statt eines Plans mit Überschneidungen.

## Anwendungsfälle

- **Adresspläne entwerfen.** Teilen Sie ein /22 für einen neuen Standort in VLANs für Benutzer, Telefonie, Drucker und Management nach Personenzahl auf und übernehmen Sie die Tabelle in Ihre Dokumentation.
- **Firewallregeln und ACLs schreiben.** Ermitteln Sie Netz/Präfix oder Wildcard für eine Objektgruppe und prüfen Sie, ob ein /20 wirklich den erwarteten Bereich abdeckt.
- **Fehlersuche.** Zwei Hosts erreichen sich nicht: Geben Sie beide Adressen mit ihrer Maske ein und prüfen Sie, ob sie tatsächlich im selben Subnetz liegen.
- **Cloud-Netze.** Planen Sie VPC- und Subnetz-CIDRs ohne Überschneidungen – Cloud-Anbieter reservieren pro Subnetz zusätzlich zu Netz und Broadcast einige Adressen.
- **Lernen und Prüfungen.** Kontrollieren Sie Subnetting-Aufgaben für CCNA, Network+ oder Vorstellungsgespräche; die Binäransicht zeigt, warum das Ergebnis so ist.
