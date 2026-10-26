---
title: "SPF, DKIM und DMARC prüfen: Domain-Check"
description: "SPF-, DKIM- und DMARC-Einträge einer Domain prüfen, SPF-Abfragen gegen das Limit von 10 zählen, DKIM-Schlüssel und BIMI prüfen und Korrekturen erhalten."
intro: "Geben Sie eine Domain ein, um ihre **E-Mail-Authentifizierung** zu bewerten. Das Tool liest den **SPF**-Eintrag und zählt seine DNS-Abfragen **über alle includes** gegen das Limit von 10, liest **DMARC**-Richtlinie, Prozentsatz, Berichtsadressen und Ausrichtung, misst die **Länge der DKIM-Schlüssel** und prüft **MX** und **BIMI**. Zu jedem Problem gibt es einen **Beispiel-Eintrag** zur Korrektur. DNS-Abfragen gehen an den DNS-over-HTTPS-Resolver von Cloudflare, nur wenn Sie auf Prüfen klicken."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["spf prüfen", "dmarc prüfen", "dkim prüfen", "spf dkim dmarc check", "spf eintrag prüfen", "dmarc eintrag beispiel", "spf zu viele dns abfragen", "dkim schlüssellänge", "dmarc richtlinie reject", "bimi eintrag"]
tags: ["security", "email", "dns", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/spf-dmarc-checker/"
tool_title: "SPF-, DKIM- und DMARC-Check"
tool_height: 1150
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Geben Sie eine **Domain** ein (oder fügen Sie eine E-Mail-Adresse ein; verwendet wird nur der Teil nach dem @)."
  - "Optional: Geben Sie Ihre **DKIM-Selektoren** ein, durch Kommas getrennt. Ohne sie testet das Tool häufige Selektornamen."
  - "Klicken Sie auf **Prüfen**. Nur in diesem Moment werden DNS-Abfragen gesendet."
  - "Lesen Sie die **Note** und jeden Abschnitt: SPF mit Abfragezähler und include-Baum, DMARC-Tags, DKIM-Schlüssel, MX und BIMI."
  - "Kopieren Sie unter **Vorgeschlagene Korrekturen** die Beispiel-Einträge, ersetzen Sie die Teile in spitzen Klammern und stimmen Sie sich vor dem Veröffentlichen mit Ihrem Mail-Anbieter ab."
faq:
  - q: "Was wird gesendet, und an wen?"
    a: "Wenn Sie auf Prüfen klicken, sendet Ihr Browser DNS-Abfragen für die Domain (TXT-Einträge für SPF, _dmarc, DKIM-Selektoren und BIMI sowie MX-Einträge) an den öffentlichen DNS-over-HTTPS-Resolver von Cloudflare, cloudflare-dns.com. Wie jede Web-Anfrage übermittelt das Cloudflare Ihre IP-Adresse und den User-Agent Ihres Browsers. An diese Website wird nichts gesendet, und vor dem Klick geht nichts hinaus."
  - q: "Warum hat SPF ein Limit von 10 Abfragen?"
    a: "Der SPF-Standard (RFC 7208) begrenzt die Mechanismen, die eine DNS-Abfrage brauchen — include, a, mx, ptr, exists und den Modifikator redirect — auf 10 pro Prüfung, gezählt über alle verschachtelten includes. Empfänger brechen beim Überschreiten mit einem dauerhaften Fehler ab, und SPF schlägt für Ihre gesamte Post fehl, nicht nur für die zusätzlichen Absender. ip4, ip6 und all zählen nicht."
  - q: "Warum wird kein DKIM-Schlüssel gefunden, obwohl meine Post signiert ist?"
    a: "DKIM-Schlüssel liegen unter einem vom Anbieter gewählten Selektornamen (selektor._domainkey.ihredomain), und DNS kann sie nicht auflisten. Das Tool testet nur einige häufige Namen. Ihren Selektor finden Sie im Tag s= eines DKIM-Signature-Headers (die E-Mail-Header-Analyse auf dieser Website zeigt ihn); geben Sie ihn ein."
  - q: "Reicht p=none?"
    a: "Es ist der richtige erste Schritt: Sie erhalten Berichte, ohne die Zustellung zu beeinflussen. Es hindert aber niemanden daran, Ihre Domain zu fälschen. Wenn die Berichte zeigen, dass Ihre legitimen Absender bestehen, wechseln Sie zu p=quarantine und dann zu p=reject."
  - q: "~all oder -all?"
    a: "Beide kennzeichnen nicht gelistete Server als nicht autorisiert. Mit DMARC auf quarantine oder reject richten sich Empfänger ohnehin nach dem DMARC-Ergebnis, daher ist ~all eine übliche und sichere Wahl; -all ist strenger, und manche Empfänger weisen Nachrichten deswegen womöglich schon vor der DMARC-Auswertung ab."
  - q: "Sind die Beispiel-Einträge direkt einsetzbar?"
    a: "Sie sind Ausgangspunkte, gebaut aus Ihren aktuellen Einträgen. Teile in spitzen Klammern müssen ersetzt werden, und nur Sie oder Ihr Mail-Anbieter kennen alle Dienste, die für Ihre Domain senden. Stimmen Sie sich mit dem Anbieter ab und prüfen Sie erneut, wenn das DNS aktualisiert ist."
---

## So funktioniert es

### SPF: Abfragen zählen wie die Empfänger

Das Tool holt die TXT-Einträge der Domain und nimmt den, der mit `v=spf1` beginnt. Dann geht es ihn Term für Term durch. Jedes `include`, `a`, `mx`, `ptr`, `exists` und `redirect` zählt als eine Abfrage, und jedes `include` wird ebenfalls geholt und durchlaufen, sodass auch verschachtelte Anbieter mitzählen. Die Summe wird mit dem Limit von 10 aus RFC 7208 verglichen. Gemeldet werden außerdem includes auf Domains ohne SPF, mehr als zwei Abfragen ohne Ergebnis, include-Schleifen, der nicht empfohlene Mechanismus `ptr` und der Qualifier von `all`.

### DMARC: Richtlinie, Abdeckung und Berichte

Der Eintrag unter `_dmarc.<domain>` wird Tag für Tag ausgewertet. Eine Subdomain ohne eigenen Eintrag erbt den der Hauptdomain und deren `sp=`-Richtlinie, wie Empfänger es tun. Die Note hängt von der Richtlinie (`none`, `quarantine`, `reject`) ab, von `pct`, davon, ob Sammelberichte (`rua`) aktiv sind, und ob Berichtsadressen auf einer anderen Domain den nötigen Autorisierungseintrag veröffentlicht haben (RFC 7489, Abschnitt 7.1).

### DKIM: Schlüssellänge aus dem öffentlichen Schlüssel

Für jeden gefundenen Selektor wird der Wert `p=` dekodiert und die Länge des RSA-Moduls aus dem Schlüssel gelesen. Schlüssel unter 1024 Bit dürfen Empfänger nicht akzeptieren (RFC 8301); empfohlen sind 2048 Bit. Leere Schlüssel gelten als widerrufen, Ed25519-Schlüssel werden erkannt.

### MX und BIMI

MX-Einträge zeigen, wo die Domain Post empfängt; ein „Null-MX“ (`0 .`) bedeutet, dass sie keine annimmt. BIMI (`default._bimi`) ist optional und funktioniert nur mit einer zu 100 % durchgesetzten DMARC-Richtlinie.

## Anwendungsfälle

- **Vor dem Newsletter-Versand** — sicherstellen, dass SPF, DKIM und DMARC bestehen, damit die Post im Posteingang landet.
- **Nach dem Hinzufügen eines Maildienstes** — prüfen, ob das neue `include:` SPF über 10 Abfragen gebracht hat.
- **Eine Domain absichern** — DMARC mit Zuversicht von `p=none` auf `p=reject` stellen und Domains schützen, die nie Post senden.
- **Sicherheitsprüfungen** — den Spoofing-Schutz der Domains eines Dienstleisters oder der eigenen Organisation prüfen.
- **Eine verdächtige E-Mail untersuchen** — sehen, was die Absenderdomain veröffentlicht, und dann die Nachricht selbst mit der [E-Mail-Header-Analyse](../email-header-analyzer/) lesen.
