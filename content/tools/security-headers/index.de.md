---
title: "Security-Header- und CSP-Analyse"
description: "HTTP-Antwort-Header oder eine Content-Security-Policy einfügen und fehlende Header, schwache CSP-Regeln und unsichere Cookies samt Lösung finden. Ohne Abruf."
intro: "Fügen Sie die **Antwort-Header** einer Seite ein – aus `curl -sI` oder den DevTools des Browsers – oder nur eine **Content-Security-Policy**. Die Analyse prüft **HSTS**, **CSP**, **X-Content-Type-Options**, den Schutz vor Einbettung, **Referrer-Policy**, **Permissions-Policy**, **COOP**, **CORS** und jedes **Set-Cookie**, erklärt jedes Problem und zeigt die Lösung. Sie stellt **keine Netzwerkanfragen**: Sie liest nur, was Sie einfügen, und funktioniert daher auch für Staging- und Intranet-Seiten."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["security header prüfen", "csp evaluator", "content security policy prüfen", "http security header", "csp analyse", "hsts prüfen", "antwort-header prüfen", "x-frame-options"]
tags: ["sicherheit", "csp", "http", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/security-headers/"
tool_title: "Security-Header- und CSP-Analyse"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Kopieren Sie die Antwort-Header der zu prüfenden Seite: Führen Sie `curl -sI https://example.com` im Terminal aus oder öffnen Sie DevTools → **Netzwerk**, laden Sie neu, wählen Sie die Anfrage der Seite und kopieren Sie die **Antwort-Header**."
  - "Fügen Sie sie in **Antwort-Header oder CSP** ein. Sie können auch nur eine Richtlinie (`default-src 'self'; …`) oder ein `<meta http-equiv=\"Content-Security-Policy\">`-Tag einfügen."
  - "Das Ergebnis erscheint beim Einfügen: eine Note, dann alle Ergebnisse von **Hoch** bis **OK** sortiert, jeweils mit dem betroffenen Header und der nötigen Änderung."
  - "Unter **Content-Security-Policy** steht jede Direktive mit ihren Quellen; riskante Quellen sind rot oder gelb markiert, sichere grün."
  - "Mit **Bericht kopieren** übernehmen Sie die Ergebnisse in ein Ticket oder einen Pull Request. Vergleichen Sie **Schwaches Beispiel** und **Starkes Beispiel**."
faq:
  - q: "Verbindet sich das Tool mit meiner Website?"
    a: "Nein. Es ruft keine URL ab, sondern analysiert nur den eingefügten Text in Ihrem Browser. So landet Ihr Server nicht in fremden Logs, und Sie können auch nicht öffentliche Seiten wie Staging, Intranet oder localhost prüfen."
  - q: "Warum Header einfügen statt eine URL einzugeben?"
    a: "Die CORS-Regeln des Browsers verhindern, dass eine Webseite eine fremde URL liest, außer ein Server erledigt das – und dieser Server sähe jede Website, die Sie testen. Die Ausgabe von `curl -sI` einzufügen geht genauso schnell und bleibt lokal."
  - q: "Was macht eine Content-Security-Policy schwach?"
    a: "Typische Probleme sind `'unsafe-inline'` in script-src (eingeschleuste Inline-Skripte laufen), Schema-Quellen wie `https:` oder `data:` und der Platzhalter `*` (Skripte von fast überall), erlaubte CDNs mit JSONP-Endpunkten oder altem AngularJS sowie fehlendes object-src oder base-uri. Eine Google-Studie zeigte, dass sich die meisten Host-Allowlist-Richtlinien umgehen lassen; Nonces mit 'strict-dynamic' vermeiden das."
  - q: "Was ist eine strikte CSP?"
    a: "Eine Richtlinie, die Skripte über eine zufällige Nonce (oder einen Hash) statt über den Host erlaubt, plus `'strict-dynamic'`, damit vertrauenswürdige Skripte weitere laden dürfen. Google und OWASP empfehlen diesen Ansatz gegen XSS. Das Beispiel unter „So funktioniert es“ ist ein guter Start: Setzen Sie es zuerst als Content-Security-Policy-Report-Only ein und beheben Sie die gemeldeten Verstöße."
  - q: "Wie wird die Note berechnet?"
    a: "Ausgangspunkt sind 100 Punkte; jedes hohe Ergebnis kostet 20, jedes mittlere 10, jedes geringe 4, Hinweise und bestandene Prüfungen nichts. A+ setzt voraus, dass es keine hohen oder mittleren Ergebnisse gibt. Die Note ist eine schnelle Zusammenfassung, keine Zertifizierung: Lesen Sie die Ergebnisse, denn ihre Tragweite hängt von Ihrer Website ab."
  - q: "Brauche ich X-Frame-Options und X-XSS-Protection noch?"
    a: "In aktuellen Browsern ersetzt frame-ancestors aus der CSP den X-Frame-Options-Header, beide zu senden schadet aber nicht und deckt alte Browser ab; das Tool akzeptiert daher beides. X-XSS-Protection ist veraltet: Browser haben den zugehörigen Filter entfernt, daher empfiehlt das Tool, den Header zu entfernen oder 0 zu senden."
  - q: "Welche Cookie-Attribute werden geprüft?"
    a: "Secure (nur über HTTPS), HttpOnly (für JavaScript unsichtbar), SameSite (begrenzt seitenübergreifendes Senden, ein CSRF-Schutz) sowie die Regeln der Namenspräfixe __Host- und __Secure-. Ein Cookie mit SameSite=None ohne Secure wird von Browsern abgelehnt und als hoch eingestuft."
---

## So funktioniert es

### Einfügen, zerlegen, prüfen

Der eingefügte Text wird in Header-Zeilen zerlegt. Statuszeilen wie `HTTP/2 200`, HTTP/2-Pseudo-Header und umbrochene Zeilen werden berücksichtigt; bei einer eingefügten Weiterleitungskette wird nur die letzte Antwort analysiert. Wiederholte Header wie `Set-Cookie` werden einzeln geprüft. Beginnt der Text mit einer CSP-Direktive oder ist er ein CSP-`<meta>`-Tag, wird nur die Richtlinie analysiert.

Anschließend wird jeder Header mit dem aktuellen Browserverhalten und den Empfehlungen von OWASP, MDN und der CSP-Spezifikation abgeglichen. Jedes Ergebnis hat einen Schweregrad, den betroffenen Header und eine konkrete Lösung.

### Die CSP-Prüfungen

Die Richtlinie wird in Direktiven und Quellen zerlegt. Die Analyse ermittelt, welche Direktive tatsächlich für Skripte gilt (`script-src` oder bei Fehlen `default-src`) und für Plugins (`object-src` erbt von `default-src`; `base-uri` und `form-action` erben gar nicht). Sie meldet `'unsafe-inline'` und `'unsafe-eval'`, Platzhalter, Schema-Quellen, Hosts über HTTP, erlaubte Hosts mit JSONP oder beliebigen Bibliotheksversionen, kurze Nonces, `'strict-dynamic'` ohne Nonce sowie Syntaxfehler, die Browser stillschweigend ignorieren: Schlüsselwörter ohne Anführungszeichen (`self` statt `'self'`), fehlende Semikolons, doppelte, unbekannte und veraltete Direktiven.

### Eine strikte Richtlinie als Ausgangspunkt

```text
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'self'
```

Erzeugen Sie für jede Antwort eine neue zufällige Nonce (mindestens 128 Bit) und ergänzen Sie `nonce="{RANDOM}"` an jedem `<script>`-Tag. Senden Sie die Richtlinie zuerst als `Content-Security-Policy-Report-Only`, beheben Sie, was nicht funktioniert, und setzen Sie sie dann durch.

## Anwendungsfälle

- **Vor dem Launch.** Die Header einer Staging-Seite prüfen, die Online-Scanner nicht erreichen.
- **Pull Requests und Audits.** Header vor und nach einer Änderung einfügen und den Bericht ins Review kopieren.
- **CSP verstehen.** Direktive für Direktive sehen, warum eine Quelle riskant ist oder nicht.
- **Notizen aus Pentests und Bug-Bounty.** Eine mitgeschnittene Antwort in eine Liste von Header-Befunden mit Lösungen verwandeln.
- **Cookie-Review.** Nach einem Framework-Update prüfen, ob Sitzungscookies weiterhin Secure, HttpOnly und SameSite sind.
