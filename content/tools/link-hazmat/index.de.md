---
title: "Ist dieser Link sicher? Phishing-Link-Check"
description: "Verdächtigen Link einfügen und die Phishing-Tricks in seiner Struktur sehen: IP-Hosts, @-Logins, Punycode-Doubletten, riskante TLDs – ohne ihn zu öffnen."
intro: "**LinkHazmat** zerlegt eine URL, *ohne sie aufzurufen*, und markiert die strukturellen Tricks, auf die Phishing-Links setzen: IP-Adressen als Host, versteckte `@`-Logins, Punycode-Doubletten, riskante TLDs, Markennamen in Subdomains und Redirect-Parameter. Danach führen Sie Links direkt zu tiefergehenden Reputationsscannern."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["ist dieser link sicher", "link überprüfen", "phishing link check", "verdächtiger link", "url scanner", "link auf sicherheit prüfen", "phishing url erkennen", "link checker"]
tags: ["sicherheit", "phishing", "url-scanner", "tool"]
app_category: "SecurityApplication"
tool_partial: "link-hazmat"
howto:
  - "Kopieren Sie den verdächtigen Link, *ohne ihn zu öffnen*: lange drücken oder Rechtsklick und „Link-Adresse kopieren“ wählen."
  - "Fügen Sie ihn in das Feld ein und klicken Sie auf **INITIATE SCAN** (oder Enter). Fehlt `http://`, wird es automatisch ergänzt."
  - "Lesen Sie das Urteil: **LOW RISK**, **SUSPICIOUS** oder **HIGH RISK**, mit jedem gefundenen Trick unter *Tricks detected*."
  - "Prüfen Sie Protokoll, echte Domain und Endung (TLD), auf die der Link tatsächlich zeigt – die echte Domain unterscheidet sich oft deutlich vom angezeigten Linktext."
  - "Für eine zweite Meinung nutzen Sie die Knöpfe **VirusTotal**, **Google Transparency** oder **Urlscan.io**, die diese Dienste mit dem Link vorbefüllt öffnen."
faq:
  - q: "Wie erkenne ich vor dem Klick, ob ein Link sicher ist?"
    a: "Achten Sie auf die echte Domain, den Teil direkt vor dem ersten einfachen `/`. In `https://paypal.com.secure-login.xyz/…` lautet die Domain `secure-login.xyz`, nicht PayPal. Seien Sie misstrauisch bei IP-Adressen statt Namen, einem `@` in der Adresse, ungewöhnlichen Endungen, vielen Bindestrichen und jeder Seite, die nach einer E-Mail oder SMS einen Login verlangt."
  - q: "Ruft LinkHazmat den Link auf?"
    a: "Nein. Die URL wird nur als Text mit dem `URL`-Parser des Browsers zerlegt; es wird nichts geladen, eine bösartige Seite kann also weder laden noch etwas ausführen. Ein Dritter sieht den Link nur, wenn Sie einen der externen Scanner-Knöpfe drücken."
  - q: "Kann ein LOW-RISK-Link trotzdem gefährlich sein?"
    a: "Ja. Es ist eine Strukturprüfung: Sie erkennt die Tricks, mit denen ein Link legitim *wirkt*, nicht, ob die Seite hinter einer normal aussehenden Domain bösartig ist. Eine frisch registrierte Domain mit sauberer Struktur schneidet gut ab. Im Zweifel die Reputationsscanner nutzen oder die Seite über eine selbst eingetippte Adresse aufrufen."
  - q: "Was ist ein Punycode- oder Homograph-Angriff?"
    a: "Domains können nichtlateinische Buchstaben enthalten, die in einer ASCII-Form mit dem Präfix `xn--` gespeichert werden. Angreifer registrieren Doubletten wie `аpple.com` mit kyrillischem а, das fast wie das Original aussieht. LinkHazmat wandelt den Host in seine ASCII-Form um, sodass jedes `xn--`-Label sichtbar und markiert wird."
  - q: "Warum ist ein @ in einer URL verdächtig?"
    a: "Alles vor einem `@` im Authority-Teil einer URL gilt als Benutzername, nicht als Host. `https://www.bank.com@evil.example/` führt in Wahrheit zu `evil.example`. Seriöse Links nutzen das praktisch nie, deshalb gibt das Tool dafür zwei Punkte."
  - q: "Welche TLDs werden markiert?"
    a: "`.xyz`, `.top`, `.gq`, `.zip`, `.mov`, `.tk`, `.ml`, `.ga`, `.cf`, `.buzz`, `.icu` und `.cam`: günstige oder kostenlose Endungen, die in Missbrauchsberichten überproportional auftauchen. Viele seriöse Seiten nutzen sie auch, daher gibt es nur einen Punkt."
---

## So funktioniert es

Die Eingabe wird mit dem Standard-Konstruktor `URL` des Browsers zerlegt (mit vorangestelltem `http://`, falls kein Schema angegeben ist). So erhält man Protokoll, Hostname in ASCII-Form und Query-String genau so, wie ein Browser sie interpretieren würde – entscheidend, weil Phishing von der Lücke zwischen dem *Aussehen* einer URL und ihrem tatsächlichen *Ziel* lebt.

Jede Prüfung addiert Punkte zu einem Risikowert:

| Prüfung | Wonach gesucht wird | Punkte |
|---|---|---|
| Unverschlüsselt | `http:` statt `https:` | +1 |
| IP-Host | ein Hostname wie `185.12.4.9` statt einer Domain | +2 |
| Versteckter Login | ein `@` irgendwo in der Eingabe | +2 |
| Riskante TLD | eine von 12 häufig missbrauchten Endungen | +1 |
| Lange Domain | Hostname über 50 Zeichen | +1 |
| Tiefe Verschachtelung | mehr als 4 Labels, z. B. `a.b.c.d.com` | +1 |
| Punycode | ein Label mit Präfix `xn--` (internationalisierte Doublette) | +2 |
| Viele Bindestriche | 3 oder mehr Bindestriche im Hostnamen | +1 |
| Redirect-Parameter | `redirect=`, `url=`, `goto=`, `next=`, `redir=` oder `link=` in der Query | +1 |
| Marke in der Subdomain | paypal, apple, google, microsoft, amazon, netflix, bank, secure, login, verify oder account *links* der registrierbaren Domain | +2 |

Ein Wert von **0** ist *LOW RISK*, **1–2** *SUSPICIOUS*, **3 oder mehr** *HIGH RISK*. Die Markenprüfung betrachtet nur Subdomain-Labels: `www.paypal.com` besteht, `paypal.com.account-check.xyz` (registrierbare Domain `account-check.xyz`) wird markiert. Als registrierbare Domain gelten näherungsweise die letzten beiden Labels; mehrteilige Endungen wie `.co.uk` werden daher um eine Ebene zu niedrig gezählt.

Die Deep-Scan-Knöpfe bauen Links zur Suche von VirusTotal, zum Safe-Browsing-Status von Google und zur Suche von urlscan.io, in denen Ihre Domain oder URL kodiert ist. Sie öffnen sich erst in einem neuen Tab, wenn Sie klicken.

## Anwendungsfälle

- **Einen Link aus E-Mail oder SMS prüfen**, der vorgibt, von Ihrer Bank, einem Paketdienst oder Streaminganbieter zu stammen, bevor Sie ihn antippen.
- **Helpdesk und SOC.** Geben Sie einem Kollegen eine schnelle Strukturanalyse eines gemeldeten Links und wechseln Sie dann zu den Reputationsscannern.
- **Security-Awareness-Schulungen.** Fügen Sie echte Phishing-Beispiele ein und zeigen Sie, welche Tricks jedes nutzt.
- **Links aus QR-Codes.** QR-Code mit der Kamera auslesen, ohne ihn zu öffnen, und die URL zuerst hier einfügen.
- **Eigene Links prüfen.** Stellen Sie sicher, dass Marketing-Links mit Tracking- oder Redirect-Parametern vorsichtigen Nutzern nicht wie Phishing vorkommen.
