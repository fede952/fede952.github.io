---
title: "QR-Code Generator kostenlos (PNG)"
description: "QR-Codes für Links oder Text erstellen, Farben und Fehlerkorrektur wählen, druckfertiges PNG laden. Statische Codes, die nie ablaufen, direkt im Browser."
intro: "Geben Sie einen Link oder beliebigen Text ein und erhalten Sie einen **statischen QR-Code**, den Sie als scharfes, druckfertiges PNG herunterladen können. Der Code entsteht in Ihrem Browser, enthält Ihre Daten direkt und läuft nie ab. Die Modi **WLAN** und **Kontakt** erzeugen Codes, die mit einem Scan ein Netzwerk verbinden oder eine Visitenkarte speichern."
date: 2026-02-03
lastmod: 2026-10-25
reviewed: false
keywords: ["qr code generator", "qr code erstellen kostenlos", "qr code generator kostenlos", "qr code für link", "qr code png", "qr code ohne anmeldung", "statischer qr code", "qr code ohne ablaufdatum"]
tags: ["qr-code", "werkzeuge", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/qr-generator/"
tool_title: "QuickLinker QR-Code-Generator"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Fügen Sie eine URL (inklusive `https://`) ein oder tippen Sie beliebigen Text in das Feld. Umlaute, Emoji und nichtlateinische Schriften funktionieren ebenfalls."
  - "Für ein Netzwerk öffnen Sie **WLAN** und geben Name, Passwort und Sicherheit ein; für eine Visitenkarte öffnen Sie **Kontakt** und füllen die gewünschten Felder aus. Der genaue Text, der kodiert wird, steht unter **Kodierter Text**."
  - "Wählen Sie bei Bedarf eine Farbe für **Vordergrund** und **Hintergrund**. Der Vordergrund muss deutlich dunkler sein als der Hintergrund, sonst lesen viele Handykameras den Code nicht."
  - "Wählen Sie die **Fehlerkorrektur**: **M (15%)** ist Standard; nehmen Sie **Q** oder **H**, wenn der Code klein, im Freien oder mit einem Logo darauf gedruckt wird."
  - "Klicken Sie auf **QR Generieren** und prüfen Sie die Vorschau, indem Sie die Handykamera auf den Bildschirm richten."
  - "Mit **.PNG Herunterladen** speichern Sie ein Bild von etwa 1200 px samt vorgeschriebenem weißem Rand – bereit für Druck oder Folien."
faq:
  - q: "Laufen diese QR-Codes ab?"
    a: "Nein. Es sind statische QR-Codes: Link oder Text stecken direkt im Muster. Sie verweisen auf keinen Server von uns, also gibt es nichts abzuschalten, kein Abo und kein Scan-Limit. Die Kehrseite: Das Ziel lässt sich später nicht ändern. Ändert sich die URL, erzeugen Sie einen neuen Code."
  - q: "Ist dieser QR-Code-Generator wirklich kostenlos?"
    a: "Ja, ohne Konto, ohne Wasserzeichen und ohne Begrenzung der Anzahl. Die Seite finanziert sich über Anzeigen rund um das Tool, nicht über gesperrte Funktionen."
  - q: "Was ist der Unterschied zwischen statischen und dynamischen QR-Codes?"
    a: "Ein dynamischer QR-Code enthält einen Kurzlink zum Server des Anbieters, der auf Ihre eigentliche URL weiterleitet. So kann der Anbieter Scans zählen und das Ziel ändern – aber der Code funktioniert nicht mehr, wenn Sie nicht mehr zahlen oder der Dienst eingestellt wird, und jeder Scan läuft über dessen Server. Ein statischer Code wie hier führt direkt zu Ihrer URL."
  - q: "Welche Fehlerkorrektur sollte ich wählen?"
    a: "L stellt rund 7 % beschädigter Module wieder her, M 15 %, Q 25 % und H 30 %. Höhere Stufen machen den Code bei gleichem Inhalt dichter. M passt für Bildschirme und saubere Drucke; Q oder H für kleine Aufkleber, raue Oberflächen oder ein Logo in der Mitte."
  - q: "Wie viel Text passt in einen QR-Code?"
    a: "Der Generator wählt automatisch die kleinste der 40 QR-Versionen, in die der Inhalt passt. Auf Stufe M fasst ein Code der Version 40 etwa 2.300 Byte Text, doch so große Codes lassen sich mit dem Handy schlecht scannen. Für Links gilt: je kürzer, desto besser – eine URL mit 30–60 Zeichen ergibt einen sauberen, gut lesbaren Code."
  - q: "Warum lässt sich mein farbiger QR-Code nicht scannen?"
    a: "Scanner suchen dunkle Module auf hellem Grund mit ausreichendem Kontrast. Invertierte Farben (hell auf dunkel), kontrastarme Paare wie Gelb auf Weiß oder ein Bild hinter dem Code sind die üblichen Ursachen. Schwarz oder eine dunkle Farbe auf Weiß ist die sicherste Wahl."
  - q: "Werden meine Eingaben irgendwohin gesendet?"
    a: "Nein. Der QR-Code wird von einer JavaScript-Bibliothek in dieser Seite berechnet und auf ein Canvas gezeichnet. Es wird nichts hochgeladen – wichtig, wenn Sie ein WLAN-Passwort, eine interne URL oder eine private Notiz kodieren."
  - q: "Wie funktioniert ein WLAN-QR-Code?"
    a: "Er enthält einen kurzen Text im Format `WIFI:`, das die Kameras von Android und iPhone verstehen, etwa `WIFI:T:WPA;S:Zuhause;P:geheim;;`. Beim Scannen bietet das Telefon an, sich ohne Eintippen des Passworts zu verbinden. Sonderzeichen in Name oder Passwort (`\\ ; , : \"`) werden wie vom Format verlangt mit einem Backslash maskiert, sodass auch ein Passwort wie `p;ss:word` funktioniert. Wer den Code scannt, kann das Passwort lesen – drucken Sie ihn also nur dort aus, wo Gäste willkommen sind."
  - q: "Welches Kontaktformat wird verwendet, und was kann es enthalten?"
    a: "Eine vCard 3.0, die Version, die Handykameras am zuverlässigsten importieren: Name, Organisation, Position, Mobilnummer, E-Mail, Website, Adresse und eine Notiz. Leere Felder werden weggelassen, damit der Code klein bleibt. Kommas, Semikolons und Zeilenumbrüche werden nach dem vCard-Standard maskiert. Eine vollständige Karte ergibt einen dichten Code – lassen Sie Unnötiges weg und belassen Sie die Fehlerkorrektur bei L oder M."
---

## So funktioniert es

Das Tool nutzt die Open-Source-Bibliothek **qrcode-generator** von Kazuhiko Arase (v1.4.4, hier selbst gehostet) und zeichnet das Ergebnis auf ein HTML-Canvas.

1. **Kodierung.** Ihr Text wird als **UTF-8** in Bytes umgewandelt und im *Byte-Modus* gespeichert, sodass `ä`, `ß`, `é`, `€` und Emoji beim Scannen genau so erscheinen, wie Sie sie eingegeben haben. (Standardmäßig würde die Bibliothek nur ein Byte pro Zeichen behalten und alles jenseits einfachen Lateins verstümmeln; die Seite stellt sie deshalb ausdrücklich auf UTF-8 um.)
2. **Versionswahl.** Die Bibliothek wählt die kleinste **QR-Version** – von Version 1 (21 × 21 Module) bis Version 40 (177 × 177) –, die Ihre Daten bei der gewählten Fehlerkorrektur aufnehmen kann.
3. **Fehlerkorrektur.** QR-Codes enthalten **Reed-Solomon**-Korrekturcodewörter, damit ein Leser fehlende oder verschmutzte Teile rekonstruieren kann: Stufe **L** stellt ~7 %, **M** ~15 %, **Q** ~25 % und **H** ~30 % der Codewörter wieder her.
4. **Darstellung.** Jedes dunkle Modul wird als Quadrat in der Vordergrundfarbe gezeichnet. Rund um das Symbol lässt das Tool eine **Ruhezone von 4 Modulen** in der Hintergrundfarbe frei – den Rand, den der QR-Standard (ISO/IEC 18004) verlangt. Ohne ihn scheitern Scanner, sobald der Code auf einer farbigen Seite steht.
5. **Export.** Die Vorschau ist etwa 300 px breit. Beim Download wird der Code mit rund **1200 px** neu gezeichnet, wobei jedes Modul eine ganze Zahl an Pixeln breit ist, damit die Kanten scharf bleiben, und als `qrcode.png` gespeichert.

| Inhalt | Typische Länge | Version auf Stufe M | Module |
|---|---|---|---|
| Kurze URL | 25 Zeichen | 2 | 25 × 25 |
| Normale URL mit Pfad | 60 Zeichen | 4 | 33 × 33 |
| Lange URL mit Tracking-Parametern | 150 Zeichen | 8 | 49 × 49 |
| Ein Absatz Text | 500 Zeichen | 17 | 85 × 85 |

Je weniger Module, desto größer ist jedes einzelne im Druck und desto leichter lässt sich der Code aus der Entfernung scannen. Deshalb bringt das Entfernen von Tracking-Parametern aus einer URL oft mehr als eine andere Fehlerkorrekturstufe.

### WLAN- und Kontakt-Codes

Im Modus **WLAN** schreibt das Tool `WIFI:T:<WPA|WEP|nopass>;S:<Netz>;P:<Passwort>;H:true;;` (das Feld `H` nur bei versteckten Netzen); `WPA` deckt WPA, WPA2 und WPA3 Personal ab, denn die genaue Version handelt das Telefon aus. Im Modus **Kontakt** schreibt es eine vCard 3.0 mit CRLF-Zeilenenden. Beide Formate werden getestet, indem das heruntergeladene PNG dekodiert und das Ergebnis Zeichen für Zeichen verglichen wird – auch mit Namen und Passwörtern voller `; , : " \`.

## Anwendungsfälle

- **Druck und Verpackung.** QR-Codes auf Flyern, Visitenkarten, Speisekarten oder Produktetiketten, die Ihre Website, eine Bewertungsseite oder eine Anleitung öffnen. Ein statischer Code funktioniert, solange die URL funktioniert.
- **Präsentationen und Poster.** Das Publikum öffnet Ihre Folien, eine Umfrage oder ein Repository, ohne eine lange Adresse abzutippen.
- **Text offline teilen.** Kodieren Sie eine kurze Notiz, eine Seriennummer oder Kontaktdaten, die ein Handy ohne Netz lesen kann.
- **Eigene Apps testen.** Erzeugen Sie Codes für Deep Links, Staging-URLs oder OAuth-Callback-Tests, ohne interne Adressen in einen Drittdienst einzufügen.
- **Sicherheitsschulungen.** „Quishing“ (QR-Phishing) versteckt bösartige Links hinter Codes. Mit eigenen Codes zeigen Sie Kollegen, wie leicht ein Code überallhin führen kann – und warum man die URL-Vorschau auf dem Handy vor dem Antippen prüfen sollte.
