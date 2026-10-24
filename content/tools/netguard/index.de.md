---
title: "Wie ist meine IP? Browser-Datenschutz-Test"
description: "Öffentliche IP, Provider und Standort sehen, lokale IP-Preisgabe per WebRTC prüfen, GPU und Geräte-Fingerprint auslesen – mit Datenschutz-Score."
intro: "**NetGuard** zeigt, was jede Website über Sie erfährt, sobald Sie sich verbinden: Ihre öffentliche IP-Adresse, Ihren Provider und Ihren ungefähren Standort, dazu die Gerätesignale, die Ihr Browser ungefragt preisgibt. Ein Klick, ein Datenschutz-Score und verständliche Erklärungen."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["wie ist meine ip", "meine ip adresse", "ip leak test", "webrtc leak test", "browser datenschutz test", "vpn testen", "was websites über mich wissen", "datenschutz score"]
tags: ["datenschutz", "netzwerk", "vpn", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/netguard/"
tool_title: "NetGuard: Browser-Datenschutz- und IP-Leak-Test"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
howto:
  - "Klicken Sie auf **Run Privacy Scan**. Der Scan dauert etwa vier Sekunden, die meiste Zeit davon für die WebRTC-Prüfung."
  - "Lesen Sie **Network & Location**: öffentliche IP-Adresse, Provider und Stadt, die jeder Webserver beim Verbindungsaufbau sieht – ermittelt über ipwho.is."
  - "Prüfen Sie die Karte **WebRTC**. Grün heißt, der Browser hat keine private Netzwerkadresse preisgegeben; rot listet die geleakten Adressen auf."
  - "Sehen Sie sich die Fingerprint-Karten an (Betriebssystem, Browser, Bildschirm, GPU, Sprache und Zeitzone, Akku). Jede davon kann jede Website ohne Berechtigungsabfrage lesen."
  - "Vergleichen Sie den **Privacy Score** vor und nach einer Änderung – etwa VPN an, Browser gewechselt, WebGL blockiert – und klicken Sie auf **Scan Again**."
faq:
  - q: "Was ist meine IP-Adresse und wer kann sie sehen?"
    a: "Ihre öffentliche IP-Adresse vergibt Ihr Internetanbieter (oder Ihr VPN) für die Verbindung. Jede Website, jeder Werbeserver und jedes CDN, das Sie kontaktieren, sieht sie, denn sie wird gebraucht, um Ihnen die Seite zurückzuschicken. Meist verrät sie Ihren Anbieter und Ihre Stadt oder Region, selten die genaue Straße."
  - q: "Verbirgt ein VPN meine IP in diesem Test?"
    a: "Ja: Die Karten für IP, Provider und Standort zeigen dann die Daten des VPN-Servers statt Ihrer eigenen – genau dafür ist ein VPN da. Der Score selbst weiß allerdings nicht, ob eine Adresse zu einem VPN gehört, und zieht für jede sichtbare IP gleich viele Punkte ab. Vergleichen Sie also die Karten, nicht nur die Zahl."
  - q: "Was ist ein WebRTC-Leak?"
    a: "WebRTC ermöglicht Browsern Peer-to-Peer-Verbindungen für Videoanrufe. Dafür sammelt es „ICE-Kandidaten“, also Netzwerkadressen, unter denen Ihr Gerät erreichbar ist. Ältere Browser gaben auf diesem Weg die private LAN-Adresse des Geräts (etwa 192.168.1.23) an jede Seite weiter. NetGuard prüft genau das; moderne Browser verstecken sie inzwischen hinter einem zufälligen `.local`-Namen."
  - q: "Erkennt NetGuard, ob mein VPN meine echte IP über WebRTC verrät?"
    a: "Nicht vollständig. Die Prüfung läuft ohne STUN-Server: Sie deckt lokale Netzwerkadressen auf, fragt aber keinen externen Server, wie Ihre öffentliche Adresse über WebRTC aussieht. Um genau dieses VPN-Leck zu testen, schalten Sie das VPN ein, öffnen einen speziellen STUN-basierten WebRTC-Test und vergleichen die dort gemeldete öffentliche Adresse mit der IP hier."
  - q: "Warum ist mein GPU-Modell sichtbar?"
    a: "Über die WebGL-Erweiterung `WEBGL_debug_renderer_info` kann eine Seite den genauen Renderer-String der Grafik auslesen, zum Beispiel ein NVIDIA- oder Apple-GPU-Modell. Zusammen mit Bildschirmgröße, Zeitzone und Sprache grenzt das Sie auf eine kleine Gruppe von Geräten ein. Manche Browser liefern einen generischen Wert oder blockieren ihn; NetGuard meldet das als sicher."
  - q: "Speichert oder sendet das Tool meine Daten?"
    a: "Nur eine Anfrage verlässt Ihren Browser: die Abfrage bei ipwho.is, die Ihre öffentliche IP und deren Standort liefert – eine Anfrage, die jede besuchte Website ebenfalls stellen könnte. Alles andere wird lokal ausgelesen und angezeigt, und beim Schließen der Seite wird nichts gespeichert."
---

## So funktioniert es

Der Scan führt nacheinander fünf Prüfungen aus, alle innerhalb der Seite, und verrechnet sie zu einem Score.

**1. Netzwerkidentität.** Der Browser ruft `https://ipwho.is/` auf, eine öffentliche IP-Geolokalisierungs-API. Die Antwort enthält die Adresse, von der die Anfrage kam, den Provider oder die Organisation, der sie gehört, sowie Land, Stadt und ungefähre Koordinaten dieser Adresse. Das sind dieselben Informationen, die jeder Webserver aus Ihrer Verbindung ableiten kann – deshalb ist die Karte als Warnung markiert.

**2. Verbindungsqualität.** Wo die **Network Information API** existiert (Chromium-basierte Browser), meldet `navigator.connection` die geschätzte Bandbreite in Mbit/s, einen effektiven Verbindungstyp wie `4g` und die Paketlaufzeit. Firefox und Safari stellen sie nicht bereit, was die Karte auch anzeigt.

**3. Geräte-Fingerprint.** NetGuard liest die Signale, die Fingerprinting-Skripte am häufigsten sammeln:

- Betriebssystem und Browserversion aus dem `User-Agent`-String, dazu `navigator.platform`;
- Bildschirmauflösung, Pixelverhältnis, Fenstergröße und Farbtiefe;
- **Renderer und Hersteller der GPU** aus einem WebGL-Kontext über die Erweiterung `WEBGL_debug_renderer_info`;
- `navigator.language` und die Zeitzone aus `Intl.DateTimeFormat().resolvedOptions()`;
- Akkustand und Ladezustand per `navigator.getBattery()`, sofern der Browser das noch unterstützt.

**4. WebRTC-Prüfung lokaler Adressen.** Die Seite erzeugt eine `RTCPeerConnection` ohne ICE-Server, öffnet einen Datenkanal und erstellt ein Angebot. Der Browser liefert daraufhin *Host*-ICE-Kandidaten, jeder mit einer Netzwerkadresse. NetGuard sammelt die IPv4-Adressen und ignoriert mDNS-Namen auf `.local`, mit denen moderne Browser die echte LAN-Adresse verbergen. Jede gesammelte Adresse wird als preisgegeben aufgeführt. Nach vier Sekunden endet die Prüfung.

**5. Datenschutz-Score.** Der Score startet bei 100 und verliert für jede gefundene Preisgabe Punkte:

| Signal | Punkte |
|---|---|
| Öffentliche IP und Standort abrufbar | −30 |
| Private IP per WebRTC preisgegeben | −20 |
| Betriebssystem, Browser und Bildschirm lesbar | −10 |
| Genaues GPU-Modell lesbar | −10 |
| Sprache und Zeitzone lesbar | −5 |
| Akkustatus lesbar | −5 |

Chrome auf dem Desktop kommt typischerweise auf 40 (in unserem Test genau das); Browser, die den GPU-String verbergen oder die Battery API nicht implementieren, liegen 5–15 Punkte höher. Die Zahl ist ein Denkanstoß, keine Labormessung – entscheidend sind die einzelnen Karten.

## Anwendungsfälle

- **Prüfen, ob das VPN aktiv ist.** Verbinden und scannen: IP, Provider und Stadt sollten zum VPN-Anbieter gehören, nicht zu Ihrem Anschluss zu Hause.
- **Sehen, was eine Website vor der Registrierung erfährt.** Die Karten zeigen genau das, was ein Analyse- oder Werbeskript beim ersten Seitenaufruf lesen kann.
- **Browser vergleichen.** Scannen Sie in Chrome, Firefox, Brave und Safari – GPU-, Akku- und Verbindungskarte unterscheiden sich deutlich.
- **Geoblocking verstehen.** Hält ein Streamingdienst Sie für jemanden aus dem falschen Land, zeigt die Standortkarte, in welchem Land Ihre IP verortet wird.
- **Grundlagen erklären.** Eine Zwei-Minuten-Demo mit NetGuard erklärt IP-Adressen, Fingerprinting und WebRTC besser als jede Folie. Für eine tiefere Fingerprint-Analyse gibt es GhostPrint.
