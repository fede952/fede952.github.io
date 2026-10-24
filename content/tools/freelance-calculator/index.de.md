---
title: "Stundensatz-Rechner für Freelancer"
description: "Berechnen Sie Ihren nötigen Stunden- und Tagessatz als Freelancer aus Wunsch-Netto, abrechenbaren Tagen und Stunden, Steuersatz und Kosten. Kostenlos."
intro: "**RateMate** übersetzt das Einkommen, das Ihnen bleiben soll, in den Satz, den Sie verlangen müssen. Geben Sie Wunsch-Nettojahresgehalt, abrechenbare Tage und Stunden, Steuersatz und monatliche Kosten ein und erhalten Sie sofort Stundensatz, Tagessatz und den nötigen Monatsumsatz."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["stundensatz rechner freelancer", "stundensatz berechnen selbstständig", "tagessatz rechner", "was soll ich als freelancer verlangen", "stundensatz freiberufler", "honorar berechnen", "tagessatz berater", "freelancer preise"]
tags: ["freelance", "finanzen", "business", "tool"]
app_category: "FinanceApplication"
tool_file: "/tools/freelance-calculator/"
tool_title: "RateMate Stundensatz-Rechner für Freelancer"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Wählen Sie die Währung ($, € oder £) und geben Sie das **Desired Annual Net Salary** ein: was nach Steuern und Betriebskosten übrig bleiben soll."
  - "Stellen Sie **Billable Days per Year** ein. Voreingestellt sind 220; ziehen Sie Urlaub, Krankheit, Verwaltung und Akquise ehrlich ab."
  - "Stellen Sie **Daily Billable Hours** ein: die Stunden, die Sie wirklich abrechnen können, meist 5–7 statt 8."
  - "Schieben Sie den Regler **Tax Rate** auf Ihre effektive Steuer- und Abgabenquote und tragen Sie die **Monthly Expenses** ein (Software, Ausstattung, Versicherungen, Coworking, Steuerberatung)."
  - "Lesen Sie **Your Hourly Rate**, den **Daily Rate** und den **Monthly Gross**, den Sie fakturieren müssen. Das Ringdiagramm zeigt, wie sich jeder fakturierte Euro auf Einkommen, Steuern und Kosten verteilt."
faq:
  - q: "Wie berechne ich meinen Stundensatz als Freelancer?"
    a: "Gehen Sie vom Einkommen aus, das Sie brauchen – nicht davon, was andere verlangen. Addieren Sie die jährlichen Betriebskosten, rechnen Sie die Summe auf brutto hoch und teilen Sie durch die Stunden, die Sie realistisch abrechnen können. Mit den Standardwerten (60.000 netto, 500 Kosten pro Monat, 25 % Steuern, 220 Tage mit 6 abrechenbaren Stunden) ergibt das (60.000 + 6.000) ÷ 0,75 = 88.000 pro Jahr, 400 pro Tag, rund 67 pro Stunde."
  - q: "Wie viele abrechenbare Tage pro Jahr sind realistisch?"
    a: "Ein Jahr hat etwa 260 Werktage. Ziehen Sie Feiertage (je nach Land und Bundesland 8–14), 20–25 Urlaubstage, einige Krankheitstage sowie Zeit für Akquise, Verwaltung und Weiterbildung ab. Die meisten Freelancer landen zwischen 180 und 220 abrechenbaren Tagen; Neueinsteiger ohne stabile Auftragslage oft darunter."
  - q: "Warum sind abrechenbare Stunden weniger als Arbeitsstunden?"
    a: "E-Mails, Rechnungen, Angebote, nicht abrechenbare Meetings und Kontextwechsel kosten Zeit. Sechs abrechenbare Stunden an einem Achtstundentag sind ein üblicher, nachhaltiger Wert. Wer jeden Tag acht Stunden abrechnet, arbeitet vermutlich zehn."
  - q: "Welchen Steuersatz soll ich eintragen?"
    a: "Ihren *effektiven* Satz: Einkommensteuer plus Sozialabgaben geteilt durch den Bruttoumsatz, nicht den Spitzensteuersatz. Er hängt stark von Land und Situation ab (in Deutschland etwa von Kranken- und Rentenversicherung); für eine erste Schätzung nehmen Sie die Zahlen des Vorjahres oder fragen Ihre Steuerberatung, und probieren Sie einige Werte aus."
  - q: "Behandelt der Rechner Kosten als absetzbar?"
    a: "Nein. Er wendet den Steuersatz auf den gesamten Bruttobetrag samt Kosten an, was einen etwas höheren, vorsichtigeren Satz ergibt. Sind die Kosten voll absetzbar, beträgt das nötige Brutto stattdessen Netto ÷ (1 − Steuersatz) + Kosten: mit den Standardwerten 86.000 statt 88.000, also etwa 65 statt 67 pro Stunde."
  - q: "Stundensatz, Tagessatz oder Projektpreis?"
    a: "Nutzen Sie den Stundensatz als Untergrenze. Viele Freelancer kalkulieren einen Tagessatz (hier angezeigt) oder einen daraus abgeleiteten Festpreis pro Projekt, der Effizienz statt Stunden belohnt. Wie auch immer Sie anbieten: Prüfen Sie, dass es nie unter dem Stundensatz dieses Rechners liegt."
  - q: "Werden meine Finanzdaten gespeichert?"
    a: "Nein. Die Berechnung läuft in Ihrem Browser, nichts wird gespeichert oder gesendet. Seite schließen, und die Zahlen sind weg."
---

## So funktioniert es

RateMate rechnet rückwärts – von dem Geld, das Ihnen bleiben soll.

1. **Jahreskosten** = monatliche Kosten × 12.
2. **Nötiger Jahresumsatz (brutto)** = (Wunsch-Netto + Jahreskosten) ÷ (1 − Steuersatz).
   Der Steuersatz wird als fester Anteil an allem behandelt, was Sie fakturieren; die Formel rechnet also Gehalt und Kosten auf brutto hoch.
3. **Jährliche Steuern** = Brutto − Netto − Kosten.
4. **Tagessatz** = Brutto ÷ abrechenbare Tage.
5. **Stundensatz** = Tagessatz ÷ abrechenbare Stunden pro Tag.
6. **Monatsbrutto** = Brutto ÷ 12, also was Sie im Schnitt pro Monat fakturieren müssen.

Das Ringdiagramm, gezeichnet mit Chart.js, zeigt die drei Anteile des Bruttos: Nettoeinkommen, Steuern und Kosten. Jedes Feld rechnet bei der Eingabe neu – ziehen Sie den Steuerregler (0–60 %) und sehen Sie zu, wie sich der Satz bewegt.

### Rechenbeispiel

| Eingabe | Wert |
|---|---|
| Wunsch-Netto | 60.000 |
| Monatliche Kosten | 500 (6.000 pro Jahr) |
| Steuersatz | 25 % |
| Abrechenbare Tage | 220 |
| Abrechenbare Stunden pro Tag | 6 |

Brutto = 66.000 ÷ 0,75 = **88.000** pro Jahr → **400** pro Tag → **≈ 67** pro Stunde → **≈ 7.333** Monatsumsatz. Von jeden 100 fakturierten sind etwa 68 Einkommen, 25 Steuern und 7 Kosten.

Ändern Sie nur eine Annahme, und Sie sehen, warum Sätze so stark schwanken. Bei 180 abrechenbaren Tagen steigt der Stundensatz auf etwa 81, bei 5 statt 6 abrechenbaren Stunden pro Tag auf 80. Der größte Hebel ist meist nicht der Steuersatz, sondern wie viel Ihrer Zeit Sie tatsächlich abrechnen können.

### Was das Modell nicht abbildet

Der Rechner bleibt bewusst bei einem einzigen effektiven Satz. Er bildet weder progressive Steuertarife noch die Umsatzsteuer ab (die Sie auf Ihren Satz aufschlagen und abführen), keine Altersvorsorge über das hinaus, was Sie ins „Netto“ einrechnen, und keine unbezahlten Lücken zwischen Aufträgen. Planen Sie dafür einen Puffer ein oder erhöhen Sie das Netto.

## Anwendungsfälle

- **Den Schritt in die Selbstständigkeit planen.** Übersetzen Sie Ihr Angestelltengehalt in den nötigen Satz – und sehen Sie sofort, warum Freelancer deutlich mehr verlangen müssen als Gehalt ÷ 2.080 Stunden.
- **Ein Angebot kalkulieren.** Prüfen Sie, ob ein Projektpreis geteilt durch die benötigten Tage über Ihrem Tagessatz bleibt.
- **Sätze erhöhen.** Tragen Sie die echten Kosten und den Steuersatz dieses Jahres ein und prüfen Sie, ob Ihr aktueller Satz sie noch deckt.
- **Angebote vergleichen.** Vergleichen Sie den Tagessatz eines Auftrags fair mit einem Festgehalt.
- **Sabbatical oder Weiterbildung planen.** Reduzieren Sie die abrechenbaren Tage und sehen Sie, wie stark der Satz steigen muss, um das gleiche Einkommen zu halten.
