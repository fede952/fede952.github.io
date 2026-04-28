---
title: "DeepSeek vs ChatGPT: Das Open-Source-LLM, Das die KI-Branche Aufmischt"
date: 2025-02-02
description: "Tiefgehender Vergleich von DeepSeek-V3 und GPT-4o zu Architektur, Preisen, Benchmarks, Datenschutz und Zensur. Erfahren Sie, warum DeepSeeks Mixture-of-Experts-Modell GPT-4-Leistung zu 1/50 der API-Kosten liefert."
tags: ["DeepSeek", "ChatGPT", "LLM", "OpenSource", "API"]
categories: ["AI", "Guides", "Tech News"]
author: "Federico Sella"
draft: false
---

Im Januar 2025 veröffentlichte ein relativ unbekanntes chinesisches KI-Labor namens **DeepSeek** ein Sprachmodell mit offenen Gewichten, das Schockwellen durch das Silicon Valley sandte — und kurzzeitig fast **600 Milliarden Dollar** von NVIDIAs Marktkapitalisierung in einer einzigen Handelssitzung auslöschte. Das Modell, **DeepSeek-V3**, erreichte oder übertraf GPT-4-Klasse-Benchmarks bei Mathematik, Programmierung und logischem Denken, mit berichteten Trainingskosten von nur **5,6 Millionen Dollar**. Zum Vergleich: OpenAIs GPT-4-Training wird auf über 100 Millionen Dollar geschätzt.

Dieser Leitfaden analysiert, was DeepSeek anders macht, wie es sich mit ChatGPTs GPT-4o bei den relevanten Metriken vergleicht, und welche Auswirkungen dies für Entwickler, Unternehmen und alle hat, die sich um KI-Datenschutz sorgen.

---

## Was ist DeepSeek?

DeepSeek ist ein KI-Forschungslabor, das 2023 von **Liang Wenfeng** gegründet wurde, der auch Mitgründer des chinesischen quantitativen Hedgefonds **High-Flyer** ist. Anders als die meisten KI-Startups, die Risikokapital suchen, finanziert sich DeepSeek weitgehend selbst über High-Flyers Gewinne und den vorhandenen GPU-Cluster. Das Labor hat mehrere Modelle veröffentlicht — DeepSeek-Coder, DeepSeek-Math, DeepSeek-V2 und das Flaggschiff **DeepSeek-V3** — alle unter permissiven Open-Weight-Lizenzen.

Das Unternehmen veröffentlichte auch **DeepSeek-R1**, ein auf logisches Denken spezialisiertes Modell, das direkt mit OpenAIs o1-Serie konkurriert. Für diesen Vergleich konzentrieren wir uns auf das universelle Flaggschiff: **DeepSeek-V3 vs GPT-4o**.

---

## Mixture-of-Experts: Die Architektur Hinter der Effizienz

Das wichtigste technische Detail von DeepSeek-V3 ist seine **Mixture-of-Experts (MoE)**-Architektur. MoE zu verstehen ist der Schlüssel, um zu begreifen, warum DeepSeek so günstig sein kann, ohne schlecht zu sein.

### Wie traditionelle dichte Modelle funktionieren

GPT-4o und die meisten großen Sprachmodelle sind **dichte** Transformer. Jeder Eingabe-Token durchläuft **alle** Parameter des Netzwerks. Hat das Modell 200 Milliarden Parameter, werden alle 200 Milliarden für jeden einzelnen Token aktiviert. Das bedeutet enorme Rechenkosten sowohl beim Training als auch bei der Inferenz.

### Wie MoE funktioniert

Ein Mixture-of-Experts-Modell teilt seine Feed-Forward-Schichten in viele kleinere Teilnetzwerke, sogenannte **Experten**, auf. Ein leichtgewichtiger **Router** (manchmal Gating-Netzwerk genannt) untersucht jeden eingehenden Token und wählt nur eine kleine Teilmenge von Experten aus — typischerweise 8 von 256 — um diesen Token zu verarbeiten. Der Rest bleibt inaktiv.

DeepSeek-V3 hat insgesamt **671 Milliarden Parameter**, aber nur **37 Milliarden sind aktiv** für jeden gegebenen Token. Das bedeutet:

- **Die Trainingskosten sinken drastisch** — nur ein Bruchteil der Gewichte wird pro Schritt aktualisiert.
- **Die Inferenz ist schneller und günstiger** — weniger Rechenaufwand pro Token bedeutet geringere Latenz und niedrigere Hardware-Anforderungen.
- **Die gesamte Wissenskapazität ist riesig** — das Modell kann spezialisiertes Wissen über Hunderte von Experten-Teilnetzwerken speichern und nur die relevanten aktivieren.

Stellen Sie es sich wie ein Krankenhaus vor. Ein dichtes Modell ist ein einzelner Arzt, der jede Fachrichtung kennen muss und jeden Patienten allein behandelt. Ein MoE-Modell ist ein Krankenhaus mit 256 Fachärzten und einer Triage-Schwester — jeder Patient sieht nur die 8 Ärzte, die er tatsächlich braucht.

### DeepSeeks MoE-Innovationen

DeepSeek-V3 führt zwei bemerkenswerte Verbesserungen ein:

1. **Multi-head Latent Attention (MLA):** Komprimiert den Key-Value-Cache und reduziert den Speicherverbrauch bei Long-Context-Inferenz drastisch.
2. **Lastausgleich ohne Hilfsverlust:** Ersetzt den traditionellen zusätzlichen Verlustterm durch eine Bias-basierte Ausgleichsstrategie.

---

## Kostenvergleich: API-Preise

| | **GPT-4o (OpenAI)** | **DeepSeek-V3** |
|---|---|---|
| **Eingabe-Tokens** | $2,50 / 1M Tokens | $0,14 / 1M Tokens |
| **Ausgabe-Tokens** | $10,00 / 1M Tokens | $0,28 / 1M Tokens |
| **Eingabekosten-Verhältnis** | 1x | **~18x günstiger** |
| **Ausgabekosten-Verhältnis** | 1x | **~36x günstiger** |
| **Kontextfenster** | 128K Tokens | 128K Tokens |
| **Offene Gewichte** | Nein | Ja |

Bei einer typischen Arbeitslast von 1 Million Ausgabe-Tokens pro Tag lägen die monatlichen Kosten bei etwa **$300 mit GPT-4o** gegenüber **$8,40 mit DeepSeek-V3**. Über ein Jahr sind das $3.600 gegenüber $100 — ein Unterschied, der für Startups und unabhängige Entwickler enorm ins Gewicht fällt.

Und da DeepSeeks Gewichte offen sind, können Sie das Modell auch auf Ihrer eigenen Infrastruktur **selbst hosten** und nichts für API-Aufrufe zahlen.

---

## Benchmark-Vergleich

| Benchmark | GPT-4o | DeepSeek-V3 |
|---|---|---|
| **MMLU** (Allgemeinwissen) | 87,2 % | 87,1 % |
| **MATH-500** (Wettbewerbsmathematik) | 74,6 % | 90,2 % |
| **HumanEval** (Python-Programmierung) | 90,2 % | 82,6 % |
| **GPQA Diamond** (Experten-QA) | 49,9 % | 59,1 % |
| **Codeforces** (Wettbewerbsprogrammierung) | 23,0 % | 51,6 % |
| **AIME 2024** (Mathematik-Olympiade) | 9,3 % | 39,2 % |
| **SWE-bench Verified** (reale Bugs) | 38,4 % | 42,0 % |

Das Muster ist klar: DeepSeek-V3 dominiert bei **Mathematik- und Denkaufgaben**, während GPT-4o bei bestimmten Programmier-Benchmarks einen leichten Vorsprung hält. Beim Allgemeinwissen (MMLU) sind sie praktisch gleichauf. Bei den schwierigsten Denkaufgaben — AIME, GPQA, Codeforces — zieht DeepSeek deutlich davon.

---

## Datenschutz und Zensur: Der Elefant im Raum

### Datenschutz

DeepSeeks API läuft über Server in **China**. Nach chinesischem Datenschutzrecht können chinesische Unternehmen verpflichtet werden, Daten mit Regierungsbehörden zu teilen. Das bedeutet, dass alle Prompts und Antworten, die über DeepSeeks gehostete API gesendet werden, theoretisch für chinesische Regulierungsbehörden zugänglich sein könnten.

Für persönliche Projekte oder nicht-sensible Arbeitslasten mag dies ein akzeptabler Kompromiss sein. Für Unternehmensanwendungen, die Kundendaten verarbeiten oder DSGVO-, HIPAA- oder SOC-2-Compliance unterliegen — **ist die Nutzung von DeepSeeks gehosteter API ein Risiko, das sorgfältig abgewogen werden muss**.

### Inhaltszensur

DeepSeek-V3 wendet Inhaltsfilter an, die mit der Politik der chinesischen Regierung übereinstimmen. Themen rund um **den Tiananmen-Platz, die Unabhängigkeit Taiwans, Xinjiang und Kritik an der Kommunistischen Partei Chinas** werden typischerweise abgelenkt oder abgelehnt.

Da die Gewichte jedoch **offen** sind, können Sie das Modell beim Selbst-Hosting feinabstimmen oder modifizieren, um diese Einschränkungen zu entfernen. Mehrere Community-Projekte haben bereits unzensierte Varianten veröffentlicht.

### Der Ausweg des Self-Hosting

Das stärkste Argument für DeepSeek ist, dass **offene Gewichte Ihnen Souveränität geben**. Sie müssen DeepSeek als Unternehmen nicht vertrauen — Sie können das Modell auf Ihrer eigenen Hardware, in Ihrer eigenen Jurisdiktion, nach Ihren eigenen Regeln betreiben.

Wenn Sie sich für lokale KI interessieren, lesen Sie unseren Leitfaden zur [Einrichtung lokaler KI mit Ollama](../local-ai-setup-ollama/), der Sie Schritt für Schritt durch die Ausführung von Open-Weight-Modellen auf Ihrem eigenen Rechner mit vollem Datenschutz führt.

---

## Wer Sollte Was Nutzen?

| Szenario | Empfehlung |
|---|---|
| Enterprise mit strenger Compliance (DSGVO, HIPAA) | GPT-4o über OpenAI API (oder DeepSeek selbst hosten) |
| Startup mit Kostenoptimierung | DeepSeek-V3 API |
| Mathematik- oder denkintensive Anwendungen | DeepSeek-V3 oder R1 |
| Universeller Chatbot | Beide — ähnliche Qualität |
| Maximaler Datenschutz und Kontrolle | DeepSeek selbst hosten (offene Gewichte) |
| Multimodale Anforderungen (Vision, Audio) | GPT-4o (ausgereifterer multimodaler Stack) |

---

## Das Große Ganze

DeepSeeks Aufstieg zählt über das Modell selbst hinaus. Er stellt drei Annahmen in Frage, die die KI-Branche dominiert haben:

1. **Man braucht keine $100M+ um ein Frontier-Modell zu trainieren.** DeepSeek-V3s Trainingskosten von $5,6M beweisen, dass architektonische Innovation rohe Rechenausgaben ersetzen kann.

2. **Open Source kann an der Spitze mit Closed Source konkurrieren.** DeepSeek zeigt, dass offene Gewichte und Spitzenleistung sich nicht gegenseitig ausschließen.

3. **US-Exportkontrollen für KI-Chips funktionieren möglicherweise nicht wie beabsichtigt.** DeepSeek trainierte Berichten zufolge auf NVIDIA H800 GPUs und erzielte dennoch erstklassige Ergebnisse.

---

## Fazit

DeepSeek-V3 bietet **GPT-4-Klasse-Leistung zu einem Bruchteil der Kosten**, mit dem zusätzlichen Vorteil offener Gewichte, die Self-Hosting und volle Datensouveränität ermöglichen. Seine Mixture-of-Experts-Architektur ist eine echte technische Innovation, die mehr Leistung pro Dollar bietet als jedes konkurrierende Modell.

Die Kompromisse sind real: chinesische Datenjurisdiktion, eingebaute Zensur und ein weniger ausgereiftes Ökosystem im Vergleich zu OpenAI. Aber für Entwickler, die bereit sind, selbst zu hosten — oder die einfach ein erschwingliches, hochwertiges LLM für nicht-sensible Arbeitslasten benötigen — ist DeepSeek die überzeugendste Option auf dem Markt.

Die KI-Landschaft ist kein Ein-Pferd-Rennen mehr. Und Ihr Geldbeutel wird es Ihnen danken, dass Sie es bemerkt haben.
