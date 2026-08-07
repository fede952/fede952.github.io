---
title: "KI-Empfehlungsvergiftung: Versteckte Prompt-Injection in Ask-AI-Buttons"
date: "2026-08-07T08:08:58Z"
original_date: "2026-08-06T11:30:00"
lang: "de"
translationKey: "ai-recommendation-poisoning-hidden-prompt-injection-in-ask-ai-buttons"
slug: "ai-recommendation-poisoning-hidden-prompt-injection-in-ask-ai-buttons"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine neue Klasse von Prompt-Injection missbraucht vorausgefüllte Deep Links in KI-Assistenten und verändert stillschweigend das LLM-Gedächtnis, ohne Malware oder Exploits."
original_url: "https://thehackernews.com/2026/08/ai-recommendation-poisoning-how-ask-ai.html"
source: "The Hacker News"
severity: "Medium"
target: "Kommerzielle Websites mit KI-Assistenten"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine neue Klasse von Prompt-Injection missbraucht vorausgefüllte Deep Links in KI-Assistenten und verändert stillschweigend das LLM-Gedächtnis, ohne Malware oder Exploits.

{{< cyber-report severity="Medium" source="The Hacker News" target="Kommerzielle Websites mit KI-Assistenten" >}}

Eine neue Klasse von Prompt-Injection verbreitet sich auf kommerziellen Websites, ohne dass Malware, gestohlene Anmeldedaten oder Zero-Day-Exploits erforderlich sind. Sie missbraucht eine Standardfunktion, die in fast jedem großen KI-Assistenten eingebaut ist: vorausgefüllte Deep Links. Es wurde beobachtet, dass Produktionswebsites versteckte Prompt-Injection-Payloads in 'Ask AI'-Buttons auf Marketing- und Konkurrenzvergleichsseiten einbetten.

{{< ad-banner >}}

Wenn ein Benutzer auf einen solchen Button klickt, löst der vorausgefüllte Deep Link den KI-Assistenten aus, die eingebettete Payload zu verarbeiten, was das Gedächtnis oder Verhalten des LLM stillschweigend verändern kann. Diese Technik, die als 'KI-Empfehlungsvergiftung' bezeichnet wird, stellt ein erhebliches Risiko für Benutzer dar, die sich bei Kauf- oder Entscheidungsfindungen auf KI-generierte Empfehlungen verlassen.

Der Angriffsvektor ist besonders tückisch, weil er vertrauenswürdige Benutzerinteraktionen mit legitimen Websites ausnutzt. Im Gegensatz zu herkömmlichen Prompt-Injection-Angriffen, die direkte Benutzereingaben erfordern, funktioniert diese Methode über die Benutzeroberfläche, was es für Benutzer schwieriger macht, sie zu erkennen. Organisationen, die KI-Assistenten einsetzen, sollten ihre Deep-Link-Verarbeitung überprüfen und Schutzmaßnahmen gegen versteckte Payloads implementieren.

{{< netrunner-insight >}}

Für SOC-Analysten unterstreicht dies die Notwendigkeit, KI-Assistenten-Interaktionen als Teil der Angriffsfläche zu überwachen. DevSecOps-Ingenieure sollten vorausgefüllte Deep Links oder Prompts, die aus externen Inhalten stammen, validieren und bereinigen. Behandeln Sie KI-Assistenten als nicht vertrauenswürdige Eingabekanäle und wenden Sie eine strenge Whitelist für Prompt-Quellen an.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/ai-recommendation-poisoning-how-ask-ai.html)**
