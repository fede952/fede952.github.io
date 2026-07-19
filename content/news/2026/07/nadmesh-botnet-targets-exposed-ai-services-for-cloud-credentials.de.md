---
title: "NadMesh-Botnet zielt auf exponierte KI-Dienste ab, um Cloud-Anmeldedaten zu stehlen"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "de"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "Ein neues Go-basiertes Botnet, NadMesh, jagt exponierte KI-Plattformen wie ComfyUI und Ollama und stiehlt AWS-Schlüssel und Kubernetes-Token. Über 3.800 Schlüssel wurden angeblich gestohlen."
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "Exponierte KI-Dienste (ComfyUI, Ollama, n8n, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ein neues Go-basiertes Botnet, NadMesh, jagt exponierte KI-Plattformen wie ComfyUI und Ollama und stiehlt AWS-Schlüssel und Kubernetes-Token. Über 3.800 Schlüssel wurden angeblich gestohlen.

{{< cyber-report severity="High" source="The Hacker News" target="Exponierte KI-Dienste (ComfyUI, Ollama, n8n, etc.)" >}}

Ein neues Botnet namens NadMesh, geschrieben in Go, tauchte Anfang Juli 2026 auf und zielt auf exponierte KI-Dienste ab, um Cloud-Anmeldedaten und Kubernetes-Token zu stehlen. Das Dashboard des Botnet-Betreibers zeigt angeblich 3.811 eindeutige AWS-Schlüssel, die geerntet wurden, was auf einen erheblichen Betriebsumfang hindeutet. NadMesh verwendet einen Shodan-basierten Harvester, um seine Scan-Warteschlange kontinuierlich mit anfälligen Instanzen beliebter KI-Tools wie ComfyUI, Ollama, n8n, Open WebUI, Langflow und Gradio zu füllen.

{{< ad-banner >}}

Diese KI-Plattformen werden oft von Entwicklungsteams schnell bereitgestellt, ohne angemessene Sicherheitshärtung, sodass sie dem Internet ausgesetzt sind. Das Botnet nutzt diesen Mangel an Firewall-Schutz aus, um Zugang zu erhalten und sensible Anmeldedaten zu extrahieren. Der Fokus auf KI-Dienste deutet auf eine Verschiebung der Angreiferziele hin zu hochwertiger Cloud-Infrastruktur und Machine-Learning-Pipelines hin.

Organisationen, die diese KI-Tools betreiben, sollten sofort ihre Exposition prüfen, den Netzwerkzugriff einschränken und alle Anmeldedaten rotieren, die möglicherweise kompromittiert wurden. Das NadMesh-Botnet zeigt die wachsende Bedrohungslandschaft, in der falsch konfigurierte KI-Dienste zu Hauptzielen für Anmeldedatendiebstahl und laterale Bewegung werden.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie das Scannen nach exponierten ComfyUI-, Ollama- und ähnlichen KI-Diensten in Ihrer Umgebung. DevSecOps-Teams müssen Netzwerksegmentierung und Firewall-Regeln durchsetzen, bevor sie diese Tools bereitstellen. Das NadMesh-Botnet ist eine deutliche Erinnerung daran, dass schnelle Bereitstellung ohne Sicherheitsüberprüfung automatisierte Anmeldedatenernte einlädt.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
