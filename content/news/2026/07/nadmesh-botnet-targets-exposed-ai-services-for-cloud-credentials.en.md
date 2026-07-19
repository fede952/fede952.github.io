---
title: "NadMesh Botnet Targets Exposed AI Services for Cloud Credentials"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "en"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "A new Go-based botnet, NadMesh, hunts exposed AI platforms like ComfyUI and Ollama, stealing AWS keys and Kubernetes tokens. Over 3,800 keys claimed stolen."
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "Exposed AI services (ComfyUI, Ollama, n8n, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A new Go-based botnet, NadMesh, hunts exposed AI platforms like ComfyUI and Ollama, stealing AWS keys and Kubernetes tokens. Over 3,800 keys claimed stolen.

{{< cyber-report severity="High" source="The Hacker News" target="Exposed AI services (ComfyUI, Ollama, n8n, etc.)" >}}

A new botnet named NadMesh, written in Go, emerged in early July 2026, targeting exposed AI services to steal cloud credentials and Kubernetes tokens. The botnet's operator dashboard reportedly shows 3,811 unique AWS keys harvested, indicating a significant operational scale. NadMesh uses a Shodan-based harvester to continuously populate its scan queue with vulnerable instances of popular AI tools such as ComfyUI, Ollama, n8n, Open WebUI, Langflow, and Gradio.

{{< ad-banner >}}

These AI platforms are often deployed rapidly by development teams without proper security hardening, leaving them exposed to the internet. The botnet exploits this lack of firewall protection to gain access and extract sensitive credentials. The focus on AI services suggests a shift in attacker targeting toward high-value cloud infrastructure and machine learning pipelines.

Organizations running these AI tools should immediately audit their exposure, restrict network access, and rotate any credentials that may have been compromised. The NadMesh botnet demonstrates the growing threat landscape where misconfigured AI services become prime targets for credential theft and lateral movement.

{{< netrunner-insight >}}

For SOC analysts: prioritize scanning for exposed ComfyUI, Ollama, and similar AI services in your environment. DevSecOps teams must enforce network segmentation and firewall rules before deploying these tools. The NadMesh botnet is a clear reminder that fast deployment without security review invites automated credential harvesting.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
