---
title: "Botnet NadMesh ataca serviços de IA expostos para roubar credenciais de nuvem"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "pt"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "Um novo botnet baseado em Go, NadMesh, caça plataformas de IA expostas como ComfyUI e Ollama, roubando chaves AWS e tokens Kubernetes. Mais de 3.800 chaves foram roubadas."
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "Serviços de IA expostos (ComfyUI, Ollama, n8n, etc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Um novo botnet baseado em Go, NadMesh, caça plataformas de IA expostas como ComfyUI e Ollama, roubando chaves AWS e tokens Kubernetes. Mais de 3.800 chaves foram roubadas.

{{< cyber-report severity="High" source="The Hacker News" target="Serviços de IA expostos (ComfyUI, Ollama, n8n, etc.)" >}}

Um novo botnet chamado NadMesh, escrito em Go, surgiu no início de julho de 2026, visando serviços de IA expostos para roubar credenciais de nuvem e tokens Kubernetes. O painel de controle do botnet supostamente mostra 3.811 chaves AWS exclusivas coletadas, indicando uma escala operacional significativa. O NadMesh usa um coletor baseado em Shodan para preencher continuamente sua fila de varredura com instâncias vulneráveis de ferramentas de IA populares como ComfyUI, Ollama, n8n, Open WebUI, Langflow e Gradio.

{{< ad-banner >}}

Essas plataformas de IA são frequentemente implantadas rapidamente por equipes de desenvolvimento sem a devida proteção de segurança, deixando-as expostas à internet. O botnet explora essa falta de proteção de firewall para obter acesso e extrair credenciais sensíveis. O foco em serviços de IA sugere uma mudança na segmentação dos atacantes em direção a infraestrutura de nuvem de alto valor e pipelines de aprendizado de máquina.

Organizações que executam essas ferramentas de IA devem auditar imediatamente sua exposição, restringir o acesso à rede e rotacionar quaisquer credenciais que possam ter sido comprometidas. O botnet NadMesh demonstra o crescente cenário de ameaças onde serviços de IA mal configurados se tornam alvos principais para roubo de credenciais e movimento lateral.

{{< netrunner-insight >}}

Para analistas de SOC: priorize a varredura por serviços expostos de ComfyUI, Ollama e similares em seu ambiente. Equipes DevSecOps devem impor segmentação de rede e regras de firewall antes de implantar essas ferramentas. O botnet NadMesh é um lembrete claro de que implantação rápida sem revisão de segurança convida à coleta automatizada de credenciais.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
