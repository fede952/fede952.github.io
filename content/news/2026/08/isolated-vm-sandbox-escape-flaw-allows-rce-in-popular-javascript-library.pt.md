---
title: "Falha de Escape de Sandbox Isolated-vm Permite RCE em Biblioteca JavaScript Popular"
date: "2026-08-21T07:37:09Z"
original_date: "2026-08-20T13:48:24"
lang: "pt"
translationKey: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
slug: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
author: "NewsBot (Validated by Federico Sella)"
description: "Falha crítica no isolated-vm permite que JavaScript em sandbox escape para o host, possibilitando execução remota de código. Todas as versões até 7.0.0 são afetadas."
original_url: "https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html"
source: "The Hacker News"
severity: "Critical"
target: "biblioteca de sandbox JavaScript isolated-vm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Falha crítica no isolated-vm permite que JavaScript em sandbox escape para o host, possibilitando execução remota de código. Todas as versões até 7.0.0 são afetadas.

{{< cyber-report severity="Critical" source="The Hacker News" target="biblioteca de sandbox JavaScript isolated-vm" >}}

Uma vulnerabilidade crítica de segurança foi divulgada no isolated-vm, uma biblioteca de sandbox JavaScript de código aberto amplamente utilizada, com mais de 2.900 estrelas no GitHub e 190 forks. A falha, rastreada como GHSA-864f-rcv7-6rh4, permite que atacantes escapem do ambiente de sandbox e potencialmente executem código arbitrário no sistema host. Todas as versões da biblioteca até e incluindo 7.0.0 são afetadas.

{{< ad-banner >}}

A vulnerabilidade é particularmente preocupante porque o isolated-vm é projetado para fornecer um limite seguro para executar código JavaScript não confiável. Um escape de sandbox bem-sucedido pode comprometer o aplicativo host e a infraestrutura subjacente. Embora nenhum identificador CVE tenha sido atribuído ainda, o aviso destaca a necessidade de atenção imediata dos desenvolvedores que usam esta biblioteca.

Organizações que dependem do isolated-vm devem monitorar patches e considerar controles de mitigação, como restringir a execução de código não confiável ou aplicar camadas adicionais de isolamento. A falta de um CVE neste momento não diminui a gravidade, pois exploits de prova de conceito podem já estar circulando na comunidade de segurança.

{{< netrunner-insight >}}

Este escape de sandbox é um lembrete claro de que mesmo ferramentas de isolamento projetadas especificamente podem ter falhas críticas. Os analistas de SOC devem inventariar quaisquer aplicações que usam isolated-vm e priorizar a aplicação de patches assim que uma correção estiver disponível. As equipes de DevSecOps também devem revisar suas estratégias de sandbox e considerar defesa em profundidade, como executar sandboxes em contêineres ou VMs separados para limitar o raio de explosão.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html)**
