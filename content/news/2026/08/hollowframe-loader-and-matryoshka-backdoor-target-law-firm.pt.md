---
title: "Loader HollowFrame e Backdoor Matryoshka Visam Escritório de Advocacia"
date: "2026-08-01T09:01:20Z"
original_date: "2026-07-31T16:39:31"
lang: "pt"
translationKey: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
slug: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
author: "NewsBot (Validated by Federico Sella)"
description: "Novo loader baseado em Go, HollowFrame, e backdoor Matryoshka baseado em Rust, usados em ataque de spear-phishing contra um escritório de advocacia, de acordo com a Blackpoint Cyber."
original_url: "https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html"
source: "The Hacker News"
severity: "High"
target: "Escritório de advocacia"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Novo loader baseado em Go, HollowFrame, e backdoor Matryoshka baseado em Rust, usados em ataque de spear-phishing contra um escritório de advocacia, de acordo com a Blackpoint Cyber.

{{< cyber-report severity="High" source="The Hacker News" target="Escritório de advocacia" >}}

A Blackpoint Cyber descobriu uma nova cadeia de ataque direcionada a um escritório de advocacia, começando com um e-mail de spear-phishing que induz o destinatário a baixar um arquivo criptografado. O arquivo contém um atalho do Windows (arquivo LNK), que, quando executado, inicia um processo de infecção em vários estágios.

{{< ad-banner >}}

O ataque utiliza duas famílias de malware anteriormente não documentadas: HollowFrame, uma estrutura de loader baseada em Go, e Matryoshka, um backdoor baseado em Rust. O loader é responsável por entregar o backdoor, que fornece aos atacantes acesso remoto ao sistema comprometido.

Esta campanha destaca a evolução contínua das ferramentas de malware, com os atacantes adotando linguagens multiplataforma como Go e Rust para evadir a detecção e complicar a análise. O uso de arquivos criptografados e arquivos LNK em spear-phishing é uma tática comum, mas a combinação dessas ferramentas específicas adiciona uma nova camada de sofisticação.

{{< netrunner-insight >}}

Os analistas de SOC devem priorizar o monitoramento de execuções de arquivos LNK e downloads de arquivos a partir de links de e-mail, pois estes são indicadores precoces desta cadeia de ataque. As equipes de DevSecOps devem considerar bloquear ou executar em sandbox a execução de arquivos de arquivos criptografados, e garantir que as soluções de detecção e resposta de endpoint (EDR) estejam ajustadas para detectar binários Go e Rust que exibem comportamento de loader.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)**
