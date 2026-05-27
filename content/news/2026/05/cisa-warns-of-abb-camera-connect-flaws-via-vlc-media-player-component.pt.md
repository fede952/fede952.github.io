---
title: "CISA Alerta sobre Falhas no ABB Camera Connect via Componente VLC Media Player"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB Ability Camera Connect versões ≤1.5.0.14 incluem um VLC media player 2.2.4 vulnerável com múltiplos bugs de corrupção de memória, incluindo CVE-2024-46461, representando risco crítico."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB Ability Camera Connect versões ≤1.5.0.14 incluem um VLC media player 2.2.4 vulnerável com múltiplos bugs de corrupção de memória, incluindo CVE-2024-46461, representando risco crítico.

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

A CISA publicou um aviso (ICSA-26-146-05) detalhando múltiplas vulnerabilidades no ABB Ability Camera Connect versões 1.5.0.14 e anteriores. As falhas originam-se de um componente de terceiros desatualizado, VLC media player versão 2.2.4, que é empacotado com o pacote de instalação. Uma atualização para a versão 1.5.0.15 resolve o problema substituindo o componente vulnerável.

{{< ad-banner >}}

As vulnerabilidades incluem estouro de buffer baseado em heap, underflow de inteiro, gravação fora dos limites, elemento de caminho de pesquisa não controlado, estouro de inteiro, erro de off-by-one, leitura fora dos limites, double free, restrição inadequada de operações em buffers de memória e use-after-free. Notavelmente, CVE-2024-46461 descreve um estouro de heap no VLC media player 3.0.20 e anteriores por meio de um fluxo MMS maliciosamente criado, levando à negação de serviço.

Com uma pontuação CVSS v3 de 9,8, essas vulnerabilidades são classificadas como Críticas. Os setores de infraestrutura crítica afetados incluem Químico, Instalações Comerciais, Comunicações, Manufatura Crítica, Energia e Sistemas de Transporte. O produto é implantado mundialmente, e a exploração pode permitir que um invasor comprometa o sistema de várias maneiras.

{{< netrunner-insight >}}

Este aviso destaca o risco de vulnerabilidades herdadas de componentes de terceiros. Analistas de SOC devem priorizar a correção do ABB Ability Camera Connect para a versão 1.5.0.15 e monitorar tentativas de exploração direcionadas a falhas do VLC media player. Equipes de DevSecOps devem impor controle rigoroso de versão de componentes e varredura regular de bibliotecas empacotadas.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
