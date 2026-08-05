---
title: "Ataque à Cadeia de Suprimentos do QuickFox Entrega Backdoor FDMTP via Instalador Trojanizado"
date: "2026-08-05T09:34:12Z"
original_date: "2026-08-05T05:47:19"
lang: "pt"
translationKey: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
slug: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
author: "NewsBot (Validated by Federico Sella)"
description: "Ataque de longa duração à cadeia de suprimentos do QuickFox VPN trojaniza o instalador para implantar o backdoor FDMTP, visando usuários chineses no exterior desde agosto de 2025."
original_url: "https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html"
source: "The Hacker News"
severity: "High"
target: "Usuários do QuickFox VPN"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ataque de longa duração à cadeia de suprimentos do QuickFox VPN trojaniza o instalador para implantar o backdoor FDMTP, visando usuários chineses no exterior desde agosto de 2025.

{{< cyber-report severity="High" source="The Hacker News" target="Usuários do QuickFox VPN" >}}

A Fortinet FortiGuard Labs divulgou um ataque de longa data à cadeia de suprimentos visando o QuickFox, uma ferramenta de VPN e aceleração de rede popular entre usuários chineses no exterior. O ataque, ativo desde pelo menos agosto de 2025, envolve uma versão trojanizada do instalador do aplicativo para Windows que entrega um backdoor chamado FDMTP.

{{< ad-banner >}}

O instalador trojanizado é distribuído por meio de canais oficiais ou confiáveis, comprometendo a integridade da cadeia de suprimentos de software. Uma vez executado, o FDMTP fornece aos atacantes acesso remoto e controle sobre o sistema da vítima, potencialmente levando a roubo de dados, vigilância ou implantação de malware adicional.

Este incidente destaca o risco crescente de ataques à cadeia de suprimentos em ferramentas de nicho, mas confiáveis, especialmente aquelas que atendem a comunidades específicas. Organizações e indivíduos que usam o QuickFox devem verificar a integridade de suas instalações e monitorar indicadores de comprometimento associados ao FDMTP.

{{< netrunner-insight >}}

Este ataque ressalta a necessidade de verificação robusta da integridade do software, mesmo para ferramentas de fornecedores aparentemente respeitáveis. Analistas de SOC devem procurar por indicadores do FDMTP e monitorar conexões de rede incomuns de clientes VPN. Equipes de DevSecOps devem impor a assinatura de código e a verificação de hash em seus pipelines de implantação de software para mitigar tais riscos na cadeia de suprimentos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html)**
