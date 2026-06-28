---
title: "Polymarket perde US$ 3 milhões em ataque à cadeia de suprimentos via fornecedor terceirizado"
date: "2026-06-28T09:58:42Z"
original_date: "2026-06-26T18:04:12"
lang: "pt"
translationKey: "polymarket-loses-3m-in-supply-chain-attack-via-third-party-vendor"
author: "NewsBot (Validated by Federico Sella)"
description: "Hackers injetaram um script malicioso no frontend da Polymarket após violar um fornecedor terceirizado, causando perdas de US$ 3 milhões aos clientes. A plataforma reembolsará integralmente as vítimas."
original_url: "https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Usuários do frontend da Polymarket"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Hackers injetaram um script malicioso no frontend da Polymarket após violar um fornecedor terceirizado, causando perdas de US$ 3 milhões aos clientes. A plataforma reembolsará integralmente as vítimas.

{{< cyber-report severity="High" source="BleepingComputer" target="Usuários do frontend da Polymarket" >}}

A Polymarket, plataforma de mercado de previsão descentralizada, divulgou que atacantes comprometeram um fornecedor terceirizado para injetar um script malicioso em seu frontend, resultando em uma perda estimada de US$ 3 milhões para os clientes. O incidente, descrito como um ataque à cadeia de suprimentos, teve como alvo a interface do usuário da plataforma para desviar fundos.

{{< ad-banner >}}

A empresa afirmou que reembolsará integralmente os clientes afetados, embora o número exato de vítimas permaneça não divulgado. A violação ressalta os riscos associados a dependências de terceiros em plataformas DeFi e cripto, onde a integridade do frontend é crítica para a segurança das transações.

Embora nenhum CVE ou pontuação CVSS específica tenha sido fornecida, o vetor de ataque—comprometer um fornecedor para alterar o código do frontend—destaca a necessidade de medidas robustas de segurança na cadeia de suprimentos, incluindo assinatura de código, verificações de integridade e avaliações de risco de fornecedores.

{{< netrunner-insight >}}

Este incidente é um ataque clássico à cadeia de suprimentos visando a integridade do frontend. Analistas de SOC devem monitorar injeções não autorizadas de scripts em aplicações web, especialmente aquelas que dependem de bibliotecas ou CDNs de terceiros. Equipes de DevSecOps devem impor políticas rigorosas de segurança de conteúdo (CSP), verificações de integridade de subrecursos (SRI) e auditorias regulares de fornecedores para mitigar tais riscos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)**
