---
title: "Sete Pacotes npm Maliciosos Visam Ecossistema Vite com C2 Baseado em Blockchain"
date: "2026-07-19T09:03:59Z"
original_date: "2026-07-17T18:54:51"
lang: "pt"
translationKey: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
slug: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
author: "NewsBot (Validated by Federico Sella)"
description: "Checkmarx descobre campanha ViteVenom usando infraestrutura C2 baseada em blockchain para entregar um RAT através de sete pacotes npm maliciosos que visam o ferramental frontend Vite."
original_url: "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
source: "The Hacker News"
severity: "High"
target: "Ecossistema de ferramentas frontend Vite"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Checkmarx descobre campanha ViteVenom usando infraestrutura C2 baseada em blockchain para entregar um RAT através de sete pacotes npm maliciosos que visam o ferramental frontend Vite.

{{< cyber-report severity="High" source="The Hacker News" target="Ecossistema de ferramentas frontend Vite" >}}

Pesquisadores de cibersegurança da Checkmarx identificaram um conjunto de sete pacotes npm maliciosos que visam o ecossistema de ferramentas frontend Vite como parte de um ataque à cadeia de suprimentos de software. A campanha, com o codinome ViteVenom, representa uma expansão da operação ChainVeil observada anteriormente, que utilizava uma infraestrutura de comando e controle (C2) baseada em blockchain de quatro camadas sem precedentes, abrangendo a rede Tron.

{{< ad-banner >}}

Os pacotes maliciosos são projetados para entregar um trojan de acesso remoto (RAT) a sistemas comprometidos, permitindo que os atacantes exfiltrem dados e mantenham acesso persistente. O uso de blockchain para comunicações C2 torna a detecção e a derrubada mais desafiadoras, pois a infraestrutura é descentralizada e resistente a técnicas tradicionais de sinkholing.

Organizações que usam Vite em seus pipelines de desenvolvimento devem auditar imediatamente suas dependências em busca dos pacotes maliciosos identificados e implementar verificações rigorosas de integridade dos pacotes. Este incidente destaca a crescente sofisticação dos ataques à cadeia de suprimentos de software, onde os atacantes aproveitam ferramentas de desenvolvimento legítimas e redes descentralizadas para evadir a detecção.

{{< netrunner-insight >}}

Para analistas de SOC, monitorar conexões de saída para nós de blockchain e consultas DNS incomuns pode ajudar a detectar essa técnica de C2. Equipes de DevSecOps devem impor a assinatura de pacotes e usar ferramentas de varredura de dependências para bloquear pacotes maliciosos conhecidos antes que entrem no pipeline de build.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)**
