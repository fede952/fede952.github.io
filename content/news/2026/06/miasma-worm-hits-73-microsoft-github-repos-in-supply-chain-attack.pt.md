---
title: "Verme Miasma atinge 73 repositórios do Microsoft GitHub em ataque à cadeia de suprimentos"
date: "2026-06-07T09:57:27Z"
original_date: "2026-06-06T06:58:04"
lang: "pt"
translationKey: "miasma-worm-hits-73-microsoft-github-repos-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Os repositórios do GitHub da Microsoft nas organizações Azure, Azure-Samples, Microsoft e MicrosoftDocs foram comprometidos pelo verme autorreplicante Miasma, impactando 73 repositórios."
original_url: "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
source: "The Hacker News"
severity: "High"
target: "Repositórios do GitHub da Microsoft"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Os repositórios do GitHub da Microsoft nas organizações Azure, Azure-Samples, Microsoft e MicrosoftDocs foram comprometidos pelo verme autorreplicante Miasma, impactando 73 repositórios.

{{< cyber-report severity="High" source="The Hacker News" target="Repositórios do GitHub da Microsoft" >}}

A campanha de ataque autorreplicante à cadeia de suprimentos Miasma expandiu-se para atingir os repositórios do GitHub da Microsoft, comprometendo 73 repositórios em quatro organizações: Azure, Azure-Samples, Microsoft e MicrosoftDocs. O incidente foi relatado pelo OpenSourceMalware, levando o GitHub a desabilitar o acesso aos repositórios afetados para conter a propagação.

{{< ad-banner >}}

Este ataque ressalta a ameaça crescente de malware autorreplicante nas cadeias de suprimentos de software. Ao comprometer repositórios confiáveis, os atacantes podem injetar código malicioso em projetos downstream que dependem dessas fontes, potencialmente afetando uma ampla gama de usuários e organizações.

Embora detalhes técnicos específicos do comprometimento permaneçam não divulgados, o incidente destaca a necessidade de medidas de segurança aprimoradas em pipelines de CI/CD e gerenciamento de repositórios. As organizações devem revisar suas dependências nos repositórios do GitHub da Microsoft e monitorar qualquer atividade anômala.

{{< netrunner-insight >}}

Para analistas de SOC, priorize o monitoramento de commits ou padrões de acesso incomuns em suas próprias organizações do GitHub. Equipes de DevSecOps devem impor regras rigorosas de proteção de branches, exigir commits assinados e implementar varredura automatizada para malware autorreplicante em pipelines de CI/CD. Este incidente é um lembrete claro de que mesmo grandes fornecedores como a Microsoft não estão imunes a ataques à cadeia de suprimentos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)**
