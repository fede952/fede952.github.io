---
title: "CISA Adiciona Falha de RCE no PTC Windchill ao KEV em Meio a Ataques Ativos de Web Shell"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "pt"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA adiciona uma vulnerabilidade crítica de execução remota de código no PTC Windchill PDMlink e FlexPLM ao seu catálogo de Vulnerabilidades Exploradas Conhecidas devido à exploração ativa."
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink e FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA adiciona uma vulnerabilidade crítica de execução remota de código no PTC Windchill PDMlink e FlexPLM ao seu catálogo de Vulnerabilidades Exploradas Conhecidas devido à exploração ativa.

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink e FlexPLM" kev="true" >}}

A Agência de Segurança Cibernética e Infraestrutura dos EUA (CISA) adicionou uma vulnerabilidade crítica de execução remota de código que afeta o PTC Windchill PDMlink e o PTC FlexPLM ao seu catálogo de Vulnerabilidades Exploradas Conhecidas (KEV). A decisão segue evidências de exploração ativa, com relatos indicando ataques contínuos de web shell direcionados a esses sistemas empresariais de Gerenciamento de Dados de Produto (PDM) e Gerenciamento do Ciclo de Vida do Produto (PLM).

{{< ad-banner >}}

Embora o identificador CVE específico não tenha sido divulgado no anúncio, a vulnerabilidade é descrita como uma falha crítica de RCE que poderia permitir que atacantes executem código arbitrário em sistemas afetados. As organizações que usam esses produtos são instadas a priorizar a aplicação de patches e revisar seus ambientes em busca de sinais de comprometimento, pois a exploração pode levar à tomada total do sistema.

O catálogo KEV da CISA serve como uma diretiva operacional vinculante para agências federais, exigindo remediação dentro de prazos especificados. As organizações do setor privado são fortemente aconselhadas a tratar isso como uma ameaça de alta prioridade e implementar mitigações como segmentação de rede e monitoramento de atividade anômala de web shell.

{{< netrunner-insight >}}

Para analistas de SOC, priorize a caça a indicadores de web shell em servidores Windchill expostos—procure por processos filhos incomuns gerados pelo aplicativo ou conexões de saída para IPs desconhecidos. As equipes de DevSecOps devem aplicar imediatamente os patches disponíveis e considerar a implementação de patches virtuais ou regras de WAF se o patch for adiado. Este é um lembrete de que sistemas PLM, muitas vezes negligenciados no gerenciamento de patches, são alvos atraentes para grupos de ransomware.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
