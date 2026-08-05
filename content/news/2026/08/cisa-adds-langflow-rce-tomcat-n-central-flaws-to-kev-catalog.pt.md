---
title: "CISA Adiciona Falhas Langflow RCE, Tomcat e N-central ao Catálogo KEV"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "pt"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "A CISA sinaliza três vulnerabilidades ativamente exploradas, incluindo Langflow RCE (CVE-2026-9198) com CVSS 9.8, instando à aplicação imediata de patches."
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow, Apache Tomcat, N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A CISA sinaliza três vulnerabilidades ativamente exploradas, incluindo Langflow RCE (CVE-2026-9198) com CVSS 9.8, instando à aplicação imediata de patches.

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow, Apache Tomcat, N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

A Agência de Segurança Cibernética e de Infraestrutura dos EUA (CISA) adicionou três vulnerabilidades ao seu catálogo de Vulnerabilidades Conhecidas Exploradas (KEV), citando evidências de exploração ativa. Entre elas está a CVE-2026-9198, uma falha crítica de injeção de código no Langflow que permite que atacantes não autenticados obtenham execução remota de código completa. A vulnerabilidade possui pontuação CVSS 9.8, indicando risco severo.

{{< ad-banner >}}

As outras duas falhas afetam o Apache Tomcat e o N-central, embora detalhes específicos não sejam fornecidos no resumo. O catálogo KEV da CISA é uma lista priorizada de vulnerabilidades conhecidas por serem exploradas, e agências federais são obrigadas a corrigi-las dentro de prazos especificados. As organizações são instadas a revisar o catálogo e aplicar patches imediatamente.

A inclusão dessas vulnerabilidades ressalta a importância da gestão oportuna de patches e da inteligência de ameaças. As equipes de segurança devem monitorar indicadores de comprometimento relacionados a esses CVEs e garantir que seus ativos não estejam expostos a vetores de ataque conhecidos.

{{< netrunner-insight >}}

Para analistas de SOC, priorize o monitoramento de tentativas de exploração contra Langflow, Tomcat e N-central, pois agora são alvos ativos confirmados. DevSecOps deve acelerar a aplicação de patches, especialmente para instâncias expostas à internet, e considerar a implementação de regras de detecção adicionais para atividades pós-exploração. Dada a pontuação CVSS crítica, trate a CVE-2026-9198 como um risco de primeira linha e valide se não ocorreu acesso não autorizado.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
