---
title: "Campanha Mini Shai-Hulud Compromete Pacotes npm @antv via Conta de Mantenedor"
date: "2026-05-19T10:37:35Z"
original_date: "2026-05-19T04:54:17"
lang: "pt"
translationKey: "mini-shai-hulud-campaign-compromises-antv-npm-packages-via-maintainer-account"
author: "NewsBot (Validated by Federico Sella)"
description: "Atacantes comprometem a conta de mantenedor '@antv' 'atool' para enviar pacotes npm maliciosos, incluindo echarts-for-react com 1,1 milhão de downloads semanais, na onda contínua de ataque à cadeia de suprimentos Mini Shai-Hulud."
original_url: "https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html"
source: "The Hacker News"
severity: "High"
target: "ecossistema npm @antv"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Atacantes comprometem a conta de mantenedor '@antv' 'atool' para enviar pacotes npm maliciosos, incluindo echarts-for-react com 1,1 milhão de downloads semanais, na onda contínua de ataque à cadeia de suprimentos Mini Shai-Hulud.

{{< cyber-report severity="High" source="The Hacker News" target="ecossistema npm @antv" >}}

Pesquisadores de cibersegurança identificaram uma nova campanha de ataque à cadeia de suprimentos de software visando o ecossistema npm @antv. Os atacantes comprometeram a conta de mantenedor npm 'atool' para publicar versões maliciosas de vários pacotes, incluindo echarts-for-react, um wrapper React amplamente usado para Apache ECharts com aproximadamente 1,1 milhão de downloads semanais.

{{< ad-banner >}}

Esta campanha faz parte da onda contínua de ataques Mini Shai-Hulud, que já alvejou outros ecossistemas de código aberto. Os pacotes comprometidos provavelmente contêm código malicioso projetado para exfiltrar dados sensíveis ou estabelecer backdoors em ambientes de desenvolvimento.

Organizações que usam qualquer pacote @antv devem auditar imediatamente suas dependências em busca de sinais de comprometimento, rotacionar credenciais e revisar alterações recentes em seus arquivos de bloqueio. O escopo total dos pacotes afetados e a carga exata permanecem sob investigação.

{{< netrunner-insight >}}

Este ataque ressalta a necessidade crítica de medidas de segurança na cadeia de suprimentos, como verificação de integridade de pacotes, autenticação multifator para contas de mantenedor e varredura automatizada de dependências. Analistas de SOC devem priorizar o monitoramento de tráfego de saída anômalo de pipelines de build, enquanto equipes DevSecOps devem impor controles de acesso rigorosos em contas de publicação de pacotes.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)**
