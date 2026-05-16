---
title: "Falhas de Parsing em PAR do Siemens Solid Edge Permitem Execução de Código"
date: "2026-05-16T08:48:36Z"
original_date: "2026-05-14T12:00:00"
lang: "pt"
translationKey: "siemens-solid-edge-par-parsing-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Duas vulnerabilidades de parsing de arquivos no Siemens Solid Edge SE2026 permitem que atacantes executem código arbitrário por meio de arquivos PAR especialmente criados. Atualize para V226.0 Update 5."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03"
source: "CISA"
severity: "High"
target: "Siemens Solid Edge SE2026"
cve: "CVE-2026-44411"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Duas vulnerabilidades de parsing de arquivos no Siemens Solid Edge SE2026 permitem que atacantes executem código arbitrário por meio de arquivos PAR especialmente criados. Atualize para V226.0 Update 5.

{{< cyber-report severity="High" source="CISA" target="Siemens Solid Edge SE2026" cve="CVE-2026-44411" cvss="7.8" >}}

O Siemens Solid Edge SE2026 anterior ao Update 5 é afetado por duas vulnerabilidades de parsing de arquivos que podem ser acionadas quando o aplicativo lê arquivos PAR especialmente criados. As falhas incluem um acesso a ponteiro não inicializado (CVE-2026-44411) e um estouro de buffer baseado em pilha (CVE-2026-44412), ambos podendo permitir que um atacante cause a parada do aplicativo ou execute código arbitrário no contexto do processo atual.

{{< ad-banner >}}

As vulnerabilidades possuem uma pontuação base CVSS v3.1 de 7,8 (Alta) com o vetor AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, indicando acesso local, baixa complexidade, nenhum privilégio necessário, interação do usuário necessária e alto impacto na confidencialidade, integridade e disponibilidade. A Siemens lançou a versão V226.0 Update 5 para corrigir esses problemas e recomenda que os usuários atualizem imediatamente.

Dado o setor de manufatura crítica implantado mundialmente, as organizações que usam o Solid Edge devem priorizar a aplicação de patches. As vulnerabilidades exigem interação do usuário (abrir um arquivo PAR malicioso), portanto, o treinamento de conscientização do usuário também é recomendado como um controle compensatório.

{{< netrunner-insight >}}

Para analistas de SOC, monitore o manuseio incomum de arquivos PAR ou travamentos em processos do Solid Edge. Engenheiros de DevSecOps devem aplicar lista de permissões de aplicativos e restringir tipos de arquivo para reduzir a superfície de ataque. Como são vulnerabilidades locais e dependentes de interação do usuário, simulações de phishing e regras de detecção de endpoint para aberturas suspeitas de arquivos são mitigações essenciais.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03)**
