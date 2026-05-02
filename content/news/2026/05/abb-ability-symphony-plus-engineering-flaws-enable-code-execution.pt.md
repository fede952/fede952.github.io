---
title: "Falhas no ABB Ability Symphony Plus Engineering Permitem Execução de Código"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "pt"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre vulnerabilidades no ABB Ability Symphony Plus Engineering devido a PostgreSQL desatualizado, permitindo execução arbitrária de código em sistemas afetados."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre vulnerabilidades no ABB Ability Symphony Plus Engineering devido a PostgreSQL desatualizado, permitindo execução arbitrária de código em sistemas afetados.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

A CISA emitiu um aviso (ICSA-26-120-06) detalhando múltiplas vulnerabilidades no ABB Ability Symphony Plus Engineering, decorrentes do uso do PostgreSQL versão 13.11 e anteriores. As falhas incluem estouro de inteiro, injeção de SQL, condição de corrida TOCTOU e erros de descarte de privilégios, que podem permitir que um atacante autenticado execute código arbitrário no sistema.

{{< ad-banner >}}

As versões afetadas vão do Ability Symphony Plus 2.2 ao 2.4 SP2 RU1. As vulnerabilidades são particularmente preocupantes devido à implantação do produto em setores de infraestrutura crítica, como Químico, Manufatura Crítica, Energia e Água e Esgoto em todo o mundo.

A vulnerabilidade mais notável, CVE-2023-5869, possui pontuação CVSS de 8.8 e envolve um estouro de inteiro que pode ser acionado por dados manipulados de um usuário PostgreSQL autenticado. A exploração bem-sucedida pode levar ao comprometimento total do sistema, enfatizando a necessidade de correção imediata.

{{< netrunner-insight >}}

Este aviso ressalta o risco de dependências desatualizadas em ambientes OT. Analistas de SOC devem priorizar a descoberta de ativos para instâncias do ABB Symphony Plus e garantir que o PostgreSQL seja atualizado para além da versão 13.11. Equipes de DevSecOps devem integrar a varredura de dependências nos pipelines de CI/CD para sistemas de controle industrial a fim de detectar tais vulnerabilidades herdadas precocemente.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
