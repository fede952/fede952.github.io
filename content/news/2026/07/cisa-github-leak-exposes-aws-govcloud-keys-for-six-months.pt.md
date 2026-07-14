---
title: "Vazamento no GitHub da CISA Expõe Chaves do AWS GovCloud por Seis Meses"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "pt"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "Um contratante vazou credenciais internas da CISA, incluindo chaves do AWS GovCloud, no GitHub por seis meses. Especialistas destacam lições críticas para equipes de segurança."
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "Repositório GitHub da CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Um contratante vazou credenciais internas da CISA, incluindo chaves do AWS GovCloud, no GitHub por seis meses. Especialistas destacam lições críticas para equipes de segurança.

{{< cyber-report severity="High" source="Krebs on Security" target="Repositório GitHub da CISA" >}}

A Cybersecurity and Infrastructure Security Agency (CISA) divulgou um vazamento de dados onde um contratante publicou inadvertidamente dezenas de credenciais internas, incluindo chaves do AWS GovCloud, em um repositório público do GitHub. As credenciais permaneceram expostas por quase seis meses antes de o KrebsOnSecurity notificar a agência.

{{< ad-banner >}}

A análise pós-incidente da CISA identificou lacunas em sua resposta inicial, como detecção tardia e falta de varredura automatizada de segredos em repositórios públicos. O incidente ressalta a necessidade de gerenciamento robusto de segredos e monitoramento contínuo de repositórios de código.

Especialistas recomendam a implementação de hooks de pré-commit, varredura regular de segredos e controles de acesso rigorosos para evitar vazamentos semelhantes. O uso de credenciais efêmeras e rotação automatizada também pode mitigar o impacto de chaves expostas.

{{< netrunner-insight >}}

Este incidente é um caso clássico de por que a varredura de segredos deve ser integrada aos pipelines de CI/CD, não apenas após o commit. Analistas de SOC devem priorizar alertas para exposições em repositórios públicos, e equipes de DevSecOps devem impor acesso com privilégios mínimos para contratantes. Automatize a rotação de credenciais e considere o uso de ferramentas como GitLeaks ou TruffleHog para detectar vazamentos precocemente.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em Krebs on Security ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
