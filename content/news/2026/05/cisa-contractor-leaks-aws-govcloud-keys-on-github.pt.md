---
title: "Contratante da CISA Vaza Chaves do AWS GovCloud no GitHub"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "pt"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "Um contratante da CISA expôs credenciais do AWS GovCloud e detalhes internos de construção em um repositório público do GitHub, marcando um dos vazamentos de dados governamentais mais graves."
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "Contas AWS GovCloud da CISA"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Um contratante da CISA expôs credenciais do AWS GovCloud e detalhes internos de construção em um repositório público do GitHub, marcando um dos vazamentos de dados governamentais mais graves.

{{< cyber-report severity="Critical" source="Krebs on Security" target="Contas AWS GovCloud da CISA" >}}

Até o último fim de semana, um contratante da Cybersecurity & Infrastructure Security Agency (CISA) mantinha um repositório público no GitHub que expunha credenciais de várias contas AWS GovCloud altamente privilegiadas e um grande número de sistemas internos da CISA. Especialistas em segurança afirmaram que o arquivo público incluía documentos detalhando como a CISA constrói, testa e implanta software internamente, e que representa um dos vazamentos de dados governamentais mais flagrantes da história recente.

{{< ad-banner >}}

As credenciais expostas poderiam permitir que um invasor acessasse ambientes governamentais sensíveis na nuvem e sistemas internos, potencialmente levando à exfiltração de dados ou a um comprometimento maior. O incidente ressalta os riscos de segredos codificados em repositórios públicos, mesmo por contratantes governamentais.

{{< netrunner-insight >}}

Este vazamento destaca a necessidade crítica de varredura automatizada de segredos e controles rigorosos de acesso a repositórios. Analistas de SOC devem priorizar o monitoramento de credenciais expostas em repositórios públicos de código, enquanto equipes de DevSecOps devem aplicar políticas de gerenciamento de segredos e rotacionar imediatamente quaisquer chaves potencialmente comprometidas.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em Krebs on Security ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
