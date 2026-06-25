---
title: "Falhas Cordyceps em CI/CD Ameaçam Mais de 300 Repositórios no GitHub"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "pt"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "Nova fraqueza em fluxos de trabalho CI/CD, codinome Cordyceps, permite que atacantes sequestrem workflows e comprometam cadeias de suprimento open-source em grandes organizações."
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "fluxos de trabalho CI/CD no GitHub"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Nova fraqueza em fluxos de trabalho CI/CD, codinome Cordyceps, permite que atacantes sequestrem workflows e comprometam cadeias de suprimento open-source em grandes organizações.

{{< cyber-report severity="Critical" source="The Hacker News" target="fluxos de trabalho CI/CD no GitHub" >}}

Pesquisadores de cibersegurança da Novee Security identificaram um padrão crítico explorável em fluxos de trabalho CI/CD, apelidado de Cordyceps, que pode permitir que atacantes sequestrem workflows e comprometam cadeias de suprimento open-source. A falha afeta mais de 300 repositórios do GitHub pertencentes a grandes organizações, incluindo Microsoft, Google e Apache.

{{< ad-banner >}}

O padrão Cordyceps permite controle total do atacante sobre os repositórios, potencialmente levando a alterações não autorizadas de código, inserção de backdoors e ataques downstream na cadeia de suprimento. A vulnerabilidade decorre de configurações inseguras de workflow que não isolam ou validam entradas adequadamente.

Organizações que usam GitHub Actions ou plataformas CI/CD similares são instadas a revisar suas definições de workflow em busca do padrão Cordyceps e implementar permissões de privilégio mínimo, sanitização de entrada e isolamento de ambiente para mitigar o risco.

{{< netrunner-insight >}}

Este é um vetor de ataque clássico de cadeia de suprimento. Analistas de SOC devem monitorar execuções anômalas de workflow e mudanças inesperadas em repositórios. Equipes de DevSecOps devem auditar imediatamente as configurações de pipeline CI/CD, focando no tratamento de entradas não confiáveis e no escopo de permissões.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
