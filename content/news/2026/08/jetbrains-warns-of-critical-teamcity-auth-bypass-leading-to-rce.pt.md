---
title: "JetBrains alerta sobre bypass crítico de autenticação no TeamCity que leva a RCE"
date: "2026-08-03T10:38:49Z"
original_date: "2026-07-30T22:01:31"
lang: "pt"
translationKey: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
slug: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "A JetBrains alerta sobre uma vulnerabilidade crítica de bypass de autenticação no TeamCity On-Premises que pode permitir execução remota de código. A aplicação imediata de patches é recomendada."
original_url: "https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/"
source: "BleepingComputer"
severity: "Critical"
target: "TeamCity On-Premises"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A JetBrains alerta sobre uma vulnerabilidade crítica de bypass de autenticação no TeamCity On-Premises que pode permitir execução remota de código. A aplicação imediata de patches é recomendada.

{{< cyber-report severity="Critical" source="BleepingComputer" target="TeamCity On-Premises" >}}

A JetBrains emitiu um alerta sobre uma vulnerabilidade crítica de bypass de autenticação que afeta o TeamCity On-Premises. Essa falha pode ser explorada por um atacante não autenticado para obter execução remota de código no servidor afetado, representando um risco severo para organizações que dependem do TeamCity para seus pipelines de build e integração contínua.

{{< ad-banner >}}

A vulnerabilidade é particularmente preocupante porque os servidores TeamCity frequentemente armazenam código-fonte sensível, artefatos de build e credenciais, tornando-os alvos de alto valor para atacantes. A exploração bem-sucedida pode levar ao comprometimento total do servidor e potencialmente da infraestrutura mais ampla se o servidor não estiver devidamente isolado.

Organizações que usam o TeamCity On-Premises devem priorizar a aplicação imediata das atualizações de segurança fornecidas pelo fornecedor. Até que os patches sejam aplicados, é recomendado restringir o acesso de rede ao servidor TeamCity e monitorar qualquer atividade suspeita.

{{< netrunner-insight >}}

Esta é uma vulnerabilidade crítica que deve ser tratada como uma emergência. Os analistas do SOC devem verificar imediatamente se sua organização usa o TeamCity On-Premises e confirmar o status dos patches. Dado o potencial de RCE não autenticado, assuma comprometimento se o servidor estiver exposto e conduza uma revisão forense completa. As equipes de DevSecOps também devem considerar segmentar servidores de build e aplicar controles de acesso rigorosos para mitigar o raio de explosão.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/)**
