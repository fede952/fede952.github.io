---
title: "CISA Alerta sobre Bypass Crítico de Autenticação no Rockwell FactoryTalk Analytics PavilionX"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre CVE-2025-14272 que afeta Rockwell Automation FactoryTalk Analytics PavilionX <7.01, permitindo operações privilegiadas não autorizadas em ambientes de manufatura crítica."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre CVE-2025-14272 que afeta Rockwell Automation FactoryTalk Analytics PavilionX <7.01, permitindo operações privilegiadas não autorizadas em ambientes de manufatura crítica.

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

A CISA publicou um aviso (ICSA-26-167-01) sobre uma vulnerabilidade de falta de autorização no Rockwell Automation FactoryTalk Analytics PavilionX. A falha, rastreada como CVE-2025-14272, afeta versões anteriores a 7.01 e permite que um invasor não autorizado execute operações privilegiadas, como gerenciamento de usuários e funções.

{{< ad-banner >}}

A vulnerabilidade decorre da aplicação inadequada de autorização em endpoints de API. A exploração bem-sucedida pode levar ao controle administrativo total do sistema afetado. A Rockwell Automation lançou a versão 7.01 para corrigir o problema, e os usuários são instados a atualizar imediatamente.

Devido à implantação deste produto em setores críticos de manufatura em todo o mundo, o risco de interrupção operacional ou comprometimento de dados é significativo. As organizações devem priorizar a aplicação de patches e revisar os controles de acesso para mitigar possíveis explorações.

{{< netrunner-insight >}}

Este é um bypass de autorização clássico que deve ser tratado como um patch de alta prioridade. Os analistas do SOC devem monitorar chamadas de API anômalas ou escalonamentos de privilégios em ambientes PavilionX. As equipes de DevSecOps devem garantir que a versão 7.01 seja implantada e que a segmentação de rede limite a exposição desses endpoints.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
