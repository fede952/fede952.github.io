---
title: "Ataques ao Salesforce se Ampliam à Medida que Icarus Vaza Dados Roubados via Violação da Klue"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "pt"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "Atacantes exploraram tokens OAuth da Klue para acessar instâncias do Salesforce; mais vítimas surgem enquanto Icarus vaza dados roubados."
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "Instâncias do Salesforce via tokens OAuth da Klue"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Atacantes exploraram tokens OAuth da Klue para acessar instâncias do Salesforce; mais vítimas surgem enquanto Icarus vaza dados roubados.

{{< cyber-report severity="High" source="Dark Reading" target="Instâncias do Salesforce via tokens OAuth da Klue" >}}

O escopo dos ataques em andamento contra o Salesforce se expandiu, com atores de ameaças, rastreados como Icarus, vazando dados roubados de múltiplas vítimas. Os atacantes inicialmente violaram o fornecedor de aplicativos Klue e aproveitaram seus tokens OAuth para obter acesso não autorizado aos ambientes Salesforce dos clientes.

{{< ad-banner >}}

De acordo com a Dark Reading, novas vítimas surgiram após a divulgação inicial, indicando que a campanha de ataque é mais ampla do que se entendia anteriormente. O uso de tokens OAuth permitiu que os atacantes contornassem os controles tradicionais de autenticação e acessassem diretamente os dados do Salesforce sem acionar alertas típicos.

Organizações que usam integrações do Salesforce com fornecedores terceiros como a Klue são instadas a auditar as permissões dos tokens OAuth e monitorar padrões de acesso anômalos. O grupo Icarus começou a vazar dados roubados, aumentando a urgência para que as empresas afetadas respondam.

{{< netrunner-insight >}}

Este ataque ressalta o risco de abuso de tokens OAuth em ecossistemas SaaS. Analistas de SOC devem priorizar o monitoramento de chamadas de API incomuns e uso de tokens de aplicativos terceiros integrados. Equipes de DevSecOps devem impor uma gestão rigorosa do ciclo de vida dos tokens e implementar permissões just-in-time para limitar o raio de explosão.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em Dark Reading ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
