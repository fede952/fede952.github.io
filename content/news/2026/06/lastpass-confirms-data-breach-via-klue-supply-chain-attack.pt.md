---
title: "LastPass confirma violação de dados via ataque à cadeia de suprimentos da Klue"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "pt"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "A LastPass revelou que atacantes roubaram tokens OAuth de um aplicativo de terceiros, a Klue, para acessar dados de clientes em seu ambiente Salesforce."
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Ambiente Salesforce da LastPass"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A LastPass revelou que atacantes roubaram tokens OAuth de um aplicativo de terceiros, a Klue, para acessar dados de clientes em seu ambiente Salesforce.

{{< cyber-report severity="High" source="BleepingComputer" target="Ambiente Salesforce da LastPass" >}}

A LastPass confirmou que hackers acessaram dados de clientes de seu ambiente Salesforce após roubarem os tokens OAuth da empresa no ataque à cadeia de suprimentos da Klue no início deste mês. A violação, divulgada em 23 de junho de 2026, destaca os riscos de integrações de terceiros e roubo de tokens.

{{< ad-banner >}}

Os atacantes usaram tokens OAuth comprometidos da Klue, um aplicativo de terceiros, para obter acesso não autorizado à instância Salesforce da LastPass. Este ataque à cadeia de suprimentos permitiu que os agentes de ameaças exfiltrassem dados de clientes sem acionar alertas típicos de autenticação.

A LastPass está notificando os clientes afetados e revogou os tokens comprometidos. A empresa também está revisando suas políticas de acesso de terceiros para evitar incidentes semelhantes. Esta violação ressalta a importância de monitorar o uso de tokens OAuth e implementar controles de acesso rigorosos para serviços integrados.

{{< netrunner-insight >}}

Este incidente é um exemplo clássico de risco na cadeia de suprimentos por meio de abuso de token OAuth. Analistas de SOC devem priorizar o monitoramento de uso anômalo de tokens e implementar políticas de expiração de tokens. Equipes de DevSecOps devem aplicar o princípio do menor privilégio para integrações de terceiros e considerar o uso de tokens de curta duração para reduzir o raio de explosão.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
