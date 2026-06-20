---
title: "Violação OAuth da Klue: Hackers Icarus Roubam Tokens do Salesforce"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "pt"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue confirma roubo de tokens OAuth afetando integrações com Salesforce; grupo de extorsão Icarus assume responsabilidade e lista de vítimas cresce."
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "plataforma de inteligência de mercado Klue"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue confirma roubo de tokens OAuth afetando integrações com Salesforce; grupo de extorsão Icarus assume responsabilidade e lista de vítimas cresce.

{{< cyber-report severity="High" source="BleepingComputer" target="plataforma de inteligência de mercado Klue" >}}

A plataforma de inteligência de mercado Klue confirmou um incidente de segurança onde atores maliciosos roubaram tokens OAuth usados para conectar-se aos ambientes Salesforce dos clientes. A violação, reivindicada pelo recém-surgido grupo de extorsão 'Icarus', levou a uma lista crescente de vítimas afetadas.

{{< ad-banner >}}

Os tokens OAuth roubados podem permitir que atacantes acessem dados do Salesforce sem exigir autenticação adicional, representando um risco significativo para os clientes da Klue. O incidente destaca os perigos da exposição de tokens OAuth e a necessidade de um gerenciamento robusto do ciclo de vida dos tokens.

À medida que o grupo Icarus reivindica publicamente o ataque, as organizações que usam a integração Salesforce da Klue devem revogar e rotacionar imediatamente quaisquer tokens OAuth associados e monitorar acessos não autorizados. O escopo total da violação permanece sob investigação.

{{< netrunner-insight >}}

Este incidente ressalta a importância crítica de proteger tokens OAuth como credenciais sensíveis. Analistas de SOC devem priorizar o monitoramento de chamadas anômalas à API do Salesforce e impor políticas de expiração de tokens. Equipes de DevSecOps devem implementar escopo rigoroso de tokens e mecanismos de rotação para limitar o raio de explosão em caso de comprometimento.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
