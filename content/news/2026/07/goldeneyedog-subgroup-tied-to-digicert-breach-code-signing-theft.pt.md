---
title: "Subgrupo GoldenEyeDog Ligado à Violação da DigiCert e Roubo de Certificados de Assinatura de Código"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "pt"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "Pesquisadores atribuem o incidente de abril de 2026 na DigiCert ao CylindricalCanine, um subgrupo do grupo de cibercrime chinês GoldenEyeDog, conhecido por atingir os setores de jogos de azar e videogames."
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "Infraestrutura de assinatura de código da DigiCert"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Pesquisadores atribuem o incidente de abril de 2026 na DigiCert ao CylindricalCanine, um subgrupo do grupo de cibercrime chinês GoldenEyeDog, conhecido por atingir os setores de jogos de azar e videogames.

{{< cyber-report severity="High" source="The Hacker News" target="Infraestrutura de assinatura de código da DigiCert" >}}

Pesquisadores de cibersegurança atribuíram o incidente de segurança de abril de 2026 na DigiCert a um cluster de atividade de ameaças chamado CylindricalCanine. O grupo é descrito como um subgrupo do GoldenEyeDog (também conhecido como APT-Q-27, Dragon Breath e Miuuti Group), um grupo de cibercrime chinês que historicamente ataca os setores de jogos de azar e videogames.

{{< ad-banner >}}

A violação envolveu o roubo de certificados de assinatura de código, o que poderia permitir que os atores da ameaça assinassem software malicioso com credenciais legítimas, contornando os controles de segurança. A Expel compartilhou detalhes técnicos do evento, destacando a natureza sofisticada da operação.

Organizações que dependem de certificados emitidos pela DigiCert devem revisar seus inventários de certificados e monitorar qualquer uso não autorizado. O incidente ressalta os riscos representados por ataques à cadeia de suprimentos que visam autoridades certificadoras confiáveis.

{{< netrunner-insight >}}

Para analistas de SOC: priorize o monitoramento de anomalias em assinatura de código e uso inesperado de certificados. Equipes de DevSecOps devem impor uma gestão rigorosa do ciclo de vida dos certificados e considerar certificados de curta duração para limitar a exposição a roubos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
