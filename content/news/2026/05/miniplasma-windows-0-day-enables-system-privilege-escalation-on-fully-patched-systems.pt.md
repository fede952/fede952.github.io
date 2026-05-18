---
title: "MiniPlasma Windows 0-Day Permite Escalação de Privilégio para SYSTEM em Sistemas Totalmente Atualizados"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "pt"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "O pesquisador de segurança Chaotic Eclipse lança PoC para MiniPlasma, um zero-day no Windows Cloud Files Mini Filter Driver (cldflt.sys) que concede privilégios de SYSTEM em sistemas totalmente atualizados."
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Windows Cloud Files Mini Filter Driver (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

O pesquisador de segurança Chaotic Eclipse lança PoC para MiniPlasma, um zero-day no Windows Cloud Files Mini Filter Driver (cldflt.sys) que concede privilégios de SYSTEM em sistemas totalmente atualizados.

{{< cyber-report severity="High" source="The Hacker News" target="Windows Cloud Files Mini Filter Driver (cldflt.sys)" >}}

Chaotic Eclipse, o pesquisador de segurança por trás das falhas recentemente divulgadas do Windows, YellowKey e GreenPlasma, lançou uma prova de conceito (PoC) para uma falha zero-day de escalação de privilégio no Windows que concede aos atacantes privilégios de SYSTEM em sistemas Windows totalmente atualizados. Apelidada de MiniPlasma, a vulnerabilidade afeta o "cldflt.sys", que se refere ao Windows Cloud Files Mini Filter Driver.

{{< ad-banner >}}

A falha permite que um atacante com acesso limitado de usuário escale privilégios para SYSTEM, potencialmente permitindo o comprometimento total do sistema. Como um zero-day, nenhum patch oficial está disponível atualmente, deixando sistemas totalmente atualizados vulneráveis à exploração se a PoC for armada.

As organizações devem monitorar comportamentos incomuns do driver cldflt.sys e considerar medidas adicionais de hardening, como restringir o acesso ao recurso Cloud Files ou aplicar mitigações temporárias até que um patch seja lançado.

{{< netrunner-insight >}}

Analistas de SOC devem priorizar o monitoramento de tentativas de exploração direcionadas ao cldflt.sys, já que a PoC reduz a barreira para atacantes. Equipes de DevSecOps devem revisar o hardening de suas imagens Windows e considerar desabilitar o Windows Cloud Files Mini Filter Driver se não for necessário, enquanto aguardam uma correção oficial da Microsoft.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
