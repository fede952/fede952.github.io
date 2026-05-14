---
title: "Prova de conceito de bypass do zero-day do Windows BitLocker divulgada: YellowKey e GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "pt"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "Exploits de prova de conceito para duas vulnerabilidades não corrigidas do Windows—YellowKey (bypass do BitLocker) e GreenPlasma (escalada de privilégio)—foram publicados, representando riscos para unidades criptografadas."
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "Unidades protegidas pelo Windows BitLocker"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Exploits de prova de conceito para duas vulnerabilidades não corrigidas do Windows—YellowKey (bypass do BitLocker) e GreenPlasma (escalada de privilégio)—foram publicados, representando riscos para unidades criptografadas.

{{< cyber-report severity="High" source="BleepingComputer" target="Unidades protegidas pelo Windows BitLocker" >}}

Um pesquisador de cibersegurança divulgou exploits de prova de conceito (PoC) para duas vulnerabilidades não corrigidas do Microsoft Windows, apelidadas de YellowKey e GreenPlasma. YellowKey é um bypass do BitLocker que permite que atacantes acessem dados em unidades protegidas sem autenticação adequada, enquanto GreenPlasma é uma falha de escalada de privilégio que pode permitir que um atacante obtenha permissões elevadas em um sistema comprometido.

{{< ad-banner >}}

A publicação desses PoCs aumenta o risco de exploração, pois atores de ameaças podem agora transformar as técnicas em armas. Organizações que dependem do BitLocker para criptografia completa de disco devem avaliar sua exposição e considerar controles de segurança adicionais, como habilitar proteção TPM+PIN ou usar autenticação de pré-inicialização.

A Microsoft ainda não lançou patches para essas vulnerabilidades, deixando os sistemas expostos até que as correções sejam implementadas. As equipes de segurança devem monitorar padrões incomuns de acesso a unidades criptografadas e aplicar soluções alternativas quando possível, como desabilitar opções de inicialização desnecessárias ou impor políticas de PIN fortes.

{{< netrunner-insight >}}

Para analistas de SOC, priorize o monitoramento de tentativas não autorizadas de acessar unidades protegidas pelo BitLocker e eventos de escalada de privilégio. Engenheiros de DevSecOps devem testar seus ambientes contra os PoCs publicados para identificar configurações vulneráveis e implementar controles compensatórios como Secure Boot e logs de inicialização medidos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
