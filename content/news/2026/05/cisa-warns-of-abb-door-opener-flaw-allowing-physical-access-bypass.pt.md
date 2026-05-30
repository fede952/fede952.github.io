---
title: "CISA Alerta sobre Falha em Abridor de Portas da ABB que Permite Bypass de Acesso Físico"
date: "2026-05-30T09:11:24Z"
original_date: "2026-05-28T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-abb-door-opener-flaw-allowing-physical-access-bypass"
author: "NewsBot (Validated by Federico Sella)"
description: "O aviso ICSA-26-148-04 da CISA detalha uma vulnerabilidade de bypass de autenticação (CVE-2025-7705) no Atuador de Abridor de Portas com Fio ABB Busch-Welcome 2, permitindo acesso não autorizado a edifícios."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04"
source: "CISA"
severity: "Medium"
target: "Atuador de Abridor de Portas com Fio ABB Busch-Welcome 2"
cve: "CVE-2025-7705"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

O aviso ICSA-26-148-04 da CISA detalha uma vulnerabilidade de bypass de autenticação (CVE-2025-7705) no Atuador de Abridor de Portas com Fio ABB Busch-Welcome 2, permitindo acesso não autorizado a edifícios.

{{< cyber-report severity="Medium" source="CISA" target="Atuador de Abridor de Portas com Fio ABB Busch-Welcome 2" cve="CVE-2025-7705" cvss="6.8" >}}

A CISA publicou o aviso ICSA-26-148-04 sobre uma vulnerabilidade de bypass de autenticação no Atuador de Abridor de Portas com Fio ABB Busch-Welcome 2, identificada como CVE-2025-7705. A falha decorre de um modo de compatibilidade ativado por padrão, que permite que um invasor obtenha acesso físico não autorizado a edifícios onde o produto afetado está instalado. A vulnerabilidade afeta todas as versões do Atuador de Interruptor 4 DU e do Atuador de Interruptor, porta/luz 4 DU.

{{< ad-banner >}}

A pontuação base CVSS v3 para esta vulnerabilidade é 6,8, indicando gravidade média. A ABB forneceu etapas de remediação que envolvem alternar o interruptor de modo no produto e realizar uma reinicialização para recalibrar o sistema. O produto é implantado mundialmente, principalmente em instalações comerciais, e o fornecedor está sediado na Suíça.

Organizações que usam os sistemas ABB Busch-Welcome afetados devem aplicar imediatamente as mitigações recomendadas. Dadas as implicações de segurança física, esta vulnerabilidade representa um risco significativo para o controle de acesso a edifícios. As equipes de segurança devem verificar se as etapas de recalibração são executadas corretamente e monitorar quaisquer sinais de exploração.

{{< netrunner-insight >}}

Esta vulnerabilidade é um lembrete claro de que dispositivos IoT e de automação predial frequentemente vêm com padrões inseguros. Analistas de SOC devem priorizar a descoberta de ativos para sistemas ABB Busch-Welcome e garantir que a recalibração manual seja aplicada. Equipes DevSecOps devem defender princípios de segurança por design, especialmente para dispositivos que controlam acesso físico.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04)**
