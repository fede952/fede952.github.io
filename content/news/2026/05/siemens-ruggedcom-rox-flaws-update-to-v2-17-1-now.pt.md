---
title: "Siemens Ruggedcom ROX: Falhas Atualize para v2.17.1 Agora"
date: "2026-05-15T09:41:40Z"
original_date: "2026-05-14T12:00:00"
lang: "pt"
translationKey: "siemens-ruggedcom-rox-flaws-update-to-v2-17-1-now"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre múltiplas vulnerabilidades de terceiros no Siemens Ruggedcom ROX anteriores à v2.17.1. Mais de 30 CVEs listadas, incluindo riscos de execução remota de código. Atualização imediata recomendada."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16"
source: "CISA"
severity: "High"
target: "Dispositivos Siemens Ruggedcom ROX"
cve: "CVE-2019-13103"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre múltiplas vulnerabilidades de terceiros no Siemens Ruggedcom ROX anteriores à v2.17.1. Mais de 30 CVEs listadas, incluindo riscos de execução remota de código. Atualização imediata recomendada.

{{< cyber-report severity="High" source="CISA" target="Dispositivos Siemens Ruggedcom ROX" cve="CVE-2019-13103" >}}

As versões do Siemens Ruggedcom ROX anteriores a 2.17.1 contêm múltiplas vulnerabilidades de terceiros, conforme divulgado no aviso ICSA-26-134-16 da CISA. Os produtos afetados incluem as séries RUGGEDCOM ROX MX5000, MX5000RE e RX1400. A Siemens lançou versões atualizadas para corrigir esses problemas e recomenda fortemente a atualização para a versão mais recente.

{{< ad-banner >}}

O aviso lista mais de 30 CVEs que abrangem de 2019 a 2025, incluindo CVE-2019-13103, CVE-2022-2347 e CVE-2025-0395. Embora pontuações CVSS específicas não sejam fornecidas, a amplitude e a idade das vulnerabilidades sugerem uma superfície de ataque significativa. Muitas dessas CVEs estão associadas a componentes de terceiros e podem levar à execução remota de código, negação de serviço ou divulgação de informações.

Organizações que usam dispositivos Ruggedcom ROX afetados devem priorizar a correção, especialmente se os dispositivos estiverem expostos a redes não confiáveis. Dada a natureza industrial desses produtos, sistemas não corrigidos podem ser aproveitados para movimento lateral ou interrupção de infraestruturas críticas.

{{< netrunner-insight >}}

Este é um caso clássico de dívida técnica acumulada em sistemas embarcados. As equipes de SOC devem inventariar todas as instâncias do Ruggedcom ROX e verificar as versões de firmware. As equipes de DevSecOps devem integrar a varredura automatizada de CVEs em seu CI/CD para dependências de terceiros. A falta de pontuações CVSS é preocupante—assuma o pior cenário e trate-as como críticas até que se prove o contrário.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16)**
