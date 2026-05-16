---
title: "Falhas no Siemens Teamcenter Comprometem Disponibilidade, Integridade e Confidencialidade"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "pt"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiplas vulnerabilidades no Siemens Teamcenter podem comprometer disponibilidade, integridade e confidencialidade. Atualize para as versões mais recentes imediatamente."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "Siemens Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiplas vulnerabilidades no Siemens Teamcenter podem comprometer disponibilidade, integridade e confidencialidade. Atualize para as versões mais recentes imediatamente.

{{< cyber-report severity="High" source="CISA" target="Siemens Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

O Siemens Teamcenter é afetado por múltiplas vulnerabilidades que podem levar ao comprometimento da disponibilidade, integridade e confidencialidade. As falhas incluem verificação inadequada de condições incomuns ou excepcionais, cross-site scripting e uso de credenciais codificadas. As versões afetadas incluem Teamcenter V2312, V2406, V2412, V2506 e V2512.

{{< ad-banner >}}

CVE-2024-4367 é uma verificação de tipo ausente ao lidar com fontes no PDF.js, permitindo execução arbitrária de JavaScript no contexto do PDF.js. Esta vulnerabilidade afeta Firefox e Thunderbird, mas está listada no aviso da Siemens. A Siemens recomenda atualizar para as versões mais recentes do Teamcenter para mitigar esses riscos.

As vulnerabilidades têm uma pontuação base CVSS v3 de 7,5, indicando alta gravidade. Setores críticos de manufatura são afetados, com implantação mundial. As organizações devem priorizar a correção e revisar sua exposição a essas vulnerabilidades.

{{< netrunner-insight >}}

Analistas de SOC devem inventariar imediatamente todas as instâncias do Teamcenter e priorizar a correção para as versões mais recentes. As equipes DevSecOps devem verificar se os componentes do PDF.js estão atualizados e monitorar tentativas de exploração direcionadas a esses CVEs. Dada a alta pontuação CVSS e o potencial de comprometimento total, trate isso como uma remediação de alta prioridade.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
