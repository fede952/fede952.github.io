---
title: "Vulnerabilidades no Hitachi Energy RTU500 Permitem DoS e Impactam a Disponibilidade"
date: "2026-06-05T10:46:09Z"
original_date: "2026-06-04T12:00:00"
lang: "pt"
translationKey: "hitachi-energy-rtu500-vulnerabilities-allow-dos-impact-availability"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta para múltiplas vulnerabilidades na série Hitachi Energy RTU500, incluindo desreferência de ponteiro nulo e loop infinito, com CVSS 7.8. Versões afetadas listadas."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04"
source: "CISA"
severity: "High"
target: "Firmware CMU da série Hitachi Energy RTU500"
cve: "CVE-2025-69421"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta para múltiplas vulnerabilidades na série Hitachi Energy RTU500, incluindo desreferência de ponteiro nulo e loop infinito, com CVSS 7.8. Versões afetadas listadas.

{{< cyber-report severity="High" source="CISA" target="Firmware CMU da série Hitachi Energy RTU500" cve="CVE-2025-69421" cvss="7.8" >}}

A Hitachi Energy divulgou múltiplas vulnerabilidades que afetam o firmware CMU da série RTU500. As falhas incluem desreferência de ponteiro nulo, estouro de inteiro ou wraparound e loop com condição de saída inalcançável (loop infinito), que podem levar a condições de negação de serviço. A exploração impacta principalmente a disponibilidade do produto, com potenciais efeitos secundários na confidencialidade e integridade.

{{< ad-banner >}}

O aviso, publicado pela CISA (ICSA-26-155-04), lista versões de firmware afetadas de 12.7.1 a 13.8.1. Múltiplos CVEs estão associados, incluindo CVE-2025-69421, CVE-2026-24515, CVE-2026-25210, CVE-2026-32776, CVE-2026-32777, CVE-2026-32778 e CVE-2026-8479. As vulnerabilidades têm uma pontuação base CVSS v3 de 7,8, indicando alta gravidade.

A Hitachi Energy recomenda ação imediata conforme as orientações de remediação do aviso. Dado o contexto de infraestrutura crítica, as organizações que usam versões afetadas do RTU500 devem priorizar a aplicação de patches e implementar segmentação de rede para mitigar o risco de exploração.

{{< netrunner-insight >}}

Essas vulnerabilidades são um lembrete de que dispositivos OT frequentemente ficam atrasados nos ciclos de patches. As equipes de SOC devem monitorar tráfego anômalo para unidades RTU500 e garantir que esses dispositivos estejam isolados de redes não confiáveis. Engenheiros de DevSecOps devem integrar a varredura de firmware nos pipelines de CI/CD para detectar CVEs conhecidos antes da implantação.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04)**
