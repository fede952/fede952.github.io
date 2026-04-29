---
title: "Vulnerabilidades em Câmeras Milesight Permitem Execução Remota de Código"
date: "2026-04-29T07:21:59Z"
original_date: "2026-04-23T12:00:00"
lang: "pt"
translationKey: "milesight-camera-vulnerabilities-enable-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre vários modelos de câmeras Milesight afetados por vulnerabilidades críticas (CVE-2026-28747, etc.) que podem levar a travamentos do dispositivo ou execução remota de código."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03"
source: "CISA"
severity: "Critical"
target: "Câmeras IP Milesight"
cve: "CVE-2026-28747"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre vários modelos de câmeras Milesight afetados por vulnerabilidades críticas (CVE-2026-28747, etc.) que podem levar a travamentos do dispositivo ou execução remota de código.

{{< cyber-report severity="Critical" source="CISA" target="Câmeras IP Milesight" cve="CVE-2026-28747" >}}

A CISA publicou um aviso (ICSA-26-113-03) detalhando múltiplas vulnerabilidades que afetam uma ampla gama de modelos de câmeras Milesight. As falhas, identificadas como CVE-2026-28747, CVE-2026-27785, CVE-2026-32644, CVE-2026-32649 e CVE-2026-20766, impactam versões de firmware em várias linhas de produtos, incluindo MS-Cxx63-PD, MS-Cxx64-xPD e outras. A exploração bem-sucedida pode permitir que um invasor trave o dispositivo ou obtenha execução remota de código.

{{< ad-banner >}}

Os modelos afetados abrangem várias séries, com versões de firmware até 51.7.0.77-r12, 3x.8.0.3-r11, 63.8.0.4-r3 e outras. Dada a natureza crítica da execução remota de código, essas vulnerabilidades representam um risco significativo para organizações que usam câmeras Milesight em implantações de vigilância ou IoT. A CISA recomenda que os usuários apliquem as correções disponíveis e sigam as orientações do fornecedor para mitigar a exposição.

Embora nenhuma pontuação CVSS ou evidência de exploração ativa seja fornecida no aviso, o potencial de comprometimento do dispositivo e invasão de rede merece atenção imediata. As equipes de segurança devem inventariar os modelos de câmeras afetados, segmentar dispositivos IoT das redes críticas e priorizar as atualizações de firmware.

{{< netrunner-insight >}}

Para analistas de SOC, monitore tráfego anômalo de sub-redes de câmeras e garanta que esses dispositivos estejam isolados. Engenheiros DevSecOps devem agilizar a correção de todas as câmeras Milesight, pois vulnerabilidades de execução remota de código em dispositivos de borda frequentemente se tornam pontos de entrada para movimentação lateral. Trate esses CVEs como críticos até que as correções do fornecedor sejam verificadas.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03)**
