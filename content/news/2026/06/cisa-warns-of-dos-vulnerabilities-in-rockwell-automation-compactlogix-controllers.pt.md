---
title: "CISA Alerta sobre Vulnerabilidades de DoS em Controladores Rockwell Automation CompactLogix"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiplas vulnerabilidades em controladores Rockwell Automation CompactLogix 5370 podem permitir ataques de negação de serviço. CVE-2025-11694 está entre as falhas."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "Controladores Rockwell Automation CompactLogix 5370"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiplas vulnerabilidades em controladores Rockwell Automation CompactLogix 5370 podem permitir ataques de negação de serviço. CVE-2025-11694 está entre as falhas.

{{< cyber-report severity="High" source="CISA" target="Controladores Rockwell Automation CompactLogix 5370" cve="CVE-2025-11694" cvss="7.5" >}}

A CISA publicou um aviso (ICSA-26-167-04) detalhando vulnerabilidades em controladores Rockwell Automation CompactLogix 5370 (L1, L2, L3). As falhas incluem validação inadequada de valores de verificação de integridade e exposição de informações sensíveis do sistema, o que pode permitir que um atacante cause uma condição de negação de serviço. O aviso afeta versões anteriores à V38.011.

{{< ad-banner >}}

A vulnerabilidade mais notável, CVE-2025-11694, envolve a falta de validação de números de sequência e endereços IP de origem no protocolo CIP. Um atacante pode explorar IDs de conexão expostos visíveis na interface web para realizar ataques de negação de serviço, resultando em uma falha menor. A pontuação CVSS v3 para esta vulnerabilidade é 7.5.

A Rockwell Automation recomenda atualizar para a versão V38.011 para corrigir esses problemas. Os produtos afetados são implantados mundialmente no setor de Manufatura Crítica. As organizações devem priorizar a correção desses controladores para mitigar possíveis interrupções operacionais.

{{< netrunner-insight >}}

Para analistas de SOC, monitore padrões incomuns de tráfego CIP ou tentativas repetidas de conexão direcionadas a controladores CompactLogix. Engenheiros de DevSecOps devem garantir que a interface web não esteja exposta a redes não confiáveis e aplicar a atualização de firmware para V38.011 prontamente. Este é um vetor de DoS direto que pode ser mitigado com segmentação de rede adequada e gerenciamento de patches.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
