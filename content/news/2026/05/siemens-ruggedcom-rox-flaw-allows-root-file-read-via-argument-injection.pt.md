---
title: "Falha no Siemens Ruggedcom ROX Permite Leitura de Arquivos como Root via Injeção de Argumentos"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "pt"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre CVE-2025-40948 afetando múltiplos dispositivos Ruggedcom ROX. Um atacante remoto autenticado pode ler arquivos arbitrários com privilégios de root. Atualize para a versão 2.17.1 ou posterior."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "Dispositivos Siemens Ruggedcom ROX"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre CVE-2025-40948 afetando múltiplos dispositivos Ruggedcom ROX. Um atacante remoto autenticado pode ler arquivos arbitrários com privilégios de root. Atualize para a versão 2.17.1 ou posterior.

{{< cyber-report severity="Medium" source="CISA" target="Dispositivos Siemens Ruggedcom ROX" cve="CVE-2025-40948" cvss="6.8" >}}

Os dispositivos da série Siemens Ruggedcom ROX são afetados por uma vulnerabilidade de controle de acesso inadequado (CVE-2025-40948) que permite a um atacante remoto autenticado ler arquivos arbitrários com privilégios de root do sistema operacional subjacente. A falha decorre da validação inadequada de entrada na interface JSON-RPC do servidor web, possibilitando injeção de argumentos.

{{< ad-banner >}}

Os seguintes produtos são vulneráveis: RUGGEDCOM ROX MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536 e RX5000, todos executando versões anteriores à 2.17.1. A Siemens lançou atualizações para corrigir o problema e recomenda a aplicação imediata de patches.

Com uma pontuação CVSS v3 de 6,8, esta vulnerabilidade é classificada como gravidade Média. O vetor de ataque é baseado em rede, requer privilégios baixos e nenhuma interação do usuário. Dados os setores de infraestrutura crítica (por exemplo, Manufatura Crítica) onde esses dispositivos são implantados, a exploração pode levar a uma divulgação significativa de informações.

{{< netrunner-insight >}}

Para analistas de SOC: priorize a aplicação de patches nos dispositivos Ruggedcom ROX em seu ambiente, especialmente aqueles expostos a redes não confiáveis. A natureza autenticada do exploit reduz o risco imediato, mas não o elimina—atacantes que comprometem uma conta de baixo privilégio podem escalar para acesso completo a arquivos como root. Equipes de DevSecOps devem revisar o endurecimento do endpoint JSON-RPC e considerar a segmentação de rede para limitar a exposição.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
