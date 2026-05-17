---
title: "CISA Alerta sobre Falha no Siemens Opcenter RDnL via ActiveMQ Artemis com Autenticação Ausente"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "O Siemens Opcenter RDnL é afetado pelo CVE-2026-27446, uma vulnerabilidade de autenticação ausente no ActiveMQ Artemis que permite que atacantes adjacentes não autenticados injetem ou exfiltrem mensagens."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

O Siemens Opcenter RDnL é afetado pelo CVE-2026-27446, uma vulnerabilidade de autenticação ausente no ActiveMQ Artemis que permite que atacantes adjacentes não autenticados injetem ou exfiltrem mensagens.

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

A CISA publicou um aviso (ICSA-26-134-09) detalhando uma vulnerabilidade de autenticação ausente para função crítica no Apache ActiveMQ Artemis, afetando o Siemens Opcenter RDnL. A falha, rastreada como CVE-2026-27446 com pontuação CVSS v3 de 7.1, permite que um atacante não autenticado na rede adjacente force um broker alvo a estabelecer uma conexão de federação Core de saída para um broker malicioso. Isso pode levar à injeção de mensagens em qualquer fila ou à exfiltração de mensagens de qualquer fila por meio do broker malicioso.

{{< ad-banner >}}

A vulnerabilidade afeta todas as versões do Siemens Opcenter RDnL. Embora o impacto na integridade seja considerado baixo devido à funcionalidade de atualização automática ausente e à ausência de informações confidenciais nas mensagens, o impacto na disponibilidade e o potencial de manipulação de mensagens permanecem significativos. O ActiveMQ Artemis lançou uma correção, e a Siemens recomenda atualizar para a versão mais recente imediatamente.

Dado o uso no setor de manufatura crítica em todo o mundo, as organizações que utilizam o Opcenter RDnL devem priorizar a aplicação de patches. O vetor de ataque de rede adjacente reduz a exposição imediata, mas ainda representa um risco em ambientes segmentados. As equipes de defesa devem monitorar conexões de federação Core incomuns e atividade de broker malicioso.

{{< netrunner-insight >}}

Para analistas de SOC, monitore conexões de federação Core de saída inesperadas de brokers ActiveMQ Artemis, pois este é o principal indicador de exploração. As equipes de DevSecOps devem atualizar imediatamente para a versão mais recente do ActiveMQ Artemis e restringir o acesso ao protocolo Core apenas a redes confiáveis. Esta falha ressalta o risco de autenticação ausente em componentes de middleware, mesmo quando o impacto imediato parece baixo.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
