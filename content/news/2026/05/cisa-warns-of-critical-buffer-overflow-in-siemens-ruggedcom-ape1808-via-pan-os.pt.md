---
title: "CISA Alerta sobre Estouro de Buffer Crítico no Siemens RUGGEDCOM APE1808 via PAN-OS"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Um estouro de buffer no Palo Alto Networks PAN-OS Captive Portal afeta dispositivos Siemens RUGGEDCOM APE1808. CVE-2026-0300 permite execução remota de código não autenticada com privilégios de root."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "dispositivos Siemens RUGGEDCOM APE1808"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Um estouro de buffer no Palo Alto Networks PAN-OS Captive Portal afeta dispositivos Siemens RUGGEDCOM APE1808. CVE-2026-0300 permite execução remota de código não autenticada com privilégios de root.

{{< cyber-report severity="Critical" source="CISA" target="dispositivos Siemens RUGGEDCOM APE1808" cve="CVE-2026-0300" cvss="10.0" >}}

A CISA publicou um aviso (ICSA-26-139-02) detalhando uma vulnerabilidade crítica de estouro de buffer no serviço User-ID Authentication Portal (Captive Portal) do software PAN-OS da Palo Alto Networks. Essa falha, rastreada como CVE-2026-0300 com pontuação CVSS de 10.0, permite que um invasor não autenticado execute código arbitrário com privilégios de root em firewalls das séries PA e VM enviando pacotes especialmente criados.

{{< ad-banner >}}

A vulnerabilidade afeta dispositivos Siemens RUGGEDCOM APE1808 em todas as versões. A Siemens está preparando versões de correção e recomenda implementar soluções alternativas fornecidas nas notificações de segurança upstream da Palo Alto Networks. Até que os patches estejam disponíveis, as organizações devem desabilitar o serviço Captive Portal se não for necessário e restringir o acesso de rede aos dispositivos afetados.

Dada a pontuação CVSS crítica e o potencial de comprometimento total do sistema, uma ação imediata é justificada. O aviso tem como alvo o setor de Manufatura Crítica, com dispositivos implantados globalmente. Os operadores devem priorizar a aplicação de mitigações e monitorar quaisquer sinais de exploração.

{{< netrunner-insight >}}

Este é um exemplo clássico de risco na cadeia de suprimentos: um componente de terceiros (PAN-OS) introduz uma falha crítica em um produto industrial. Analistas de SOC devem imediatamente caçar tráfego anômalo para portas do Captive Portal e garantir que a segmentação limite a exposição. Equipes de DevSecOps devem inventariar todas as instâncias do RUGGEDCOM APE1808 e aplicar as mitigações upstream da Palo Alto Networks sem demora.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
