---
title: "Falha em Câmeras CCTV ZKTeco Expõe Credenciais via Porta Não Autenticada"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "pt"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre CVE-2026-8598 em câmeras CCTV ZKTeco, permitindo roubo de credenciais por uma porta não documentada. Patch disponível no firmware V5.0.1.2.20260421."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "Câmeras CCTV ZKTeco"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre CVE-2026-8598 em câmeras CCTV ZKTeco, permitindo roubo de credenciais por uma porta não documentada. Patch disponível no firmware V5.0.1.2.20260421.

{{< cyber-report severity="Critical" source="CISA" target="Câmeras CCTV ZKTeco" cve="CVE-2026-8598" cvss="9.1" >}}

A CISA publicou um aviso (ICSA-26-139-04) detalhando uma vulnerabilidade crítica de bypass de autenticação em câmeras CCTV ZKTeco. A falha, rastreada como CVE-2026-8598, envolve uma porta de exportação de configuração não documentada que é acessível sem autenticação. A exploração bem-sucedida pode levar à divulgação de informações, incluindo a captura de credenciais de conta da câmera.

{{< ad-banner >}}

A vulnerabilidade afeta versões de firmware da solução ZKTeco SSC335-GC2063-Face-0b77 anteriores a V5.0.1.2.20260421. A pontuação base CVSS v3 é 9.1, indicando gravidade crítica. Os dispositivos afetados são implantados mundialmente em instalações comerciais, com o fornecedor sediado na China.

A ZKTeco lançou uma versão de firmware corrigida V5.0.1.2.20260421 para resolver o problema. Os usuários são fortemente aconselhados a atualizar imediatamente. A vulnerabilidade é classificada sob CWE-288 (Bypass de Autenticação Usando um Caminho ou Canal Alternativo).

{{< netrunner-insight >}}

Este é um exemplo clássico de uma interface de depuração exposta se tornando uma backdoor. Analistas de SOC devem imediatamente escanear por câmeras ZKTeco em sua rede e verificar as versões de firmware. Para DevSecOps, isso ressalta a necessidade de desabilitar ou firewalar portas não documentadas em builds de firmware IoT. Trate qualquer câmera com firmware abaixo de V5.0.1.2.20260421 como comprometida até prova em contrário.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
