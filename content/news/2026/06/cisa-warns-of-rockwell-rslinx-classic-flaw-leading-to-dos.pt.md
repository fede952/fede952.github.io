---
title: "CISA Alerta sobre Falha no Rockwell RSLinx Classic que Leva a DoS"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "O aviso da CISA destaca CVE-2020-13573, um estouro de buffer baseado em pilha no Rockwell Automation RSLinx Classic ≤4.50.00, que pode causar negação de serviço e execução remota de código."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

O aviso da CISA destaca CVE-2020-13573, um estouro de buffer baseado em pilha no Rockwell Automation RSLinx Classic ≤4.50.00, que pode causar negação de serviço e execução remota de código.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

A CISA divulgou um aviso (ICSA-26-167-02) sobre uma vulnerabilidade no Rockwell Automation RSLinx Classic, um software de comunicação industrial amplamente utilizado. A falha, identificada como CVE-2020-13573, é um estouro de buffer baseado em pilha que pode ser explorado remotamente para executar código arbitrário ou causar negação de serviço, deixando o aplicativo sem resposta e incapaz de se recuperar automaticamente.

{{< ad-banner >}}

As versões afetadas incluem RSLinx Classic até a versão 4.50.00 inclusive. A vulnerabilidade possui uma pontuação CVSS v3 de 7,5, indicando alta gravidade. A Rockwell Automation recomenda a atualização para a versão 4.60.00 ou posterior, ou a aplicação do patch BF31213 para clientes que não puderem atualizar imediatamente. O aviso também faz referência à CWE-125 (Leitura Fora dos Limites) como a fraqueza subjacente.

Dados os setores de infraestrutura crítica envolvidos — Manufatura Crítica, Energia, Alimentos e Agricultura, e Água e Esgoto — e a implantação global do produto, a aplicação de patches em tempo hábil é essencial. As organizações devem priorizar esta atualização para mitigar o risco de exploração, especialmente em ambientes onde o RSLinx Classic está exposto a redes não confiáveis.

{{< netrunner-insight >}}

Para analistas de SOC, monitore travamentos incomuns ou falta de resposta nos processos do RSLinx Classic, pois isso pode indicar tentativas de exploração. As equipes de DevSecOps devem planejar imediatamente a atualização para a versão 4.60.00 ou aplicar o patch BF31213, e garantir que as instâncias do RSLinx não estejam diretamente acessíveis pela internet. Dada a pontuação CVSS e o potencial de execução remota de código, trate isso como um item de remediação de alta prioridade.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
