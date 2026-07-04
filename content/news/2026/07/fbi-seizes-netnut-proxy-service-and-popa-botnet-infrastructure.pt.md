---
title: "FBI apreende serviço de proxy NetNut e infraestrutura do botnet Popa"
date: "2026-07-04T09:20:04Z"
original_date: "2026-07-02T19:27:33"
lang: "pt"
translationKey: "fbi-seizes-netnut-proxy-service-and-popa-botnet-infrastructure"
author: "NewsBot (Validated by Federico Sella)"
description: "O FBI apreendeu domínios ligados à NetNut, um serviço de proxy residencial associado ao botnet Popa de 2 milhões de dispositivos comprometidos, após reportagem investigativa."
original_url: "https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/"
source: "Krebs on Security"
severity: "High"
target: "Serviço de proxy residencial NetNut e botnet Popa"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

O FBI apreendeu domínios ligados à NetNut, um serviço de proxy residencial associado ao botnet Popa de 2 milhões de dispositivos comprometidos, após reportagem investigativa.

{{< cyber-report severity="High" source="Krebs on Security" target="Serviço de proxy residencial NetNut e botnet Popa" >}}

O FBI, em coordenação com parceiros do setor, apreendeu centenas de domínios associados à NetNut, um serviço de proxy residencial operado pela empresa israelense de capital aberto Alarum Technologies (NASDAQ: ALAR). A ação segue um relatório do KrebsOnSecurity ligando a NetNut ao botnet Popa, uma rede de pelo menos dois milhões de dispositivos comprometidos sem o consentimento do usuário.

{{< ad-banner >}}

O botnet Popa utiliza dispositivos infectados para rotear tráfego através da infraestrutura de proxy da NetNut, permitindo atividades maliciosas como preenchimento de credenciais, fraude de anúncios e roubo de contas. A apreensão interrompe tanto o serviço de proxy quanto as capacidades de comando e controle do botnet.

Esta operação destaca a tendência crescente de aplicação da lei visando serviços de proxy que facilitam o cibercrime. As organizações devem revisar seu tráfego de rede em busca de conexões com domínios apreendidos e monitorar atividade residual do botnet.

{{< netrunner-insight >}}

Para analistas de SOC, esta derrubada ressalta a importância de monitorar faixas de IP de proxy residencial em feeds de inteligência de ameaças. Equipes de DevSecOps devem auditar quaisquer integrações com serviços de proxy de terceiros e garantir que mecanismos robustos de detecção de botnet estejam em vigor, pois resquícios do Popa podem persistir em infraestrutura alternativa.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em Krebs on Security ›](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)**
