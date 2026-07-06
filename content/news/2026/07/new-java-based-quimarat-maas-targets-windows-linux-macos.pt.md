---
title: "Novo QuimaRAT Baseado em Java como MaaS Visa Windows, Linux e macOS"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "pt"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "QuimaRAT, um RAT Java multiplataforma vendido como malware-as-a-service, ameaça sistemas Windows, Linux e macOS. Pesquisadores da LevelBlue detalham seu modelo de assinatura e capacidades."
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "sistemas Windows, Linux e macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuimaRAT, um RAT Java multiplataforma vendido como malware-as-a-service, ameaça sistemas Windows, Linux e macOS. Pesquisadores da LevelBlue detalham seu modelo de assinatura e capacidades.

{{< cyber-report severity="High" source="The Hacker News" target="sistemas Windows, Linux e macOS" >}}

Pesquisadores de cibersegurança da LevelBlue identificaram um novo trojan de acesso remoto (RAT) baseado em Java chamado QuimaRAT, capaz de atingir ambientes Windows, Linux e macOS. O malware é comercializado sob um modelo de malware-as-a-service (MaaS), com níveis de assinatura que variam de US$ 150 por um mês a US$ 1.200 para acesso vitalício, além de um nível de US$ 300.

{{< ad-banner >}}

A natureza multiplataforma do QuimaRAT, possibilitada pelo Java, permite que ele comprometa diversos sistemas operacionais, tornando-se uma ameaça versátil para organizações com ambientes heterogêneos. O modelo MaaS reduz a barreira de entrada para atores de ameaças menos qualificados, potencialmente aumentando a frequência de ataques.

Embora detalhes técnicos específicos sobre as capacidades do QuimaRAT sejam limitados no relatório inicial, sua arquitetura baseada em Java sugere que ele pode aproveitar técnicas comuns como keylogging, captura de tela e exfiltração de arquivos. As organizações devem monitorar processos Java suspeitos e implementar listas de permissão de aplicativos para mitigar o risco.

{{< netrunner-insight >}}

Para analistas de SOC, a natureza multiplataforma do QuimaRAT significa que as regras de detecção devem cobrir endpoints Windows, Linux e macOS. As equipes de DevSecOps devem revisar o uso do runtime Java e considerar restringir a execução de aplicativos Java não assinados. Dado o modelo MaaS, espere que atacantes de baixa sofisticação implantem este RAT, portanto, o monitoramento de linha de base para conexões de rede incomuns e comportamentos de processo é crítico.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
