---
title: "Quase 800 pacotes npm maliciosos entregam RAT multiplataforma e infostealer"
date: "2026-08-08T07:43:01Z"
original_date: "2026-08-07T18:48:17"
lang: "pt"
translationKey: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
slug: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
author: "NewsBot (Validated by Federico Sella)"
description: "Uma campanha com quase 800 pacotes npm maliciosos usa typo-squatting com IA para entregar um RAT multiplataforma e infostealer direcionado a Windows, Mac e Linux."
original_url: "https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "usuários do registro npm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Uma campanha com quase 800 pacotes npm maliciosos usa typo-squatting com IA para entregar um RAT multiplataforma e infostealer direcionado a Windows, Mac e Linux.

{{< cyber-report severity="High" source="The Hacker News" target="usuários do registro npm" >}}

Uma nova campanha foi descoberta publicando quase 800 pacotes maliciosos no registro npm, de acordo com um relatório do pesquisador Paul, da OpenSourceMalware. Os pacotes são projetados para entregar um trojan de acesso remoto (RAT) multiplataforma e um payload infostealer, afetando sistemas Windows, macOS e Linux.

{{< ad-banner >}}

Os pacotes maliciosos parecem usar nomes de pacotes com 'typo-squatting gerado por IA' ou gerados aleatoriamente, uma técnica que utiliza nomes gerados por IA para evadir a detecção e enganar desenvolvedores para que os instalem. Uma vez instalados, o payload fornece aos atacantes acesso remoto e a capacidade de roubar informações sensíveis de sistemas comprometidos.

Esta campanha destaca o risco contínuo de ataques à cadeia de suprimentos por meio de registros de pacotes. Desenvolvedores e organizações são aconselhados a examinar os nomes dos pacotes, verificar as identidades dos publicadores e empregar varredura de segurança automatizada para detectar e bloquear tais pacotes maliciosos antes que possam causar danos.

{{< netrunner-insight >}}

Para analistas de SOC e engenheiros DevSecOps, esta campanha ressalta a necessidade de verificação robusta de proveniência de pacotes e monitoramento em tempo de execução. Implemente ferramentas automatizadas que sinalizem nomes e comportamentos suspeitos de pacotes, e considere usar um registro privado com lista de permissões estrita. Além disso, eduque os desenvolvedores sobre os riscos do typo-squatting e incentive-os a verificar os nomes dos pacotes antes da instalação.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html)**
