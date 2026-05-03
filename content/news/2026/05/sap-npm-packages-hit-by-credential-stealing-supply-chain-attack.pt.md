---
title: "Pacotes npm da SAP são alvo de ataque à cadeia de suprimentos que rouba credenciais"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "pt"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Uma campanha apelidada de 'Mini Shai-Hulud' atinge pacotes npm relacionados à SAP com malware que rouba credenciais, afetando vários pacotes. Pesquisadores de várias empresas alertam sobre riscos na cadeia de suprimentos."
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "Pacotes npm relacionados à SAP"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Uma campanha apelidada de 'Mini Shai-Hulud' atinge pacotes npm relacionados à SAP com malware que rouba credenciais, afetando vários pacotes. Pesquisadores de várias empresas alertam sobre riscos na cadeia de suprimentos.

{{< cyber-report severity="High" source="The Hacker News" target="Pacotes npm relacionados à SAP" >}}

Pesquisadores de cibersegurança descobriram uma campanha de ataque à cadeia de suprimentos direcionada a pacotes npm relacionados à SAP. Apelidada de 'Mini Shai-Hulud', a campanha implanta malware que rouba credenciais por meio de pacotes comprometidos, de acordo com relatórios da Aikido Security, Onapsis, OX Security, SafeDep, Socket, StepSecurity e Wiz.

{{< ad-banner >}}

O ataque afeta vários pacotes npm associados à SAP, embora nomes e versões específicos dos pacotes não tenham sido divulgados. O malware foi projetado para roubar credenciais, potencialmente dando aos atacantes acesso a ambientes SAP sensíveis e sistemas downstream.

Este incidente destaca a ameaça crescente às cadeias de suprimentos de software, particularmente para plataformas críticas para empresas como a SAP. As organizações que usam pacotes afetados são aconselhadas a auditar suas dependências e rotacionar quaisquer credenciais potencialmente comprometidas.

{{< netrunner-insight >}}

Para analistas de SOC e equipes DevSecOps, este ataque ressalta a necessidade de varredura rigorosa de dependências e verificações de integridade em pacotes npm. Monitore conexões de saída incomuns de sistemas relacionados à SAP e considere implementar proteção de aplicativo em tempo de execução (RASP) para detectar roubo de credenciais. Rotacione imediatamente todas as credenciais que possam ter sido expostas por meio de pacotes comprometidos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
