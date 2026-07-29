---
title: "Pacotes npm joyfill comprometidos entregam RAT a projetos Node.js"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "pt"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "Versões beta de @joyfill/layouts e @joyfill/components contêm um implante JavaScript em tempo de importação que resolve código criptografado para implantar um trojan de acesso remoto."
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "Desenvolvedores Node.js que usam pacotes joyfill"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Versões beta de @joyfill/layouts e @joyfill/components contêm um implante JavaScript em tempo de importação que resolve código criptografado para implantar um trojan de acesso remoto.

{{< cyber-report severity="High" source="The Hacker News" target="Desenvolvedores Node.js que usam pacotes joyfill" >}}

Dois pacotes npm no namespace @joyfill, @joyfill/layouts versão 0.1.2-2773.beta.0 e @joyfill/components versão 4.0.0-rc24-2773-beta.4, foram comprometidos. Essas versões beta contêm um implante JavaScript em tempo de importação que resolve código criptografado, entregando um trojan de acesso remoto (RAT) associado à família de malware DEV#POPPER.

{{< ad-banner >}}

O código malicioso é executado quando os pacotes são importados para um projeto Node.js, dando aos atacantes acesso remoto ao sistema comprometido. O ataque destaca o risco contínuo de ataques à cadeia de suprimentos visando o ecossistema npm, particularmente através de versões beta ou release candidate que podem receber menos escrutínio.

Desenvolvedores que usaram essas versões específicas devem imediatamente rotacionar credenciais, verificar indicadores de comprometimento e revisar suas árvores de dependência em busca de outros pacotes suspeitos. O registro npm provavelmente removeu as versões maliciosas, mas as instalações existentes continuam sendo uma ameaça.

{{< netrunner-insight >}}

Este incidente ressalta a importância de examinar pacotes de pré-lançamento e implementar verificações de integridade de dependências. Analistas de SOC devem monitorar conexões de saída incomuns de aplicações Node.js, enquanto equipes DevSecOps devem impor fixação rigorosa de versões e usar ferramentas como npm audit ou scanners SCA para detectar pacotes maliciosos conhecidos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
