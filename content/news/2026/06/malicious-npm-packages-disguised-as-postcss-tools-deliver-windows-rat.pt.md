---
title: "Pacotes npm maliciosos disfarçados como ferramentas PostCSS entregam RAT para Windows"
date: "2026-06-23T10:35:14Z"
original_date: "2026-06-23T08:54:32"
lang: "pt"
translationKey: "malicious-npm-packages-disguised-as-postcss-tools-deliver-windows-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Três pacotes npm maliciosos se passando por ferramentas PostCSS foram encontrados entregando um trojan de acesso remoto para Windows. Pesquisadores alertam para cautela ao instalar pacotes npm."
original_url: "https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html"
source: "The Hacker News"
severity: "High"
target: "usuários npm, sistemas Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Três pacotes npm maliciosos se passando por ferramentas PostCSS foram encontrados entregando um trojan de acesso remoto para Windows. Pesquisadores alertam para cautela ao instalar pacotes npm.

{{< cyber-report severity="High" source="The Hacker News" target="usuários npm, sistemas Windows" >}}

Pesquisadores de cibersegurança identificaram três pacotes npm maliciosos—aes-decode-runner-pro, postcss-minify-selector e postcss-minify-selector-parser—que são projetados para entregar um trojan de acesso remoto (RAT) para Windows. Os pacotes foram publicados no último mês por um usuário npm e acumularam um total de 1.016 downloads, indicando uma distribuição moderada, mas preocupante.

{{< ad-banner >}}

Os pacotes se disfarçam como ferramentas legítimas do PostCSS, um popular pós-processador CSS, para enganar desenvolvedores e fazê-los instalá-los. Uma vez instalado, o código malicioso executa um payload que estabelece acesso remoto à máquina Windows infectada, potencialmente permitindo que atacantes exfiltrem dados, instalem malware adicional ou se movam lateralmente na rede.

Este incidente destaca a ameaça contínua de typosquatting e confusão de dependências no ecossistema npm. Os desenvolvedores são aconselhados a verificar cuidadosamente os nomes dos pacotes, revisar o código-fonte antes da instalação e usar ferramentas de verificação de integridade de pacotes para mitigar tais riscos.

{{< netrunner-insight >}}

Para analistas de SOC e engenheiros DevSecOps, este é um lembrete para impor verificações rigorosas de proveniência de pacotes e monitorar instalações anômalas de pacotes npm. Considere implementar varredura automatizada para pacotes maliciosos conhecidos e educar os desenvolvedores sobre os riscos de confiar cegamente em nomes de pacotes. O número relativamente baixo de downloads sugere que esta campanha pode estar em estágio inicial, então a caça proativa por pacotes semelhantes é justificada.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)**
