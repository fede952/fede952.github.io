---
title: "Backdoor GigaWiper combina limpeza de disco, ransomware falso e spyware"
date: "2026-07-10T10:21:21Z"
original_date: "2026-07-09T18:08:07"
lang: "pt"
translationKey: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
slug: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
author: "NewsBot (Validated by Federico Sella)"
description: "A Microsoft descobre o GigaWiper, um backdoor modular para Windows que reúne três ferramentas destrutivas: limpador de disco, ransomware falso e spyware, representando uma ameaça severa para endpoints."
original_url: "https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html"
source: "The Hacker News"
severity: "High"
target: "Endpoints Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

A Microsoft descobre o GigaWiper, um backdoor modular para Windows que reúne três ferramentas destrutivas: limpador de disco, ransomware falso e spyware, representando uma ameaça severa para endpoints.

{{< cyber-report severity="High" source="The Hacker News" target="Endpoints Windows" >}}

A Microsoft identificou um novo backdoor destrutivo para Windows chamado GigaWiper, que integra três programas maliciosos mais antigos em uma única estrutura modular. O backdoor oferece aos operadores um menu de comandos para escolher, cada um projetado para infligir um tipo diferente de dano: limpeza completa do disco, sobrescrita da unidade de sistema do Windows ou execução de ransomware falso que criptografa arquivos com uma chave que nunca é salva.

{{< ad-banner >}}

O design modular do GigaWiper permite que os atacantes adaptem suas ações destrutivas com base no ambiente alvo. A inclusão de capacidades de limpeza de disco e ransomware falso sugere que o objetivo principal é causar o máximo de interrupção e perda de dados, em vez de ganho financeiro. Essa combinação de técnicas torna o GigaWiper uma ferramenta versátil e perigosa para operações cibernéticas destrutivas.

Embora o vetor de distribuição específico permaneça não divulgado, a capacidade do backdoor de limpar discos inteiros e simular ataques de ransomware indica um alto nível de sofisticação. As organizações devem priorizar soluções de detecção e resposta de endpoints (EDR) e garantir estratégias robustas de backup para mitigar o impacto de tais ameaças.

{{< netrunner-insight >}}

Para analistas de SOC, o GigaWiper ressalta a necessidade de regras de detecção comportamental que sinalizem operações em massa de arquivos e gravações em nível de disco. As equipes de DevSecOps devem validar a integridade dos backups e testar procedimentos de recuperação regularmente, já que o ransomware falso pode contornar abordagens tradicionais de descriptografia. Trate qualquer incidente de ransomware não verificado como um potencial ataque de wiper até prova em contrário.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)**
