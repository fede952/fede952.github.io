---
title: "7-Zip 26.02 corrige falha de RCE em arquivos maliciosos"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "pt"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "7-Zip lançou a versão 26.02 para corrigir uma vulnerabilidade de execução remota de código que pode ser acionada ao abrir arquivos compactados especialmente criados. Atualize imediatamente."
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "Usuários do 7-Zip"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

7-Zip lançou a versão 26.02 para corrigir uma vulnerabilidade de execução remota de código que pode ser acionada ao abrir arquivos compactados especialmente criados. Atualize imediatamente.

{{< cyber-report severity="High" source="BleepingComputer" target="Usuários do 7-Zip" >}}

A versão 26.02 do 7-Zip foi lançada para corrigir uma vulnerabilidade de execução remota de código (RCE) que poderia permitir que atacantes executassem código arbitrário no sistema da vítima. A falha é explorável ao convencer usuários a abrir arquivos compactados especialmente criados, como arquivos contendo payloads maliciosos.

{{< ad-banner >}}

A vulnerabilidade afeta todas as versões anteriores do popular compactador de arquivos. Embora nenhum identificador CVE tenha sido divulgado no anúncio, a gravidade é considerada alta devido ao potencial de comprometimento total do sistema. Os usuários são fortemente aconselhados a atualizar para a versão mais recente imediatamente.

Dado o uso generalizado do 7-Zip em ambientes corporativos e de consumo, esta correção é crítica para reduzir a superfície de ataque. As organizações devem priorizar a implantação por meio de mecanismos de atualização automatizados ou instalação manual.

{{< netrunner-insight >}}

Analistas de SOC devem monitorar atividades incomuns de arquivos compactados e garantir que o 7-Zip esteja atualizado em todos os endpoints. Equipes de DevSecOps devem integrar esta atualização em seus pipelines de gerenciamento de patches e considerar bloquear versões antigas do 7-Zip de acessar sistemas sensíveis.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
