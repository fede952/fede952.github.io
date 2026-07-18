---
title: "Nova falha wp2shell no núcleo do WordPress permite que invasores não autenticados executem código"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "pt"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "Uma requisição HTTP anônima pode executar código em sites WordPress. O bug afeta o núcleo, então até instalações limpas são exploráveis. Todos os sites 6.9 e 7.0 estavam em risco até a correção."
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "Núcleo do WordPress (versões 6.9 e 7.0)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Uma requisição HTTP anônima pode executar código em sites WordPress. O bug afeta o núcleo, então até instalações limpas são exploráveis. Todos os sites 6.9 e 7.0 estavam em risco até a correção.

{{< cyber-report severity="Critical" source="The Hacker News" target="Núcleo do WordPress (versões 6.9 e 7.0)" >}}

Uma vulnerabilidade crítica de execução remota de código não autenticada foi descoberta no núcleo do WordPress, afetando as versões 6.9 e 7.0. A falha, apelidada de wp2shell, permite que um invasor execute código arbitrário em um site alvo enviando uma requisição HTTP especialmente criada. Notavelmente, a vulnerabilidade existe no software principal, o que significa que até uma instalação nova do WordPress sem plugins é explorável.

{{< ad-banner >}}

Os detalhes técnicos completos e uma prova de conceito funcional foram publicados, juntamente com identificadores CVE atribuídos às duas falhas subjacentes. Uma condição de cache de objeto persistente também foi identificada, o que pode complicar a exploração em certos ambientes. Todos os sites executando as versões afetadas foram considerados em risco até que as correções fossem aplicadas.

Os administradores são instados a atualizar para a versão corrigida mais recente imediatamente. Dada a facilidade de exploração e o uso generalizado do WordPress, esta vulnerabilidade representa uma ameaça significativa à segurança web. As organizações devem priorizar a correção e revisar suas regras de firewall de aplicação web para detectar e bloquear tentativas de exploração.

{{< netrunner-insight >}}

Este é um exemplo clássico de por que o software principal deve ser endurecido contra ataques não autenticados. Analistas de SOC devem imediatamente escanear por instâncias do WordPress 6.9 e 7.0 e verificar o status da correção. Equipes de DevSecOps devem tratar isso como um lembrete para implementar proteção de aplicação em tempo de execução (RASP) e monitorar requisições HTTP anômalas direcionadas a wp-admin ou wp-includes.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
