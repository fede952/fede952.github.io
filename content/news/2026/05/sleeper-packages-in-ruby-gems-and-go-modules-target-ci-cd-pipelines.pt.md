---
title: "Pacotes Adormecidos em Ruby Gems e Go Modules Visam Pipelines CI/CD"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "pt"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "Atacantes usam pacotes adormecidos para entregar payloads maliciosos, roubando credenciais, adulterando GitHub Actions e estabelecendo persistência SSH em ataques à cadeia de suprimentos de software."
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "Pipelines CI/CD e cadeias de suprimentos de software"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Atacantes usam pacotes adormecidos para entregar payloads maliciosos, roubando credenciais, adulterando GitHub Actions e estabelecendo persistência SSH em ataques à cadeia de suprimentos de software.

{{< cyber-report severity="High" source="The Hacker News" target="Pipelines CI/CD e cadeias de suprimentos de software" >}}

Uma nova campanha de ataque à cadeia de suprimentos de software foi observada usando pacotes adormecidos como um conduto para posteriormente enviar payloads maliciosos que possibilitaram roubo de credenciais, adulteração do GitHub Actions e persistência SSH. A atividade foi atribuída à conta do GitHub "BufferZoneCorp", que publicou um conjunto de repositórios associados a Ruby gems e Go modules maliciosos.

{{< ad-banner >}}

O ataque aproveita pacotes inicialmente benignos que posteriormente recebem atualizações maliciosas, uma técnica conhecida como pacotes "adormecidos" ou "trojanizados". Uma vez instalados em ambientes CI/CD, os payloads roubam credenciais, modificam workflows do GitHub Actions e estabelecem acesso SSH persistente, representando uma ameaça significativa para pipelines de desenvolvimento.

Organizações que usam Ruby gems ou Go modules de fontes não confiáveis devem auditar suas dependências e monitorar atividades suspeitas em repositórios. A campanha destaca a sofisticação crescente de ataques à cadeia de suprimentos visando a infraestrutura de desenvolvedores.

{{< netrunner-insight >}}

Esta campanha ressalta a necessidade de fixação rigorosa de dependências e verificação de integridade em pipelines CI/CD. Analistas de SOC devem monitorar modificações anômalas no GitHub Actions e adições de chaves SSH, enquanto engenheiros DevSecOps devem implementar acesso com privilégio mínimo e considerar o uso de ambientes de build efêmeros para limitar o raio de explosão.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
