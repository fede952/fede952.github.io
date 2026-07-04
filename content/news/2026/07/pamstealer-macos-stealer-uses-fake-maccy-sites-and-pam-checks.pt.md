---
title: "PamStealer: Stealer para macOS usa sites falsos do Maccy e verificações PAM"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "pt"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs descobre PamStealer, um info-stealer para macOS distribuído via sites falsos do Maccy, usando verificações PAM para roubar senhas de login."
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "usuários de macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs descobre PamStealer, um info-stealer para macOS distribuído via sites falsos do Maccy, usando verificações PAM para roubar senhas de login.

{{< cyber-report severity="High" source="The Hacker News" target="usuários de macOS" >}}

Pesquisadores de segurança cibernética da Jamf Threat Labs identificaram um novo info-stealer para macOS chamado PamStealer. O malware é distribuído como um arquivo AppleScript compilado (.scpt) que se passa por Maccy, um gerenciador de área de transferência legítimo de código aberto. Ele emprega uma série de truques inteligentes para infectar sistemas e roubar dados sensíveis, incluindo senhas de login.

{{< ad-banner >}}

PamStealer recebe esse nome por sua capacidade de abusar do framework Pluggable Authentication Module (PAM) no macOS. Ao interceptar processos de autenticação, ele pode capturar credenciais de usuário quando eles fazem login ou autenticam para operações privilegiadas. O stealer então exfiltra os dados roubados para servidores controlados por atacantes.

A campanha depende de sites falsos e engenharia social para enganar os usuários a baixar o arquivo .scpt malicioso. Uma vez executado, o malware realiza verificações PAM para colher senhas sem levantar suspeitas. Organizações com endpoints macOS devem monitorar execuções incomuns de arquivos .scpt e anomalias relacionadas ao PAM.

{{< netrunner-insight >}}

Para analistas de SOC, isso destaca a necessidade de monitorar execuções de AppleScript compilado e modificações no PAM em endpoints macOS. Equipes de DevSecOps devem impor listas de permissões de aplicativos e educar os usuários sobre verificação de fontes de software, especialmente para gerenciadores de área de transferência. Implementar regras de detecção de endpoint para abuso do PAM pode ajudar a detectar esse stealer precocemente.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
