---
title: "Extensão maliciosa do Edge 'Edgecution' usa Mensagens Nativas para implantar backdoor"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "pt"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "Uma extensão maliciosa do Microsoft Edge chamada 'Edgecution' escapa da sandbox do navegador via Mensagens Nativas para implantar um backdoor baseado em Python em ataques de ransomware."
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Usuários do Microsoft Edge"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Uma extensão maliciosa do Microsoft Edge chamada 'Edgecution' escapa da sandbox do navegador via Mensagens Nativas para implantar um backdoor baseado em Python em ataques de ransomware.

{{< cyber-report severity="High" source="BleepingComputer" target="Usuários do Microsoft Edge" >}}

Uma extensão maliciosa do Microsoft Edge apelidada de 'Edgecution' foi observada em um ataque de ransomware, utilizando a API de Mensagens Nativas do navegador para escapar da sandbox e executar código arbitrário no sistema hospedeiro. A extensão atua como uma ponte para implantar um backdoor baseado em Python, possibilitando acesso persistente e outras atividades maliciosas.

{{< ad-banner >}}

A cadeia de ataque começa com a instalação da extensão maliciosa, que então abusa das Mensagens Nativas para se comunicar com um aplicativo nativo fora da sandbox do navegador. Essa técnica contorna as barreiras de segurança típicas do navegador, permitindo que o atacante execute comandos e insira cargas adicionais, incluindo ransomware.

Pesquisadores de segurança destacam que esse método é particularmente insidioso porque explora um recurso legítimo do navegador, dificultando a detecção por soluções tradicionais de segurança de endpoint. As organizações são aconselhadas a monitorar extensões de navegador não autorizadas e restringir permissões de Mensagens Nativas sempre que possível.

{{< netrunner-insight >}}

Este ataque ressalta a importância de monitorar instalações de extensões de navegador e atividade de Mensagens Nativas. Analistas de SOC devem procurar comportamentos anômalos de extensões e comunicações inesperadas com hosts nativos, enquanto equipes de DevSecOps devem impor listas de permissões rigorosas de extensões e desabilitar hosts de Mensagens Nativas desnecessários.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
